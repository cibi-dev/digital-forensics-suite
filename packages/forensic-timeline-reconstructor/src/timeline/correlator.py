"""Forensic timeline correlation and multi-source time-merge engine.

Implements streaming k-way merge (heapq.merge) for O(K) memory bounds (CWE-400),
automated log format detection, query filtering, and multi-stage attack chain correlation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import heapq
import logging
import os
import re
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Union

from timeline.normalizer import ForensicEvent, normalize_severity, normalize_to_utc
from timeline.parsers.auth import AuthLogParser
from timeline.parsers.json_lines import JsonLinesParser
from timeline.parsers.nginx import NginxParser
from timeline.parsers.syslog import SyslogParser

logger = logging.getLogger(__name__)

SEVERITY_RANKS: dict[str, int] = {
    "DEBUG": 0,
    "INFO": 1,
    "NOTICE": 2,
    "WARNING": 3,
    "ERROR": 4,
    "CRITICAL": 5,
    "ALERT": 6,
    "EMERGENCY": 7,
}


def detect_parser_for_file(filepath: str, default_year: Optional[int] = None) -> Any:
    """Auto-detect the appropriate parser for a given log file by inspecting header lines."""
    safe_path = os.path.realpath(filepath)
    sample_lines: list[str] = []
    try:
        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(10):
                line = f.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    sample_lines.append(stripped)
    except Exception as e:
        logger.warning("Failed to sample lines from %s: %s", filepath, e)
        return SyslogParser(default_year=default_year)

    if not sample_lines:
        return SyslogParser(default_year=default_year)

    first_line = sample_lines[0]

    # 1. JSON test
    if first_line.startswith("{") and first_line.endswith("}"):
        json_p = JsonLinesParser(default_year=default_year)
        if json_p.parse_line(first_line) is not None:
            return json_p

    # 2. Nginx test
    nginx_p = NginxParser(default_year=default_year)
    if nginx_p.parse_line(first_line) is not None:
        return nginx_p

    # 3. Auth.log test (sshd, sudo, pam, etc.)
    if any(k in first_line for k in ("sshd", "sudo", "pam_unix", "useradd", "passwd", "su[")):
        auth_p = AuthLogParser(default_year=default_year)
        if auth_p.parse_line(first_line) is not None:
            return auth_p

    # 4. Syslog test
    syslog_p = SyslogParser(default_year=default_year)
    if syslog_p.parse_line(first_line) is not None:
        return syslog_p

    # Fallback to Syslog parser
    return syslog_p


def correlate_streams(*streams: Iterable[ForensicEvent]) -> Iterator[ForensicEvent]:
    """Perform a streaming k-way merge of multiple sorted ForensicEvent streams in O(K) memory."""
    # heapq.merge requires the items or key to be orderable.
    # ForensicEvent defines __lt__ on (timestamp, source_file, line_number, event_id).
    return heapq.merge(*streams)


class TimelineCorrelator:
    """Enterprise IR timeline correlator engine."""

    def __init__(self, default_year: Optional[int] = None) -> None:
        self.default_year = default_year

    def open_stream(self, filepath: str) -> Iterator[ForensicEvent]:
        """Open a file and return a streaming iterator of ForensicEvents."""
        parser = detect_parser_for_file(filepath, default_year=self.default_year)
        return parser.parse_file(filepath)

    def merge_files(self, filepaths: list[str]) -> Iterator[ForensicEvent]:
        """Open and merge multiple log files into a single unified chronological timeline."""
        streams = [self.open_stream(fp) for fp in filepaths]
        return correlate_streams(*streams)

    def filter_events(
        self,
        events: Iterable[ForensicEvent],
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        min_severity: Optional[str] = None,
        source_types: Optional[Set[str]] = None,
        hosts: Optional[Set[str]] = None,
        users: Optional[Set[str]] = None,
        client_ips: Optional[Set[str]] = None,
        search_pattern: Optional[str] = None,
    ) -> Iterator[ForensicEvent]:
        """Filter a stream of ForensicEvents with bounded CPU and memory."""
        st_utc = normalize_to_utc(start_time) if start_time is not None else None
        et_utc = normalize_to_utc(end_time) if end_time is not None else None
        min_rank = SEVERITY_RANKS.get(normalize_severity(min_severity), 0) if min_severity else 0

        # Compile regex if provided (bounded length)
        re_search = None
        if search_pattern:
            if len(search_pattern) > 256:
                raise ValueError("Search pattern exceeds maximum length")
            re_search = re.compile(search_pattern, re.IGNORECASE)

        for evt in events:
            # Time bounds
            if st_utc and evt.timestamp < st_utc:
                continue
            if et_utc and evt.timestamp > et_utc:
                continue

            # Severity threshold
            evt_rank = SEVERITY_RANKS.get(evt.severity, 0)
            if evt_rank < min_rank:
                continue

            # Source types
            if source_types and evt.source_type not in source_types:
                continue

            # Hosts
            if hosts and (not evt.host or evt.host not in hosts):
                continue

            # Users
            if users and (not evt.user or evt.user not in users):
                continue

            # Client IPs
            if client_ips and (not evt.client_ip or evt.client_ip not in client_ips):
                continue

            # Text search
            if re_search:
                match_text = f"{evt.message} {evt.action or ''} {evt.raw_log}"
                if not re_search.search(match_text):
                    continue

            yield evt

    def find_attack_chains(
        self,
        events: Iterable[ForensicEvent],
        max_gap_seconds: float = 300.0,
    ) -> list[dict[str, Any]]:
        """Identify correlated attack chains (e.g. Brute-Force to Login to Sudo escalation)."""
        # Group events by IP and user
        ip_groups: dict[str, list[ForensicEvent]] = {}
        user_groups: dict[str, list[ForensicEvent]] = {}

        for evt in events:
            if evt.client_ip:
                ip_groups.setdefault(evt.client_ip, []).append(evt)
            if evt.user:
                user_groups.setdefault(evt.user, []).append(evt)

        chains: list[dict[str, Any]] = []

        # 1. Correlate IP-based brute force & successful logins
        for ip, ip_evts in ip_groups.items():
            failed_attempts = [
                e for e in ip_evts if e.action in ("SSH_LOGIN_FAILED", "SSH_LOGIN_FAILED_INVALID_USER", "INVALID_USER")
            ]
            successful_logins = [
                e for e in ip_evts if e.action == "SSH_LOGIN_SUCCESS"
            ]

            if len(failed_attempts) >= 3:
                # Check if followed by success
                chain_evts = failed_attempts + successful_logins
                chain_evts.sort(key=lambda x: x.timestamp)
                start_t = chain_evts[0].timestamp
                end_t = chain_evts[-1].timestamp
                has_success = bool(successful_logins)

                chains.append({
                    "pivot": f"ip:{ip}",
                    "chain_type": "BRUTE_FORCE_SUCCESS" if has_success else "BRUTE_FORCE_SCAN",
                    "severity": "CRITICAL" if has_success else "WARNING",
                    "start_time": start_t.isoformat(),
                    "end_time": end_t.isoformat(),
                    "event_count": len(chain_evts),
                    "description": (
                        f"Detected {len(failed_attempts)} failed login attempts from IP {ip}"
                        + (f" followed by SUCCESSFUL LOGIN as user '{successful_logins[0].user}'" if has_success else "")
                    ),
                    "events": [e.to_dict() for e in chain_evts[:20]],
                })

        # 2. Correlate User-based Privilege Escalation (SSH Login -> Sudo Command)
        for user, user_evts in user_groups.items():
            if user in ("root", "daemon", "nobody"):
                continue
            logins = [e for e in user_evts if e.action == "SSH_LOGIN_SUCCESS"]
            sudos = [e for e in user_evts if e.action == "SUDO_COMMAND"]

            if logins and sudos:
                for login in logins:
                    related_sudos = [
                        s for s in sudos
                        if 0 <= (s.timestamp - login.timestamp).total_seconds() <= max_gap_seconds
                    ]
                    if related_sudos:
                        all_evts = [login] + related_sudos
                        chains.append({
                            "pivot": f"user:{user}",
                            "chain_type": "PRIVILEGE_ESCALATION",
                            "severity": "CRITICAL",
                            "start_time": login.timestamp.isoformat(),
                            "end_time": related_sudos[-1].timestamp.isoformat(),
                            "event_count": len(all_evts),
                            "description": (
                                f"User '{user}' logged in via SSH from {login.client_ip or 'unknown'} "
                                f"and executed {len(related_sudos)} sudo command(s) within {max_gap_seconds}s"
                            ),
                            "events": [e.to_dict() for e in all_evts[:20]],
                        })

        return chains
