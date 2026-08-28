"""JSON-Lines generic structured log parser with auto-discovery of forensic fields."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Iterable, Iterator, List, Optional

from timeline.normalizer import ForensicEvent, normalize_severity, normalize_to_utc

logger = logging.getLogger(__name__)

TIMESTAMP_KEYS = [
    "timestamp",
    "@timestamp",
    "time",
    "ts",
    "datetime",
    "date",
    "event_time",
    "created_at",
    "time_utc",
]

MESSAGE_KEYS = [
    "message",
    "msg",
    "log",
    "event",
    "text",
    "description",
    "summary",
]

SEVERITY_KEYS = [
    "severity",
    "level",
    "log_level",
    "status",
    "loglevel",
]

HOST_KEYS = [
    "host",
    "hostname",
    "node",
    "computer",
    "device",
    "host_name",
]

PROCESS_KEYS = [
    "process",
    "service",
    "app",
    "application",
    "program",
    "logger",
]

PID_KEYS = ["pid", "process_id", "proc_id"]

USER_KEYS = [
    "user",
    "username",
    "account",
    "actor",
    "login",
    "user_name",
]

CLIENT_IP_KEYS = [
    "client_ip",
    "ip",
    "src_ip",
    "source_ip",
    "remote_addr",
    "remote_ip",
]

ACTION_KEYS = [
    "action",
    "event_type",
    "type",
    "operation",
    "audit_action",
    "event_name",
]

MAX_LINE_LENGTH = 131072  # 128 KB for JSON-Lines


def _extract_first(data: dict[str, Any], candidate_keys: list[str]) -> tuple[Optional[str], Any]:
    for k in candidate_keys:
        if k in data and data[k] is not None:
            return k, data[k]
    return None, None


class JsonLinesParser:
    """High-performance streaming parser for JSON-Lines logs."""

    def __init__(self, default_year: Optional[int] = None) -> None:
        self.default_year = default_year

    def parse_line(
        self, line: str, line_number: int = 1, source_file: str = "events.jsonl"
    ) -> Optional[ForensicEvent]:
        """Parse a single JSON-Line into a ForensicEvent."""
        if not line:
            return None

        clean_line = line.rstrip("\r\n")
        if not clean_line or clean_line.startswith("#"):
            return None

        if len(clean_line) > MAX_LINE_LENGTH:
            clean_line = clean_line[:MAX_LINE_LENGTH]

        try:
            raw_obj = json.loads(clean_line)
            if not isinstance(raw_obj, dict):
                return None

            # 1. Extract Timestamp (mandatory)
            ts_key, ts_val = _extract_first(raw_obj, TIMESTAMP_KEYS)
            if ts_val is None:
                logger.debug("Line %d in %s has no timestamp field", line_number, source_file)
                return None

            dt = normalize_to_utc(ts_val, default_year=self.default_year)

            # 2. Extract Message
            msg_key, msg_val = _extract_first(raw_obj, MESSAGE_KEYS)
            message = str(msg_val) if msg_val is not None else ""

            # 3. Extract Severity
            sev_key, sev_val = _extract_first(raw_obj, SEVERITY_KEYS)
            severity = normalize_severity(sev_val) if sev_val is not None else "INFO"

            # 4. Extract Host
            host_key, host_val = _extract_first(raw_obj, HOST_KEYS)
            host = str(host_val) if host_val is not None else None

            # 5. Extract Process
            proc_key, proc_val = _extract_first(raw_obj, PROCESS_KEYS)
            process = str(proc_val) if proc_val is not None else None

            # 6. Extract PID
            pid_key, pid_val = _extract_first(raw_obj, PID_KEYS)
            pid = int(pid_val) if pid_val is not None and str(pid_val).isdigit() else None

            # 7. Extract User
            user_key, user_val = _extract_first(raw_obj, USER_KEYS)
            user = str(user_val) if user_val is not None else None

            # 8. Extract Client IP
            ip_key, ip_val = _extract_first(raw_obj, CLIENT_IP_KEYS)
            client_ip = str(ip_val) if ip_val is not None else None

            # 9. Extract Action
            act_key, act_val = _extract_first(raw_obj, ACTION_KEYS)
            action = str(act_val) if act_val is not None else None

            # 10. Remaining fields into metadata
            extracted_keys = {
                ts_key, msg_key, sev_key, host_key, proc_key,
                pid_key, user_key, ip_key, act_key,
            }
            metadata: dict[str, Any] = {
                k: v for k, v in raw_obj.items() if k not in extracted_keys
            }

            source_type = raw_obj.get("source_type") or raw_obj.get("log_type") or "json_lines"

            return ForensicEvent(
                timestamp=dt,
                source_type=str(source_type),
                source_file=source_file,
                line_number=line_number,
                facility=raw_obj.get("facility"),
                severity=severity,
                host=host,
                process=process,
                pid=pid,
                user=user,
                client_ip=client_ip,
                action=action,
                message=message,
                raw_log=clean_line,
                metadata=metadata,
            )

        except Exception as err:
            logger.warning(
                "Error parsing JSON-Line %d in %s: %s",
                line_number,
                source_file,
                str(err),
            )
            return None

    def parse_lines(
        self, lines: Iterable[str], source_file: str = "events.jsonl"
    ) -> Iterator[ForensicEvent]:
        """Stream parsed ForensicEvents from an iterable of lines."""
        for line_num, line in enumerate(lines, start=1):
            evt = self.parse_line(line, line_number=line_num, source_file=source_file)
            if evt is not None:
                yield evt

    def parse_file(self, filepath: str) -> Iterator[ForensicEvent]:
        """Stream parsed ForensicEvents from a file path."""
        safe_path = os.path.realpath(filepath)
        source_name = os.path.basename(safe_path)
        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            yield from self.parse_lines(f, source_file=source_name)


def parse_jsonl_file(filepath: str, default_year: Optional[int] = None) -> Iterator[ForensicEvent]:
    """Convenience generator to parse a JSON-Lines file."""
    parser = JsonLinesParser(default_year=default_year)
    yield from parser.parse_file(filepath)
