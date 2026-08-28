"""Parser module for Auth.log, Syslog RFC 5424 / RFC 3164, and Network JSON-Lines."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generator, Iterable, Optional
from pydantic import BaseModel, Field, ConfigDict


class SourceType(str, Enum):
    """Source log format identification."""
    AUTH_LOG = "auth_log"
    SYSLOG = "syslog"
    NETWORK_JSON = "network_json"
    GENERIC = "generic"


class EventType(str, Enum):
    """Normalized security event classifications."""
    SSH_AUTH_FAIL = "ssh_auth_fail"
    SSH_AUTH_SUCCESS = "ssh_auth_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    SSH_DISCONNECT = "ssh_disconnect"
    SUDO_COMMAND = "sudo_command"
    SUDO_AUTH_FAIL = "sudo_auth_fail"
    NETWORK_FLOW = "network_flow"
    GENERIC_EVENT = "generic_event"
    MALFORMED = "malformed"


class LogEvent(BaseModel):
    """Unified normalized log event data model."""
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    source_type: SourceType
    event_type: EventType
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration: float = 0.0
    raw_message: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    is_anomaly: Optional[bool] = None


# Max line length for CWE-400 resource exhaustion mitigation
MAX_LINE_LENGTH = 65536

# Month mapping for traditional syslog timestamp parsing
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# Compiled Regex patterns for Auth.log / Syslog
RE_SYSLOG_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+(?P<host>\S+)\s+(?P<process>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

RE_ISO_HEADER = re.compile(
    r"^(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)\s+(?P<host>\S+)\s+(?P<process>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d+)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\[.*?\]|-)\s*(?P<msg>.*)$"
)

RE_SSH_FAILED = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[a-fA-F0-9\.\:]+)\s+port\s+(?P<port>\d+)\s+ssh2"
)

RE_SSH_ACCEPTED = re.compile(
    r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[a-fA-F0-9\.\:]+)\s+port\s+(?P<port>\d+)\s+ssh2"
)

RE_SSH_INVALID_USER = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[a-fA-F0-9\.\:]+)\s+port\s+(?P<port>\d+)"
)

RE_SSH_DISCONNECT = re.compile(
    r"(?:Disconnected\s+from|Received\s+disconnect\s+from)\s+(?:invalid\s+user\s+|authenticating\s+user\s+)?(?:(?P<user>\S+)\s+)?(?P<ip>[a-fA-F0-9\.\:]+)\s+port\s+(?P<port>\d+)"
)

RE_PAM_FAIL = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication\s+failure;\s+.*rhost=(?P<ip>[a-fA-F0-9\.\:]+)(?:\s+user=(?P<user>\S+))?"
)

RE_SUDO_CMD = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.*)"
)

RE_SUDO_FAIL = re.compile(
    r"pam_unix\(sudo:auth\):\s+authentication\s+failure;\s+.*logname=(?P<logname>\S*)\s+uid=(?P<uid>\d+)\s+euid=(?P<euid>\d+)\s+tty=(?P<tty>\S*)\s+ruser=(?P<ruser>\S*)\s+rhost=(?P<rhost>\S*)\s+user=(?P<user>\S*)"
)


class LogParser:
    """High-performance resilient log parser."""

    def __init__(self, default_year: Optional[int] = None) -> None:
        self.default_year = default_year or datetime.now(timezone.utc).year

    def parse_line(self, line: str, format_hint: str = "auto") -> LogEvent:
        """Parse a single raw log line into a normalized LogEvent."""
        if not line or not line.strip():
            return LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.GENERIC,
                event_type=EventType.MALFORMED,
                status="empty",
                raw_message="",
            )

        if len(line) > MAX_LINE_LENGTH:
            return LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.GENERIC,
                event_type=EventType.MALFORMED,
                status="line_too_long",
                raw_message=line[:256] + "... [TRUNCATED]",
            )

        line_str = line.strip()

        # Format dispatching
        if format_hint == "json" or (format_hint == "auto" and line_str.startswith("{") and line_str.endswith("}")):
            return self._parse_json_line(line_str)

        if format_hint == "syslog" or (format_hint == "auto" and line_str.startswith("<")):
            event = self._parse_rfc5424_line(line_str)
            if event.event_type != EventType.MALFORMED:
                return event

        # Default: Auth.log / Syslog format
        return self._parse_auth_or_syslog_line(line_str)

    def _parse_json_line(self, line: str) -> LogEvent:
        """Parse network flow or structured JSON log."""
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                raise ValueError("JSON payload is not an object")

            # Parse timestamp
            ts_raw = data.get("timestamp") or data.get("ts") or data.get("@timestamp")
            if ts_raw:
                if isinstance(ts_raw, (int, float)):
                    ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
                elif isinstance(ts_raw, str):
                    try:
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    except Exception:
                        ts = datetime.now(timezone.utc)
                else:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event_type_str = str(data.get("event_type", "network_flow")).lower()
            try:
                event_type = EventType(event_type_str)
            except ValueError:
                event_type = EventType.NETWORK_FLOW

            return LogEvent(
                timestamp=ts,
                source_type=SourceType.NETWORK_JSON,
                event_type=event_type,
                src_ip=str(data["src_ip"]) if "src_ip" in data else data.get("orig_h"),
                dst_ip=str(data["dst_ip"]) if "dst_ip" in data else data.get("resp_h"),
                src_port=int(data["src_port"]) if "src_port" in data and str(data["src_port"]).isdigit() else (
                    int(data["orig_p"]) if "orig_p" in data and str(data["orig_p"]).isdigit() else None
                ),
                dst_port=int(data["dst_port"]) if "dst_port" in data and str(data["dst_port"]).isdigit() else (
                    int(data["resp_p"]) if "resp_p" in data and str(data["resp_p"]).isdigit() else None
                ),
                user=str(data["user"]) if "user" in data else data.get("username"),
                action=str(data["action"]) if "action" in data else None,
                status=str(data["status"]) if "status" in data else None,
                bytes_sent=int(data.get("bytes_sent", data.get("orig_bytes", 0)) or 0),
                bytes_recv=int(data.get("bytes_recv", data.get("resp_bytes", 0)) or 0),
                duration=float(data.get("duration", 0.0) or 0.0),
                raw_message=line,
                metadata={k: v for k, v in data.items() if k not in {
                    "timestamp", "ts", "@timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                    "orig_h", "resp_h", "orig_p", "resp_p", "user", "username", "action", "status",
                    "bytes_sent", "bytes_recv", "orig_bytes", "resp_bytes", "duration", "event_type", "is_anomaly"
                }},
                is_anomaly=data.get("is_anomaly")
            )
        except Exception:
            return LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.NETWORK_JSON,
                event_type=EventType.MALFORMED,
                status="json_parse_error",
                raw_message=line,
            )

    def _parse_rfc5424_line(self, line: str) -> LogEvent:
        """Parse RFC 5424 structured syslog."""
        m = RE_RFC5424.match(line)
        if not m:
            return LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.SYSLOG,
                event_type=EventType.MALFORMED,
                status="rfc5424_mismatch",
                raw_message=line,
            )

        groups = m.groupdict()
        ts_str = groups["ts"]
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)

        msg = groups.get("msg", "")
        # Inspect inner message for authentication or system patterns
        return self._extract_security_semantics(
            ts=ts,
            source_type=SourceType.SYSLOG,
            process=groups.get("app", "syslog"),
            message=msg,
            raw_line=line,
            metadata={"pri": groups["pri"], "procid": groups["procid"], "msgid": groups["msgid"]}
        )

    def _parse_auth_or_syslog_line(self, line: str) -> LogEvent:
        """Parse standard Linux auth.log or syslog entry."""
        # Try ISO timestamp first (modern systemd / rsyslog)
        iso_match = RE_ISO_HEADER.match(line)
        if iso_match:
            g = iso_match.groupdict()
            try:
                ts = datetime.fromisoformat(g["iso_ts"].replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)
            return self._extract_security_semantics(
                ts=ts,
                source_type=SourceType.AUTH_LOG,
                process=g.get("process", ""),
                message=g.get("message", ""),
                raw_line=line,
                metadata={"host": g.get("host", ""), "pid": g.get("pid")}
            )

        # Traditional BSD syslog timestamp (e.g. Aug 27 15:20:01)
        sys_match = RE_SYSLOG_HEADER.match(line)
        if sys_match:
            g = sys_match.groupdict()
            month = MONTH_MAP.get(g["month"], 1)
            day = int(g["day"])
            hour = int(g["hour"])
            minute = int(g["minute"])
            second = int(g["second"])
            try:
                ts = datetime(self.default_year, month, day, hour, minute, second, tzinfo=timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)

            return self._extract_security_semantics(
                ts=ts,
                source_type=SourceType.AUTH_LOG,
                process=g.get("process", ""),
                message=g.get("message", ""),
                raw_line=line,
                metadata={"host": g.get("host", ""), "pid": g.get("pid")}
            )

        # If regex matching fails, return generic/malformed entry
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.GENERIC,
            event_type=EventType.GENERIC_EVENT,
            status="unstructured",
            raw_message=line,
        )

    def _extract_security_semantics(
        self,
        ts: datetime,
        source_type: SourceType,
        process: str,
        message: str,
        raw_line: str,
        metadata: dict[str, Any]
    ) -> LogEvent:
        """Extract domain specific security fields from message body."""
        # 1. SSH Failed Password
        m_fail = RE_SSH_FAILED.search(message)
        if m_fail:
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SSH_AUTH_FAIL,
                src_ip=m_fail.group("ip"),
                src_port=int(m_fail.group("port")),
                user=m_fail.group("user"),
                action="ssh_login",
                status="failed",
                raw_message=raw_line,
                metadata=metadata,
            )

        # 2. SSH Invalid User
        m_inv = RE_SSH_INVALID_USER.search(message)
        if m_inv:
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SSH_INVALID_USER,
                src_ip=m_inv.group("ip"),
                src_port=int(m_inv.group("port")),
                user=m_inv.group("user"),
                action="ssh_login_invalid_user",
                status="failed",
                raw_message=raw_line,
                metadata=metadata,
            )

        # 3. SSH Accepted Login
        m_ok = RE_SSH_ACCEPTED.search(message)
        if m_ok:
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SSH_AUTH_SUCCESS,
                src_ip=m_ok.group("ip"),
                src_port=int(m_ok.group("port")),
                user=m_ok.group("user"),
                action="ssh_login",
                status="success",
                raw_message=raw_line,
                metadata=metadata,
            )

        # 4. SSH Disconnect
        m_disc = RE_SSH_DISCONNECT.search(message)
        if m_disc:
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SSH_DISCONNECT,
                src_ip=m_disc.group("ip"),
                src_port=int(m_disc.group("port")),
                user=m_disc.group("user"),
                action="ssh_disconnect",
                status="closed",
                raw_message=raw_line,
                metadata=metadata,
            )

        # 5. PAM failure
        m_pam = RE_PAM_FAIL.search(message)
        if m_pam:
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SSH_AUTH_FAIL,
                src_ip=m_pam.group("ip"),
                user=m_pam.group("user"),
                action="pam_auth",
                status="failed",
                raw_message=raw_line,
                metadata=metadata,
            )

        # 6. Sudo failure
        m_sudofail = RE_SUDO_FAIL.search(message)
        if m_sudofail:
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SUDO_AUTH_FAIL,
                src_ip=m_sudofail.group("rhost") if m_sudofail.group("rhost") else None,
                user=m_sudofail.group("user"),
                action="sudo_auth",
                status="failed",
                raw_message=raw_line,
                metadata=metadata,
            )

        # 7. Sudo Command
        m_sudo = RE_SUDO_CMD.search(message)
        if m_sudo:
            meta = dict(metadata)
            meta.update({
                "tty": m_sudo.group("tty"),
                "pwd": m_sudo.group("pwd"),
                "target_user": m_sudo.group("target_user"),
                "command": m_sudo.group("cmd"),
            })
            return LogEvent(
                timestamp=ts,
                source_type=source_type,
                event_type=EventType.SUDO_COMMAND,
                user=m_sudo.group("user"),
                action="sudo_exec",
                status="success",
                raw_message=raw_line,
                metadata=meta,
            )

        # Generic syslog message
        return LogEvent(
            timestamp=ts,
            source_type=source_type,
            event_type=EventType.GENERIC_EVENT,
            action=process,
            status="info",
            raw_message=raw_line,
            metadata=metadata,
        )

    def parse_stream(self, stream: Iterable[str], format_hint: str = "auto") -> Generator[LogEvent, None, None]:
        """Stream generator for batch and file processing."""
        for line in stream:
            yield self.parse_line(line, format_hint=format_hint)
