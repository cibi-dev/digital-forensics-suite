"""Canonical normalizer for timestamps, severities, and forensic events.

Guarantees UTC timezone awareness, microsecond resolution, and strict
Pydantic v2 data models.
"""

from __future__ import annotations

import calendar
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, Optional, Union

from dateutil import parser as date_parser
from pydantic import BaseModel, Field, field_validator


# Common Syslog severity mapping
SYSLOG_SEVERITIES: dict[int, str] = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}

SEVERITY_ALIAS_MAP: dict[str, str] = {
    "EMERG": "EMERGENCY",
    "EMERGENCY": "EMERGENCY",
    "PANIC": "EMERGENCY",
    "ALERT": "ALERT",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "NOTE": "NOTICE",
    "NOTICE": "NOTICE",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "DEBUG": "DEBUG",
    "TRACE": "DEBUG",
    "AUTH": "NOTICE",
    "AUTHPRIV": "NOTICE",
}

MONTH_MAP: dict[str, int] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Regexes bounded and anchored to avoid ReDoS (CWE-1333)
# Max input length is strictly enforced prior to regex evaluation.
RE_BSD_SYSLOG = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<usec>\d{1,6}))?$"
)

RE_NGINX_ACCESS = re.compile(
    r"^(?P<day>\d{1,2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<usec>\d{1,6}))?\s+(?P<tz>[+\-]\d{4})$"
)

RE_NGINX_ERROR = re.compile(
    r"^(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<usec>\d{1,6}))?$"
)


def normalize_severity(severity: Union[int, str, None]) -> str:
    """Normalize log severity to canonical uppercase string."""
    if severity is None:
        return "INFO"
    if isinstance(severity, int):
        return SYSLOG_SEVERITIES.get(severity, "INFO")
    
    clean_sev = str(severity).strip().upper()
    if clean_sev.isdigit():
        return SYSLOG_SEVERITIES.get(int(clean_sev), "INFO")
    return SEVERITY_ALIAS_MAP.get(clean_sev, clean_sev if clean_sev else "INFO")


def normalize_to_utc(
    raw_timestamp: Union[datetime, str, int, float],
    default_year: Optional[int] = None,
    default_tz: timezone = timezone.utc,
) -> datetime:
    """Parse and normalize any supported timestamp format into UTC with microsecond resolution.

    Guarantees:
    - Always returns timezone-aware datetime with tzinfo=timezone.utc.
    - Preserves microsecond precision where available.
    - ReDoS protected by restricting raw string length.
    """
    if isinstance(raw_timestamp, datetime):
        if raw_timestamp.tzinfo is None:
            return raw_timestamp.replace(tzinfo=default_tz).astimezone(timezone.utc)
        return raw_timestamp.astimezone(timezone.utc)

    if isinstance(raw_timestamp, (int, float)):
        if isinstance(raw_timestamp, int):
            abs_ts = abs(raw_timestamp)
            if abs_ts >= 10**17:  # Nanoseconds
                seconds = raw_timestamp // (10**9)
                usec = (raw_timestamp % (10**9)) // 1000
                return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=usec)
            elif abs_ts >= 10**14:  # Microseconds
                seconds = raw_timestamp // (10**6)
                usec = raw_timestamp % (10**6)
                return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=usec)
            elif abs_ts >= 10**11:  # Milliseconds
                seconds = raw_timestamp // 1000
                usec = (raw_timestamp % 1000) * 1000
                return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=usec)
            else:
                return datetime.fromtimestamp(raw_timestamp, tz=timezone.utc)

        ts_float = float(raw_timestamp)
        abs_ts_f = abs(ts_float)
        if abs_ts_f >= 1e17:
            sec_val = ts_float / 1e9
        elif abs_ts_f >= 1e14:
            sec_val = ts_float / 1e6
        elif abs_ts_f >= 1e11:
            sec_val = ts_float / 1e3
        else:
            sec_val = ts_float
        return datetime.fromtimestamp(sec_val, tz=timezone.utc)

    # String parsing
    if not isinstance(raw_timestamp, str):
        raise ValueError(f"Unsupported timestamp type: {type(raw_timestamp)}")

    ts_str = raw_timestamp.strip()
    if not ts_str:
        raise ValueError("Empty timestamp string")

    # Guard against ReDoS: bound max string length (CWE-1333)
    if len(ts_str) > 256:
        raise ValueError(f"Timestamp string exceeds maximum length (len={len(ts_str)})")

    # 1. Numeric epoch in string form
    try:
        val = float(ts_str)
        return normalize_to_utc(val, default_year, default_tz)
    except ValueError:
        pass

    # 2. Fast check: BSD Syslog format (e.g. 'Oct 11 22:14:15' or 'Oct  1 04:02:10.123456')
    m_bsd = RE_BSD_SYSLOG.match(ts_str)
    if m_bsd:
        gd = m_bsd.groupdict()
        year = default_year if default_year is not None else datetime.now(timezone.utc).year
        month = MONTH_MAP[gd["month"]]
        day = int(gd["day"])
        hour = int(gd["hour"])
        minute = int(gd["minute"])
        second = int(gd["second"])
        usec_str = gd.get("usec") or "0"
        usec = int(usec_str.ljust(6, "0")[:6])
        return datetime(year, month, day, hour, minute, second, usec, tzinfo=default_tz).astimezone(timezone.utc)

    # 3. Fast check: Nginx access format (e.g. '10/Oct/2023:13:55:36 +0000')
    m_nginx_acc = RE_NGINX_ACCESS.match(ts_str)
    if m_nginx_acc:
        gd = m_nginx_acc.groupdict()
        day = int(gd["day"])
        month = MONTH_MAP.get(gd["month"].capitalize(), 1)
        year = int(gd["year"])
        hour = int(gd["hour"])
        minute = int(gd["minute"])
        second = int(gd["second"])
        usec_str = gd.get("usec") or "0"
        usec = int(usec_str.ljust(6, "0")[:6])
        tz_raw = gd["tz"]
        sign = 1 if tz_raw[0] == "+" else -1
        tz_hours = int(tz_raw[1:3])
        tz_mins = int(tz_raw[3:5])
        from datetime import timedelta
        tz_offset = timezone(sign * timedelta(hours=tz_hours, minutes=tz_mins))
        return datetime(year, month, day, hour, minute, second, usec, tzinfo=tz_offset).astimezone(timezone.utc)

    # 4. Fast check: Nginx error format (e.g. '2023/10/11 12:34:56')
    m_nginx_err = RE_NGINX_ERROR.match(ts_str)
    if m_nginx_err:
        gd = m_nginx_err.groupdict()
        year = int(gd["year"])
        month = int(gd["month"])
        day = int(gd["day"])
        hour = int(gd["hour"])
        minute = int(gd["minute"])
        second = int(gd["second"])
        usec_str = gd.get("usec") or "0"
        usec = int(usec_str.ljust(6, "0")[:6])
        return datetime(year, month, day, hour, minute, second, usec, tzinfo=default_tz).astimezone(timezone.utc)

    # 5. General parser (ISO 8601, RFC 3339, etc.)
    try:
        # Default datetime for missing components
        ref_year = default_year if default_year is not None else datetime.now(timezone.utc).year
        default_dt = datetime(ref_year, 1, 1, 0, 0, 0, 0, tzinfo=default_tz)
        dt = date_parser.parse(ts_str, default=default_dt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=default_tz)
        return dt.astimezone(timezone.utc)
    except Exception as e:
        raise ValueError(f"Failed to parse timestamp '{ts_str}': {e}") from e


def generate_event_id(
    source_file: str,
    line_number: int,
    timestamp: datetime,
    raw_log: str,
) -> str:
    """Generate deterministic event ID based on event attributes."""
    content = f"{source_file}:{line_number}:{timestamp.isoformat()}:{raw_log[:256]}"
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


class ForensicEvent(BaseModel):
    """Canonical forensic event representation with microsecond UTC timestamp."""

    model_config = {"extra": "forbid"}

    timestamp: datetime
    source_type: str = "generic"
    source_file: str = "stream"
    line_number: int = 1
    facility: Optional[str] = None
    severity: str = "INFO"
    host: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    user: Optional[str] = None
    client_ip: Optional[str] = None
    action: Optional[str] = None
    message: str = ""
    raw_log: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    event_id: str = ""

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return normalize_to_utc(v)
        return normalize_to_utc(v)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> str:
        return normalize_severity(v)

    @field_validator("raw_log", mode="before")
    @classmethod
    def truncate_raw_log(cls, v: Any) -> str:
        s = str(v) if v is not None else ""
        if len(s) > 4096:
            return s[:4093] + "..."
        return s

    def model_post_init(self, __context: Any) -> None:
        if not self.event_id:
            self.event_id = generate_event_id(
                self.source_file, self.line_number, self.timestamp, self.raw_log
            )

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, ForensicEvent):
            return NotImplemented
        return (
            self.timestamp,
            self.source_file,
            self.line_number,
            self.event_id,
        ) < (
            other.timestamp,
            other.source_file,
            other.line_number,
            other.event_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return canonical dictionary representation with ISO 8601 UTC timestamp."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_jsonl(self) -> str:
        """Return JSON-Lines formatted string."""
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False)
