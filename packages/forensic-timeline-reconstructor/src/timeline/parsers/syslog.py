"""Syslog parser supporting RFC 5424 and RFC 3164 (BSD) formats.

Provides streaming iteration, PRI calculation (facility/severity), structured
data extraction, and bounded-memory line processing.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple

from timeline.normalizer import ForensicEvent, normalize_severity, normalize_to_utc

logger = logging.getLogger(__name__)

# Syslog facilities (RFC 5424 / RFC 3164)
FACILITY_NAMES: dict[int, str] = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "solaris-cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
# Anchored and non-backtracking to mitigate ReDoS (CWE-1333)
RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2})\s+"
    r"(?P<timestamp>[^\s]+)\s+"
    r"(?P<hostname>[^\s]+)\s+"
    r"(?P<app_name>[^\s]+)\s+"
    r"(?P<proc_id>[^\s]+)\s+"
    r"(?P<msg_id>[^\s]+)"
    r"(?:\s+(?P<sd>\[.+?\]|-))?"
    r"(?:\s+(?P<msg>.*))?$",
    re.DOTALL,
)

# RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG  or  TIMESTAMP HOSTNAME TAG: MSG
RE_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+"
    r"(?P<hostname>[^\s:]+)\s+"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d{1,10})\])?:\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

RE_RFC3164_NOTAG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+"
    r"(?P<hostname>[^\s:]+)\s+"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

RE_SD_ELEMENT = re.compile(r'\[(?P<id>[^\s=\]]+)(?:\s+(?P<params>[^\]]+))?\]')
RE_SD_PARAM = re.compile(r'(?P<key>[^\s=]+)="(?P<val>[^"]*)"')

MAX_LINE_LENGTH = 65536


def parse_pri(pri_val: int) -> tuple[str, str]:
    """Calculate facility name and severity name from numeric PRI."""
    facility_code = pri_val >> 3
    severity_code = pri_val & 7
    facility_name = FACILITY_NAMES.get(facility_code, f"facility_{facility_code}")
    severity_name = normalize_severity(severity_code)
    return facility_name, severity_name


def parse_structured_data(sd_str: Optional[str]) -> dict[str, Any]:
    """Parse RFC 5424 structured data blocks into a dictionary."""
    if not sd_str or sd_str == "-":
        return {}
    
    result: dict[str, Any] = {}
    for match in RE_SD_ELEMENT.finditer(sd_str):
        elem_id = match.group("id")
        params_str = match.group("params")
        elem_dict: dict[str, str] = {}
        if params_str:
            for p_match in RE_SD_PARAM.finditer(params_str):
                elem_dict[p_match.group("key")] = p_match.group("val")
        result[elem_id] = elem_dict
    return result


class SyslogParser:
    """High-throughput streaming parser for Syslog logs."""

    def __init__(self, default_year: Optional[int] = None) -> None:
        self.default_year = default_year

    def parse_line(
        self, line: str, line_number: int = 1, source_file: str = "syslog"
    ) -> Optional[ForensicEvent]:
        """Parse a single syslog line into a ForensicEvent (returns None on malformed line)."""
        if not line:
            return None
        
        # Enforce line length bound (CWE-1333 / CWE-400)
        clean_line = line.rstrip("\r\n")
        if len(clean_line) > MAX_LINE_LENGTH:
            clean_line = clean_line[:MAX_LINE_LENGTH]

        try:
            # 1. Try RFC 5424
            m_5424 = RE_RFC5424.match(clean_line)
            if m_5424:
                gd = m_5424.groupdict()
                pri = int(gd["pri"])
                facility, severity = parse_pri(pri)
                dt = normalize_to_utc(gd["timestamp"], default_year=self.default_year)
                host = None if gd["hostname"] == "-" else gd["hostname"]
                app = None if gd["app_name"] == "-" else gd["app_name"]
                
                pid_raw = gd.get("proc_id")
                pid = int(pid_raw) if pid_raw and pid_raw.isdigit() else None
                msg_id = None if gd["msg_id"] == "-" else gd["msg_id"]
                
                sd_raw = gd.get("sd")
                metadata = parse_structured_data(sd_raw)
                if msg_id:
                    metadata["msg_id"] = msg_id
                metadata["rfc"] = "5424"
                metadata["version"] = int(gd["version"])

                msg = (gd.get("msg") or "").strip()

                return ForensicEvent(
                    timestamp=dt,
                    source_type="syslog",
                    source_file=source_file,
                    line_number=line_number,
                    facility=facility,
                    severity=severity,
                    host=host,
                    process=app,
                    pid=pid,
                    message=msg,
                    raw_log=clean_line,
                    metadata=metadata,
                )

            # 2. Try RFC 3164 with Tag & optional PID
            m_3164 = RE_RFC3164.match(clean_line)
            if m_3164:
                gd = m_3164.groupdict()
                pri_str = gd.get("pri")
                if pri_str:
                    facility, severity = parse_pri(int(pri_str))
                else:
                    facility, severity = "syslog", "INFO"
                
                dt = normalize_to_utc(gd["timestamp"], default_year=self.default_year)
                host = gd["hostname"]
                tag = gd.get("tag")
                pid_raw = gd.get("pid")
                pid = int(pid_raw) if pid_raw else None
                msg = (gd.get("msg") or "").strip()

                metadata = {"rfc": "3164"}

                return ForensicEvent(
                    timestamp=dt,
                    source_type="syslog",
                    source_file=source_file,
                    line_number=line_number,
                    facility=facility,
                    severity=severity,
                    host=host,
                    process=tag,
                    pid=pid,
                    message=msg,
                    raw_log=clean_line,
                    metadata=metadata,
                )

            # 3. Try RFC 3164 without Tag
            m_3164_notag = RE_RFC3164_NOTAG.match(clean_line)
            if m_3164_notag:
                gd = m_3164_notag.groupdict()
                pri_str = gd.get("pri")
                if pri_str:
                    facility, severity = parse_pri(int(pri_str))
                else:
                    facility, severity = "syslog", "INFO"
                
                dt = normalize_to_utc(gd["timestamp"], default_year=self.default_year)
                host = gd["hostname"]
                msg = (gd.get("msg") or "").strip()
                metadata = {"rfc": "3164_notag"}

                return ForensicEvent(
                    timestamp=dt,
                    source_type="syslog",
                    source_file=source_file,
                    line_number=line_number,
                    facility=facility,
                    severity=severity,
                    host=host,
                    process=None,
                    pid=None,
                    message=msg,
                    raw_log=clean_line,
                    metadata=metadata,
                )

            logger.debug("Failed to parse syslog line %d in %s", line_number, source_file)
            return None

        except Exception as err:
            # Controlled fail-open (CWE-209): log warning with sanitized line info
            logger.warning(
                "Error parsing syslog line %d in %s: %s",
                line_number,
                source_file,
                str(err),
            )
            return None

    def parse_lines(
        self, lines: Iterable[str], source_file: str = "syslog"
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


def parse_syslog_file(filepath: str, default_year: Optional[int] = None) -> Iterator[ForensicEvent]:
    """Convenience generator to parse a syslog file."""
    parser = SyslogParser(default_year=default_year)
    yield from parser.parse_file(filepath)
