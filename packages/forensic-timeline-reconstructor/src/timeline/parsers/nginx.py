"""Nginx access and error log parser with microsecond-resolution normalization."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Iterable, Iterator, Optional

from timeline.normalizer import ForensicEvent, normalize_severity, normalize_to_utc

logger = logging.getLogger(__name__)

# Bounded regexes (CWE-1333)
RE_NGINX_COMBINED = re.compile(
    r"^(?P<ip>[^\s]+)\s+"
    r"(?P<ident>[^\s]+)\s+"
    r"(?P<user>[^\s]+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?',
    re.DOTALL,
)

RE_NGINX_ERROR_LOG = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+"
    r"\[(?P<level>[a-zA-Z]+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s+"
    r"(?:\*(?P<cid>\d+)\s+)?"
    r"(?P<msg>.*?)"
    r"(?:,\s+client:\s+(?P<client>[^,]+))?"
    r"(?:,\s+server:\s+(?P<server>[^,]+))?"
    r'(?:,\s+request:\s+"(?P<request>[^"]*)")?'
    r'(?:,\s+host:\s+"(?P<host>[^"]*)")?$',
    re.DOTALL,
)

MAX_LINE_LENGTH = 65536


class NginxParser:
    """High-throughput parser for Nginx Combined Access and Error logs."""

    def __init__(self, default_year: Optional[int] = None) -> None:
        self.default_year = default_year

    def parse_access_line(
        self, line: str, line_number: int = 1, source_file: str = "nginx_access.log"
    ) -> Optional[ForensicEvent]:
        """Parse an Nginx access log line."""
        m = RE_NGINX_COMBINED.match(line)
        if not m:
            return None

        gd = m.groupdict()
        dt = normalize_to_utc(gd["time"], default_year=self.default_year)
        client_ip = gd["ip"]
        user = gd["user"] if gd["user"] != "-" else None
        status_code = int(gd["status"])
        bytes_sent = int(gd["bytes"]) if gd["bytes"].isdigit() else 0
        req = gd.get("request") or ""

        parts = req.split(" ", 2)
        method = parts[0] if parts else "UNKNOWN"
        url = parts[1] if len(parts) > 1 else ""
        http_ver = parts[2] if len(parts) > 2 else ""

        if status_code >= 500:
            severity = "ERROR"
        elif status_code >= 400:
            severity = "WARNING"
        else:
            severity = "INFO"

        action = f"HTTP_{method}_{status_code}"
        metadata: dict[str, Any] = {
            "method": method,
            "url": url,
            "http_version": http_ver,
            "status_code": status_code,
            "bytes_sent": bytes_sent,
        }
        if gd.get("referer") and gd["referer"] != "-":
            metadata["referer"] = gd["referer"]
        if gd.get("user_agent") and gd["user_agent"] != "-":
            metadata["user_agent"] = gd["user_agent"]

        return ForensicEvent(
            timestamp=dt,
            source_type="nginx_access",
            source_file=source_file,
            line_number=line_number,
            facility="daemon",
            severity=severity,
            host=None,
            process="nginx",
            pid=None,
            user=user,
            client_ip=client_ip,
            action=action,
            message=f"{method} {url} HTTP status {status_code}",
            raw_log=line,
            metadata=metadata,
        )

    def parse_error_line(
        self, line: str, line_number: int = 1, source_file: str = "nginx_error.log"
    ) -> Optional[ForensicEvent]:
        """Parse an Nginx error log line."""
        m = RE_NGINX_ERROR_LOG.match(line)
        if not m:
            return None

        gd = m.groupdict()
        dt = normalize_to_utc(gd["timestamp"], default_year=self.default_year)
        level_raw = gd["level"]
        severity = normalize_severity(level_raw)
        pid = int(gd["pid"])
        tid = int(gd["tid"])
        msg = gd.get("msg") or ""
        client_ip = gd.get("client")
        server = gd.get("server")
        req = gd.get("request")
        host = gd.get("host") or server

        metadata: dict[str, Any] = {
            "tid": tid,
            "raw_level": level_raw,
        }
        if gd.get("cid"):
            metadata["cid"] = int(gd["cid"])
        if server:
            metadata["server"] = server
        if req:
            metadata["request"] = req

        return ForensicEvent(
            timestamp=dt,
            source_type="nginx_error",
            source_file=source_file,
            line_number=line_number,
            facility="daemon",
            severity=severity,
            host=host,
            process="nginx",
            pid=pid,
            user=None,
            client_ip=client_ip,
            action=f"NGINX_ERROR_{level_raw.upper()}",
            message=msg,
            raw_log=line,
            metadata=metadata,
        )

    def parse_line(
        self, line: str, line_number: int = 1, source_file: str = "nginx.log"
    ) -> Optional[ForensicEvent]:
        """Auto-detect access or error log and parse line."""
        if not line:
            return None

        clean_line = line.rstrip("\r\n")
        if len(clean_line) > MAX_LINE_LENGTH:
            clean_line = clean_line[:MAX_LINE_LENGTH]

        try:
            # Check combined access first
            evt = self.parse_access_line(clean_line, line_number=line_number, source_file=source_file)
            if evt is not None:
                return evt
            # Check error log
            return self.parse_error_line(clean_line, line_number=line_number, source_file=source_file)
        except Exception as err:
            logger.warning(
                "Error parsing nginx line %d in %s: %s",
                line_number,
                source_file,
                str(err),
            )
            return None

    def parse_lines(
        self, lines: Iterable[str], source_file: str = "nginx.log"
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


def parse_nginx_file(filepath: str, default_year: Optional[int] = None) -> Iterator[ForensicEvent]:
    """Convenience generator to parse an nginx log file."""
    parser = NginxParser(default_year=default_year)
    yield from parser.parse_file(filepath)
