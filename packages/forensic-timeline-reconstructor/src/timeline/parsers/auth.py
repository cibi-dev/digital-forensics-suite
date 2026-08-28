"""Auth.log parser specializing in SSH authentication, sudo escalation, and PAM events."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Iterable, Iterator, Optional

from timeline.normalizer import ForensicEvent, normalize_to_utc

logger = logging.getLogger(__name__)

# Bounded regexes (CWE-1333)
RE_AUTH_HEADER = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?|\d{4}-\d{2}-\d{2}T[^\s]+))\s+"
    r"(?P<hostname>[^\s:]+)\s+"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d{1,10})\])?:\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# Specific SSH Patterns
RE_SSH_ACCEPTED = re.compile(
    r"^Accepted\s+(?P<method>publickey|password|keyboard-interactive)\s+for\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

RE_SSH_FAILED_INVALID = re.compile(
    r"^Failed\s+(?P<method>password|publickey|none)\s+for\s+invalid\s+user\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

RE_SSH_FAILED = re.compile(
    r"^Failed\s+(?P<method>password|publickey|none)\s+for\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

RE_SSH_INVALID_USER = re.compile(
    r"^Invalid\s+user\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

RE_SSH_DISCONNECT = re.compile(
    r"^(?:Disconnected\s+from|Connection\s+closed\s+by)(?:\s+authenticating)?(?:\s+invalid)?(?:\s+user\s+(?P<user>[^\s]+))?\s+(?P<ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

# Sudo Patterns
RE_SUDO_CMD = re.compile(
    r"^\s*(?P<user>[^\s]+)\s*:\s*TTY=(?P<tty>[^\s]+)\s*;\s*PWD=(?P<pwd>[^\s]+)\s*;\s*USER=(?P<target_user>[^\s]+)\s*;\s*COMMAND=(?P<command>.*)$"
)

RE_SUDO_PAM_OPEN = re.compile(
    r"^pam_unix\(sudo:session\):\s*session opened for user (?P<target_user>[^\s\(]+)(?:\(uid=\d+\))? by (?P<user>[^\s\(]+)?(?:\(uid=\d+\))?"
)

RE_SUDO_PAM_CLOSE = re.compile(
    r"^pam_unix\(sudo:session\):\s*session closed for user (?P<target_user>[^\s\(]+)"
)

RE_SUDO_FAILED = re.compile(
    r"^\s*(?P<user>[^\s]+)\s*:\s*(?P<attempts>\d+)\s+incorrect password attempts"
)

# User / Passwd changes
RE_USERADD = re.compile(r"^new user:\s*name=(?P<user>[^,\s]+)")
RE_PASSWD = re.compile(r"^password changed for (?P<user>[^\s]+)")

MAX_LINE_LENGTH = 65536


class AuthLogParser:
    """Specialized streaming parser for Linux /var/log/auth.log and secure logs."""

    def __init__(self, default_year: Optional[int] = None) -> None:
        self.default_year = default_year

    def parse_line(
        self, line: str, line_number: int = 1, source_file: str = "auth.log"
    ) -> Optional[ForensicEvent]:
        """Parse a single auth.log line into a structured ForensicEvent."""
        if not line:
            return None

        clean_line = line.rstrip("\r\n")
        if len(clean_line) > MAX_LINE_LENGTH:
            clean_line = clean_line[:MAX_LINE_LENGTH]

        try:
            m_header = RE_AUTH_HEADER.match(clean_line)
            if not m_header:
                return None

            gd = m_header.groupdict()
            dt = normalize_to_utc(gd["timestamp"], default_year=self.default_year)
            host = gd["hostname"]
            tag = gd["tag"]
            pid_raw = gd.get("pid")
            pid = int(pid_raw) if pid_raw else None
            msg = (gd.get("msg") or "").strip()

            action = "AUTH_EVENT"
            severity = "INFO"
            user: Optional[str] = None
            client_ip: Optional[str] = None
            metadata: dict[str, Any] = {}

            # Analyze message contents
            # 1. SSH Accepted
            m = RE_SSH_ACCEPTED.match(msg)
            if m:
                action = "SSH_LOGIN_SUCCESS"
                severity = "NOTICE"
                user = m.group("user")
                client_ip = m.group("ip")
                metadata["auth_method"] = m.group("method")
                metadata["port"] = int(m.group("port"))

            # 2. SSH Failed (invalid user)
            elif (m := RE_SSH_FAILED_INVALID.match(msg)):
                action = "SSH_LOGIN_FAILED_INVALID_USER"
                severity = "WARNING"
                user = m.group("user")
                client_ip = m.group("ip")
                metadata["auth_method"] = m.group("method")
                metadata["port"] = int(m.group("port"))

            # 3. SSH Failed
            elif (m := RE_SSH_FAILED.match(msg)):
                action = "SSH_LOGIN_FAILED"
                severity = "WARNING"
                user = m.group("user")
                client_ip = m.group("ip")
                metadata["auth_method"] = m.group("method")
                metadata["port"] = int(m.group("port"))

            # 4. SSH Invalid User
            elif (m := RE_SSH_INVALID_USER.match(msg)):
                action = "INVALID_USER"
                severity = "WARNING"
                user = m.group("user")
                client_ip = m.group("ip")
                metadata["port"] = int(m.group("port"))

            # 5. SSH Disconnect
            elif (m := RE_SSH_DISCONNECT.match(msg)):
                action = "SSH_DISCONNECT"
                severity = "INFO"
                user = m.group("user")
                client_ip = m.group("ip")
                metadata["port"] = int(m.group("port"))

            # 6. Sudo Command Execution
            elif (m := RE_SUDO_CMD.match(msg)):
                action = "SUDO_COMMAND"
                severity = "NOTICE"
                user = m.group("user")
                metadata["target_user"] = m.group("target_user")
                metadata["tty"] = m.group("tty")
                metadata["pwd"] = m.group("pwd")
                metadata["command"] = m.group("command")

            # 7. Sudo PAM Open
            elif (m := RE_SUDO_PAM_OPEN.match(msg)):
                action = "PAM_SESSION_OPEN"
                severity = "NOTICE"
                user = m.group("user") or m.group("target_user")
                metadata["target_user"] = m.group("target_user")

            # 8. Sudo PAM Close
            elif (m := RE_SUDO_PAM_CLOSE.match(msg)):
                action = "PAM_SESSION_CLOSE"
                severity = "INFO"
                user = m.group("target_user")

            # 9. Sudo Failed
            elif (m := RE_SUDO_FAILED.match(msg)):
                action = "SUDO_FAILED_AUTH"
                severity = "ALERT"
                user = m.group("user")
                metadata["attempts"] = int(m.group("attempts"))

            # 10. User created
            elif (m := RE_USERADD.match(msg)):
                action = "USER_CREATED"
                severity = "CRITICAL"
                user = m.group("user")

            # 11. Password changed
            elif (m := RE_PASSWD.match(msg)):
                action = "PASSWORD_CHANGED"
                severity = "CRITICAL"
                user = m.group("user")

            return ForensicEvent(
                timestamp=dt,
                source_type="auth",
                source_file=source_file,
                line_number=line_number,
                facility="auth",
                severity=severity,
                host=host,
                process=tag,
                pid=pid,
                user=user,
                client_ip=client_ip,
                action=action,
                message=msg,
                raw_log=clean_line,
                metadata=metadata,
            )

        except Exception as err:
            logger.warning(
                "Error parsing auth log line %d in %s: %s",
                line_number,
                source_file,
                str(err),
            )
            return None

    def parse_lines(
        self, lines: Iterable[str], source_file: str = "auth.log"
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


def parse_auth_file(filepath: str, default_year: Optional[int] = None) -> Iterator[ForensicEvent]:
    """Convenience generator to parse an auth.log file."""
    parser = AuthLogParser(default_year=default_year)
    yield from parser.parse_file(filepath)
