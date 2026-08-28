"""Unit tests for LogParser module."""

from datetime import datetime, timezone
import pytest

from detector.parser import EventType, LogParser, SourceType, MAX_LINE_LENGTH


@pytest.fixture
def parser() -> LogParser:
    return LogParser(default_year=2026)


def test_parse_empty_and_whitespace(parser: LogParser) -> None:
    ev_empty = parser.parse_line("")
    assert ev_empty.event_type == EventType.MALFORMED
    assert ev_empty.status == "empty"

    ev_space = parser.parse_line("   \n\t ")
    assert ev_space.event_type == EventType.MALFORMED
    assert ev_space.status == "empty"


def test_parse_line_too_long(parser: LogParser) -> None:
    huge_line = "A" * (MAX_LINE_LENGTH + 10)
    ev = parser.parse_line(huge_line)
    assert ev.event_type == EventType.MALFORMED
    assert ev.status == "line_too_long"
    assert "[TRUNCATED]" in ev.raw_message


def test_parse_auth_ssh_failed_password(parser: LogParser) -> None:
    line = "Aug 27 15:20:01 srv-core sshd[14231]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_AUTH_FAIL
    assert ev.source_type == SourceType.AUTH_LOG
    assert ev.src_ip == "198.51.100.42"
    assert ev.src_port == 54321
    assert ev.user == "admin"
    assert ev.status == "failed"
    assert ev.timestamp.year == 2026
    assert ev.timestamp.month == 8
    assert ev.timestamp.day == 27


def test_parse_auth_ssh_accepted_password(parser: LogParser) -> None:
    line = "Aug 27 15:20:05 srv-core sshd[14232]: Accepted password for juan from 192.168.1.50 port 54322 ssh2"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_AUTH_SUCCESS
    assert ev.src_ip == "192.168.1.50"
    assert ev.user == "juan"
    assert ev.status == "success"


def test_parse_auth_ssh_accepted_publickey(parser: LogParser) -> None:
    line = "Aug 27 15:20:10 srv-core sshd[14233]: Accepted publickey for cibi from 10.0.1.15 port 54323 ssh2"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_AUTH_SUCCESS
    assert ev.user == "cibi"
    assert ev.src_ip == "10.0.1.15"


def test_parse_auth_ssh_invalid_user(parser: LogParser) -> None:
    line = "Aug 27 15:20:12 srv-core sshd[14234]: Invalid user guest from 203.0.113.88 port 48210"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_INVALID_USER
    assert ev.user == "guest"
    assert ev.src_ip == "203.0.113.88"
    assert ev.src_port == 48210


def test_parse_auth_ssh_disconnect(parser: LogParser) -> None:
    line = "Aug 27 15:20:15 srv-core sshd[14235]: Disconnected from invalid user test 198.51.100.42 port 54321 [preauth]"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_DISCONNECT
    assert ev.src_ip == "198.51.100.42"
    assert ev.user == "test"


def test_parse_auth_pam_failure(parser: LogParser) -> None:
    line = "Aug 27 15:20:18 srv-core sshd[14236]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.42  user=root"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_AUTH_FAIL
    assert ev.src_ip == "198.51.100.42"
    assert ev.user == "root"


def test_parse_sudo_command(parser: LogParser) -> None:
    line = "Aug 27 15:20:20 srv-core sudo:   juan : TTY=pts/0 ; PWD=/home/juan ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SUDO_COMMAND
    assert ev.user == "juan"
    assert ev.metadata.get("command") == "/usr/bin/systemctl restart nginx"
    assert ev.metadata.get("target_user") == "root"


def test_parse_sudo_auth_failure(parser: LogParser) -> None:
    line = "Aug 27 15:20:22 srv-core sudo: pam_unix(sudo:auth): authentication failure; logname=juan uid=1000 euid=0 tty=/dev/pts/1 ruser=juan rhost= user=juan"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SUDO_AUTH_FAIL
    assert ev.user == "juan"


def test_parse_iso8601_auth_log(parser: LogParser) -> None:
    line = "2026-08-27T15:25:30.123456+00:00 srv-core sshd[9999]: Failed password for root from 192.0.2.1 port 2222 ssh2"
    ev = parser.parse_line(line)
    assert ev.event_type == EventType.SSH_AUTH_FAIL
    assert ev.src_ip == "192.0.2.1"
    assert ev.user == "root"
    assert ev.timestamp.year == 2026
    assert ev.timestamp.minute == 25


def test_parse_syslog_rfc5424(parser: LogParser) -> None:
    line = "<134>1 2026-08-27T15:30:00Z srv01.corp sshd 8712 ID47 [exampleSDID@32473 iut=\"3\"] Failed password for admin from 10.0.0.99 port 60000 ssh2"
    ev = parser.parse_line(line, format_hint="syslog")
    assert ev.source_type == SourceType.SYSLOG
    assert ev.event_type == EventType.SSH_AUTH_FAIL
    assert ev.src_ip == "10.0.0.99"
    assert ev.user == "admin"


def test_parse_network_json_flow(parser: LogParser) -> None:
    json_str = '{"timestamp": "2026-08-27T15:40:00Z", "src_ip": "10.0.4.15", "dst_ip": "185.220.101.5", "src_port": 45120, "dst_port": 443, "bytes_sent": 25000000, "bytes_recv": 500, "duration": 4.5, "event_type": "network_flow", "is_anomaly": true}'
    ev = parser.parse_line(json_str, format_hint="json")
    assert ev.source_type == SourceType.NETWORK_JSON
    assert ev.event_type == EventType.NETWORK_FLOW
    assert ev.src_ip == "10.0.4.15"
    assert ev.dst_ip == "185.220.101.5"
    assert ev.bytes_sent == 25000000
    assert ev.bytes_recv == 500
    assert ev.duration == 4.5
    assert ev.is_anomaly is True


def test_parse_network_json_zeek_format(parser: LogParser) -> None:
    json_str = '{"ts": 1787845200.0, "orig_h": "192.168.1.10", "resp_h": "8.8.8.8", "orig_p": 54000, "resp_p": 53, "orig_bytes": 120, "resp_bytes": 450, "duration": 0.05}'
    ev = parser.parse_line(json_str, format_hint="json")
    assert ev.src_ip == "192.168.1.10"
    assert ev.dst_ip == "8.8.8.8"
    assert ev.src_port == 54000
    assert ev.dst_port == 53
    assert ev.bytes_sent == 120
    assert ev.bytes_recv == 450


def test_parse_corrupted_json(parser: LogParser) -> None:
    bad_json = '{"timestamp": "invalid", "unclosed": true'
    ev = parser.parse_line(bad_json, format_hint="json")
    assert ev.event_type == EventType.MALFORMED
    assert ev.status == "json_parse_error"


def test_parse_stream_generator(parser: LogParser) -> None:
    lines = [
        "Aug 27 15:00:01 srv sshd[1]: Failed password for root from 1.1.1.1 port 1111 ssh2",
        "Aug 27 15:00:02 srv sshd[2]: Accepted password for juan from 2.2.2.2 port 2222 ssh2",
        "",
    ]
    events = list(parser.parse_stream(lines))
    assert len(events) == 3
    assert events[0].event_type == EventType.SSH_AUTH_FAIL
    assert events[1].event_type == EventType.SSH_AUTH_SUCCESS
    assert events[2].event_type == EventType.MALFORMED
