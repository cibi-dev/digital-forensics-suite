"""Tests for correlator.py: streaming multi-source merge, filtering, and attack chains."""

from datetime import datetime, timezone, timedelta
import os
import tempfile
import pytest

from timeline.correlator import (
    TimelineCorrelator,
    correlate_streams,
    detect_parser_for_file,
)
from timeline.normalizer import ForensicEvent
from timeline.parsers.auth import AuthLogParser
from timeline.parsers.json_lines import JsonLinesParser
from timeline.parsers.nginx import NginxParser
from timeline.parsers.syslog import SyslogParser


def test_detect_parser_for_file() -> None:
    # 1. JSON file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as tf:
        tf.write('{"timestamp": "2023-10-11T12:00:00Z", "message": "hello"}\n')
        p_json = tf.name
    # 2. Nginx access file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tf:
        tf.write('127.0.0.1 - - [10/Oct/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"\n')
        p_nginx = tf.name
    # 3. Auth log file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tf:
        tf.write("Oct 11 12:00:00 myhost sshd[100]: Accepted publickey for root from 1.1.1.1 port 22 ssh2\n")
        p_auth = tf.name
    # 4. Syslog file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tf:
        tf.write("<165>1 2023-10-11T12:00:00Z myhost myapp 100 ID47 - Application started\n")
        p_syslog = tf.name

    try:
        assert isinstance(detect_parser_for_file(p_json), JsonLinesParser)
        assert isinstance(detect_parser_for_file(p_nginx), NginxParser)
        assert isinstance(detect_parser_for_file(p_auth), AuthLogParser)
        assert isinstance(detect_parser_for_file(p_syslog), SyslogParser)
    finally:
        for p in (p_json, p_nginx, p_auth, p_syslog):
            os.unlink(p)


def test_correlate_streams_k_way_merge() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    s1 = [
        ForensicEvent(timestamp=t0 + timedelta(seconds=1), source_type="auth", message="auth 1"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=4), source_type="auth", message="auth 4"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=7), source_type="auth", message="auth 7"),
    ]
    s2 = [
        ForensicEvent(timestamp=t0 + timedelta(seconds=2), source_type="nginx", message="nginx 2"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=5), source_type="nginx", message="nginx 5"),
    ]
    s3 = [
        ForensicEvent(timestamp=t0 + timedelta(seconds=3), source_type="syslog", message="syslog 3"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=6), source_type="syslog", message="syslog 6"),
    ]

    merged = list(correlate_streams(iter(s1), iter(s2), iter(s3)))
    assert len(merged) == 7
    # Verify strict ascending order
    for i in range(len(merged) - 1):
        assert merged[i].timestamp <= merged[i + 1].timestamp

    messages = [e.message for e in merged]
    assert messages == ["auth 1", "nginx 2", "syslog 3", "auth 4", "nginx 5", "syslog 6", "auth 7"]


def test_correlator_filter_events() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(
            timestamp=t0,
            source_type="auth",
            severity="INFO",
            user="alice",
            client_ip="192.168.1.10",
            message="Alice login",
        ),
        ForensicEvent(
            timestamp=t0 + timedelta(minutes=5),
            source_type="auth",
            severity="WARNING",
            user="bob",
            client_ip="10.0.0.5",
            message="Bob failed login",
        ),
        ForensicEvent(
            timestamp=t0 + timedelta(minutes=10),
            source_type="nginx_access",
            severity="ERROR",
            client_ip="10.0.0.5",
            message="HTTP 500 internal server error",
        ),
    ]

    correlator = TimelineCorrelator()

    # Time filter
    res_time = list(correlator.filter_events(
        events,
        start_time=t0 + timedelta(minutes=2),
        end_time=t0 + timedelta(minutes=7),
    ))
    assert len(res_time) == 1
    assert res_time[0].user == "bob"

    # Min severity filter
    res_sev = list(correlator.filter_events(events, min_severity="WARNING"))
    assert len(res_sev) == 2
    assert [e.severity for e in res_sev] == ["WARNING", "ERROR"]

    # User filter
    res_user = list(correlator.filter_events(events, users={"alice"}))
    assert len(res_user) == 1
    assert res_user[0].user == "alice"

    # IP filter
    res_ip = list(correlator.filter_events(events, client_ips={"10.0.0.5"}))
    assert len(res_ip) == 2

    # Regex search
    res_search = list(correlator.filter_events(events, search_pattern=r"500\s+internal"))
    assert len(res_search) == 1
    assert res_search[0].source_type == "nginx_access"


def test_correlator_attack_chains() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    ip_attacker = "198.51.100.22"

    events = [
        # Brute force from IP
        ForensicEvent(timestamp=t0, source_type="auth", action="SSH_LOGIN_FAILED", client_ip=ip_attacker, user="root"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=2), source_type="auth", action="SSH_LOGIN_FAILED", client_ip=ip_attacker, user="admin"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=4), source_type="auth", action="SSH_LOGIN_FAILED", client_ip=ip_attacker, user="deploy"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=6), source_type="auth", action="SSH_LOGIN_SUCCESS", client_ip=ip_attacker, user="deploy"),

        # User deploy privilege escalation
        ForensicEvent(timestamp=t0 + timedelta(seconds=10), source_type="auth", action="SUDO_COMMAND", user="deploy", message="sudo /bin/bash"),
    ]

    correlator = TimelineCorrelator()
    chains = correlator.find_attack_chains(events, max_gap_seconds=60.0)

    assert len(chains) == 2
    chain_types = {c["chain_type"] for c in chains}
    assert "BRUTE_FORCE_SUCCESS" in chain_types
    assert "PRIVILEGE_ESCALATION" in chain_types
