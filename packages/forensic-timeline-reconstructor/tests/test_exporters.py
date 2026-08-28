"""Tests for exporters: JSON-Lines streaming and Markdown executive report."""

from datetime import datetime, timezone, timedelta
import io
import json
import os
import tempfile
import pytest

from timeline.exporters.jsonl import export_jsonl, export_jsonl_stream
from timeline.exporters.markdown import export_markdown_report, render_markdown_report
from timeline.integrity import AnomalySeverity, AnomalyType, IntegrityAnomaly
from timeline.normalizer import ForensicEvent


def test_export_jsonl_io_and_file() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(timestamp=t0, source_type="syslog", message="syslog 1"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=1), source_type="auth", message="auth 1"),
    ]

    # Test StringIO
    buf = io.StringIO()
    count = export_jsonl(events, target=buf)
    assert count == 2
    lines = buf.getvalue().strip().split("\n")
    assert len(lines) == 2
    obj1 = json.loads(lines[0])
    assert obj1["source_type"] == "syslog"

    # Test File
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as tf:
        tf_path = tf.name

    try:
        count_f = export_jsonl(events, target=tf_path)
        assert count_f == 2
        with open(tf_path, "r", encoding="utf-8") as f:
            f_lines = f.readlines()
        assert len(f_lines) == 2
    finally:
        os.unlink(tf_path)


def test_export_markdown_report() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(
            timestamp=t0,
            source_type="auth",
            source_file="auth.log",
            user="ubuntu",
            client_ip="192.168.1.50",
            severity="NOTICE",
            action="SSH_LOGIN_SUCCESS",
            message="User ubuntu logged in",
        ),
        ForensicEvent(
            timestamp=t0 + timedelta(seconds=10),
            source_type="auth",
            source_file="auth.log",
            user="ubuntu",
            severity="NOTICE",
            action="SUDO_COMMAND",
            message="sudo whoami",
        ),
    ]

    anomalies = [
        IntegrityAnomaly(
            anomaly_type=AnomalyType.NEGATIVE_CLOCK_JUMP.value,
            severity=AnomalySeverity.CRITICAL.value,
            source_file="auth.log",
            start_line=1,
            end_line=2,
            start_time=t0,
            end_time=t0 - timedelta(seconds=50),
            delta_seconds=-50.0,
            description="Clock roll back detected",
        )
    ]

    attack_chains = [
        {
            "pivot": "user:ubuntu",
            "chain_type": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "start_time": t0.isoformat(),
            "end_time": (t0 + timedelta(seconds=10)).isoformat(),
            "description": "User logged in and ran sudo",
            "events": [e.to_dict() for e in events],
        }
    ]

    report = render_markdown_report(
        events,
        anomalies=anomalies,
        attack_chains=attack_chains,
        title="Test Investigation",
    )

    assert "# 🛡️ Test Investigation" in report
    assert "Executive Summary" in report
    assert "COMPROMISED / ANOMALIES DETECTED" in report
    assert "NEGATIVE_CLOCK_JUMP" in report
    assert "PRIVILEGE_ESCALATION" in report
    assert "192.168.1.50" in report
    assert "sudo whoami" in report

    # Export to file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".md") as tf:
        md_path = tf.name
    try:
        out_content = export_markdown_report(events, output_file=md_path, anomalies=anomalies)
        assert os.path.exists(md_path)
        assert len(out_content) > 100
    finally:
        os.unlink(md_path)
