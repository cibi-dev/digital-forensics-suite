"""Tests for integrity.py: timestomping, negative clock jumps, and deletion gaps."""

from datetime import datetime, timezone, timedelta
import os
import tempfile
import pytest

from timeline.integrity import (
    AnomalySeverity,
    AnomalyType,
    IntegrityAnalyzer,
    IntegrityAnomaly,
)
from timeline.normalizer import ForensicEvent


def test_integrity_negative_clock_jump() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(timestamp=t0, source_file="auth.log", line_number=1, message="Event 1"),
        ForensicEvent(timestamp=t0 + timedelta(seconds=10), source_file="auth.log", line_number=2, message="Event 2"),
        # Attacker rolled clock back 500 seconds
        ForensicEvent(timestamp=t0 - timedelta(seconds=490), source_file="auth.log", line_number=3, message="Tampered Event 3"),
    ]

    analyzer = IntegrityAnalyzer(reference_now=t0 + timedelta(hours=1))
    anomalies = list(analyzer.analyze_stream(events))

    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.anomaly_type == AnomalyType.NEGATIVE_CLOCK_JUMP.value
    assert a.severity == AnomalySeverity.CRITICAL.value
    assert a.start_line == 2
    assert a.end_line == 3
    assert a.delta_seconds < 0


def test_integrity_anomalous_gap() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(timestamp=t0, source_file="syslog.log", line_number=10, message="Normal event"),
        # Gap of 7200 seconds (2 hours)
        ForensicEvent(timestamp=t0 + timedelta(seconds=7200), source_file="syslog.log", line_number=11, message="Post-gap event"),
    ]

    analyzer = IntegrityAnalyzer(max_allowed_gap_seconds=3600.0, reference_now=t0 + timedelta(days=1))
    anomalies = list(analyzer.analyze_stream(events))

    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.anomaly_type == AnomalyType.ANOMALOUS_GAP.value
    assert a.severity == AnomalySeverity.MEDIUM.value
    assert a.delta_seconds == 7200.0


def test_integrity_future_timestamp() -> None:
    ref_now = datetime(2023, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(
            timestamp=ref_now + timedelta(days=5),
            source_file="nginx.log",
            line_number=1,
            message="Future event",
        )
    ]

    analyzer = IntegrityAnalyzer(reference_now=ref_now, future_skew_tolerance_seconds=60.0)
    anomalies = list(analyzer.analyze_stream(events))

    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == AnomalyType.FUTURE_TIMESTAMP.value
    assert anomalies[0].severity == AnomalySeverity.HIGH.value


def test_integrity_burst_detection() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(
            timestamp=t0,
            source_file="auth.log",
            line_number=i,
            message=f"Burst event {i}",
        )
        for i in range(1, 250)
    ]

    analyzer = IntegrityAnalyzer(burst_threshold_events_per_sec=100, reference_now=t0 + timedelta(days=1))
    anomalies = list(analyzer.analyze_stream(events))

    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == AnomalyType.BURST_INCONSISTENCY.value


def test_integrity_analyzer_clean_stream() -> None:
    t0 = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(timestamp=t0 + timedelta(seconds=i), source_file="clean.log", line_number=i, message=f"Log {i}")
        for i in range(1, 20)
    ]

    analyzer = IntegrityAnalyzer(reference_now=t0 + timedelta(days=1))
    anomalies = list(analyzer.analyze_stream(events))
    summary = analyzer.generate_integrity_summary(anomalies)

    assert len(anomalies) == 0
    assert summary["status"] == "CLEAN"
    assert summary["total_anomalies"] == 0
