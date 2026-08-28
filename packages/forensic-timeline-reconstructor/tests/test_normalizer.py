"""Tests for normalizer.py: UTC conversion, microsecond resolution, and ForensicEvent."""

from datetime import datetime, timezone, timedelta
import pytest
from pydantic import ValidationError

from timeline.normalizer import (
    ForensicEvent,
    normalize_severity,
    normalize_to_utc,
    generate_event_id,
)


def test_normalize_to_utc_datetime() -> None:
    # Naive datetime gets converted assuming UTC default
    dt_naive = datetime(2023, 10, 11, 15, 30, 45, 123456)
    res = normalize_to_utc(dt_naive)
    assert res.tzinfo == timezone.utc
    assert res.microsecond == 123456

    # Aware datetime with timezone offset +02:00
    tz_plus_2 = timezone(timedelta(hours=2))
    dt_aware = datetime(2023, 10, 11, 15, 30, 45, 123456, tzinfo=tz_plus_2)
    res_aware = normalize_to_utc(dt_aware)
    assert res_aware.tzinfo == timezone.utc
    assert res_aware.hour == 13
    assert res_aware.minute == 30
    assert res_aware.microsecond == 123456


def test_normalize_to_utc_epochs() -> None:
    # Seconds
    ts_sec = 1697062455.123456
    res = normalize_to_utc(ts_sec)
    assert res.tzinfo == timezone.utc
    assert res.microsecond == 123456

    # Milliseconds (13 digits)
    ts_ms = 1697062455123
    res_ms = normalize_to_utc(ts_ms)
    assert res_ms.tzinfo == timezone.utc
    assert res_ms.microsecond == 123000

    # Microseconds (16 digits)
    ts_us = 1697062455123456
    res_us = normalize_to_utc(ts_us)
    assert res_us.tzinfo == timezone.utc
    assert res_us.microsecond == 123456

    # Nanoseconds (19 digits)
    ts_ns = 1697062455123456789
    res_ns = normalize_to_utc(ts_ns)
    assert res_ns.tzinfo == timezone.utc
    assert res_ns.microsecond == 123456


def test_normalize_to_utc_strings() -> None:
    # ISO 8601 with Z and microseconds
    res_iso = normalize_to_utc("2023-10-11T22:14:15.654321Z")
    assert res_iso == datetime(2023, 10, 11, 22, 14, 15, 654321, tzinfo=timezone.utc)

    # ISO 8601 with timezone offset
    res_offset = normalize_to_utc("2023-10-11T22:14:15.654321+02:00")
    assert res_offset == datetime(2023, 10, 11, 20, 14, 15, 654321, tzinfo=timezone.utc)

    # Nginx access log format
    res_nginx_acc = normalize_to_utc("10/Oct/2023:13:55:36.999999 +0000")
    assert res_nginx_acc == datetime(2023, 10, 10, 13, 55, 36, 999999, tzinfo=timezone.utc)

    # Nginx error log format
    res_nginx_err = normalize_to_utc("2023/10/11 12:34:56.500000")
    assert res_nginx_err == datetime(2023, 10, 11, 12, 34, 56, 500000, tzinfo=timezone.utc)

    # BSD Syslog format with explicit year
    res_bsd = normalize_to_utc("Oct 11 22:14:15.123456", default_year=2023)
    assert res_bsd == datetime(2023, 10, 11, 22, 14, 15, 123456, tzinfo=timezone.utc)

    # Numeric string epoch
    res_str_num = normalize_to_utc("1697062455.5")
    assert res_str_num.microsecond == 500000


def test_normalize_to_utc_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="Empty timestamp string"):
        normalize_to_utc("")

    with pytest.raises(ValueError, match="exceeds maximum length"):
        normalize_to_utc("2023-01-01 " + "A" * 300)

    with pytest.raises(ValueError, match="Unsupported timestamp type"):
        normalize_to_utc({"invalid": "dict"})  # type: ignore

    with pytest.raises(ValueError, match="Failed to parse timestamp"):
        normalize_to_utc("not-a-timestamp-at-all-xyz")


def test_normalize_severity() -> None:
    assert normalize_severity(0) == "EMERGENCY"
    assert normalize_severity(1) == "ALERT"
    assert normalize_severity(2) == "CRITICAL"
    assert normalize_severity(3) == "ERROR"
    assert normalize_severity(4) == "WARNING"
    assert normalize_severity(5) == "NOTICE"
    assert normalize_severity(6) == "INFO"
    assert normalize_severity(7) == "DEBUG"

    assert normalize_severity("ERR") == "ERROR"
    assert normalize_severity("warn") == "WARNING"
    assert normalize_severity("CRIT") == "CRITICAL"
    assert normalize_severity("panic") == "EMERGENCY"
    assert normalize_severity("3") == "ERROR"
    assert normalize_severity(None) == "INFO"
    assert normalize_severity("CUSTOM_SEV") == "CUSTOM_SEV"


def test_forensic_event_validation_and_ordering() -> None:
    dt1 = datetime(2023, 10, 11, 10, 0, 0, 100, tzinfo=timezone.utc)
    dt2 = datetime(2023, 10, 11, 10, 0, 0, 200, tzinfo=timezone.utc)

    evt1 = ForensicEvent(
        timestamp=dt1,
        source_type="syslog",
        source_file="syslog.log",
        line_number=10,
        message="first event",
    )
    evt2 = ForensicEvent(
        timestamp=dt2,
        source_type="syslog",
        source_file="syslog.log",
        line_number=11,
        message="second event",
    )

    # Ordering
    assert evt1 < evt2
    assert not (evt2 < evt1)

    # Event ID is populated
    assert evt1.event_id != ""
    assert len(evt1.event_id) == 16

    # Serialization
    d = evt1.to_dict()
    assert d["timestamp"] == "2023-10-11T10:00:00.000100+00:00"
    assert d["message"] == "first event"

    jsonl = evt1.to_jsonl()
    assert '"timestamp": "2023-10-11T10:00:00.000100+00:00"' in jsonl

    # Extra fields forbidden (CWE-502)
    with pytest.raises(ValidationError):
        ForensicEvent(
            timestamp=dt1,
            source_type="syslog",
            malicious_injected_field="payload",  # type: ignore
        )


def test_forensic_event_raw_log_truncation() -> None:
    oversized_log = "X" * 6000
    dt = datetime(2023, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    evt = ForensicEvent(
        timestamp=dt,
        source_type="syslog",
        raw_log=oversized_log,
    )
    assert len(evt.raw_log) <= 4096
    assert evt.raw_log.endswith("...")
