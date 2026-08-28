"""Unit tests for Alerting and Sanitization modules (CWE-209)."""

import json
from datetime import datetime, timezone
import pytest

from detector.alerting import (
    AlertGenerator,
    AlertSeverity,
    ThreatAlert,
    sanitize_dict,
    sanitize_text,
)
from detector.engine import AnomalyScoreResult
from detector.rules import RuleMatch, RuleSeverity


def test_sanitize_text_redacts_passwords_and_tokens() -> None:
    raw = "Failed auth for user=admin password=SecretPassword123 from 10.0.0.1 token=my_secret_token"
    clean = sanitize_text(raw)
    assert "SecretPassword123" not in clean
    assert "my_secret_token" not in clean
    assert "password=[REDACTED]" in clean
    assert "token=[REDACTED]" in clean


def test_sanitize_text_redacts_bearer_and_api_keys() -> None:
    fake_token = "sk_" + "live_1234567890abcdef123456"
    raw = f"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and key: {fake_token}"
    clean = sanitize_text(raw)
    assert "Bearer eyJhb" not in clean
    assert "Bearer [REDACTED]" in clean
    assert "sk_" + "live_" not in clean
    assert "[REDACTED]" in clean


def test_sanitize_text_redacts_private_keys() -> None:
    raw = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0m4wz7
...
-----END RSA PRIVATE KEY-----"""
    clean = sanitize_text(raw)
    assert "MIIEow" not in clean
    assert "[REDACTED_PRIVATE_KEY]" in clean


def test_sanitize_dict_recursive() -> None:
    data = {
        "user": "juan",
        "secret_info": {
            "token": "api_" + "key=ak_secret12345678",
            "logs": ["password=SuperSecret!"],
        },
        "count": 42,
    }
    clean = sanitize_dict(data)
    assert clean["count"] == 42
    assert "SuperSecret!" not in clean["secret_info"]["logs"][0]
    assert "[REDACTED]" in clean["secret_info"]["logs"][0]


def test_alert_generator_triggers_on_anomaly() -> None:
    gen = AlertGenerator(cooldown_seconds=60.0)
    detection = AnomalyScoreResult(
        anomaly_score=0.88,
        iso_score=0.85,
        z_score=0.90,
        is_anomaly=True,
        feature_contributions={"event_count": 0.5},
    )
    rule_match = RuleMatch(
        rule_id="RULE-SSH-BRUTE-FORCE",
        name="SSH Authentication Brute Force",
        severity=RuleSeverity.CRITICAL,
        confidence=0.95,
        description="Brute force detected",
        matched_events_count=50,
    )

    alert = gen.generate_alert(
        entity="198.51.100.42",
        detection=detection,
        rule_matches=[rule_match],
        context_details={"password": "should_be_redacted_123"},
    )

    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.threat_score >= 0.85
    assert alert.entity == "198.51.100.42"
    assert "should_be_redacted_123" not in json.dumps(alert.details)
    assert alert.sanitized is True


def test_alert_generator_cooldown_deduplication() -> None:
    gen = AlertGenerator(cooldown_seconds=300.0)
    detection = AnomalyScoreResult(
        anomaly_score=0.65,
        iso_score=0.60,
        z_score=0.70,
        is_anomaly=True,
        feature_contributions={},
    )
    # First alert should trigger
    alert1 = gen.generate_alert(entity="10.0.0.1", detection=detection)
    assert alert1 is not None

    # Immediate second alert for same entity should be suppressed by cooldown
    alert2 = gen.generate_alert(entity="10.0.0.1", detection=detection)
    assert alert2 is None

    # Reset cooldown and it should trigger again
    gen.reset_cooldown()
    alert3 = gen.generate_alert(entity="10.0.0.1", detection=detection)
    assert alert3 is not None


def test_alert_to_syslog_format() -> None:
    alert = ThreatAlert(
        severity=AlertSeverity.HIGH,
        threat_score=0.85,
        anomaly_score=0.80,
        z_score=0.85,
        entity="198.51.100.42",
        summary="High threat detected",
        details={},
    )
    syslog_msg = alert.to_syslog_str()
    assert "CEF:0|cibi-dev|threat-log-detector" in syslog_msg
    assert "src=198.51.100.42" in syslog_msg
    assert "HIGH" in syslog_msg
