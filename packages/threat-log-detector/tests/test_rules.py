"""Unit tests for heuristic correlation rules."""

from datetime import datetime, timezone
import pytest

from detector.parser import EventType, LogEvent, SourceType
from detector.rules import (
    DataExfiltrationRule,
    HeuristicRuleEngine,
    PasswordSprayingRule,
    PortScanRule,
    PrivilegeEscalationRule,
    RuleSeverity,
    SSHBruteForceRule,
)


def make_event(
    event_type: EventType,
    src_ip: str = "1.1.1.1",
    user: str = "root",
    status: str = "failed",
    bytes_sent: int = 0,
    bytes_recv: int = 0,
    dst_port: int = 22,
) -> LogEvent:
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.AUTH_LOG,
        event_type=event_type,
        src_ip=src_ip,
        user=user,
        status=status,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        dst_port=dst_port,
    )


def test_ssh_brute_force_rule_triggers_on_failures() -> None:
    rule = SSHBruteForceRule(min_failures=5, max_distinct_users=2)
    # 6 failed events on single user
    events = [make_event(EventType.SSH_AUTH_FAIL, user="root") for _ in range(6)]
    match = rule.evaluate(events, entity="198.51.100.42")

    assert match is not None
    assert match.rule_id == "RULE-SSH-BRUTE-FORCE"
    assert match.severity in (RuleSeverity.HIGH, RuleSeverity.CRITICAL)
    assert match.matched_events_count == 6


def test_ssh_brute_force_rule_does_not_trigger_on_few_failures() -> None:
    rule = SSHBruteForceRule(min_failures=5)
    events = [make_event(EventType.SSH_AUTH_FAIL, user="root") for _ in range(3)]
    assert rule.evaluate(events) is None


def test_ssh_brute_force_critical_severity_on_massive_burst() -> None:
    rule = SSHBruteForceRule(min_failures=5)
    events = [make_event(EventType.SSH_AUTH_FAIL, user="root") for _ in range(25)]
    match = rule.evaluate(events)
    assert match is not None
    assert match.severity == RuleSeverity.CRITICAL


def test_password_spraying_rule_triggers_on_many_users() -> None:
    rule = PasswordSprayingRule(min_distinct_users=4, max_per_user_attempts=2)
    users = ["admin", "oracle", "postgres", "test", "deploy", "guest"]
    events = [make_event(EventType.SSH_AUTH_FAIL, user=u) for u in users]
    match = rule.evaluate(events, entity="203.0.113.88")

    assert match is not None
    assert match.rule_id == "RULE-PASSWORD-SPRAY"
    assert match.details["distinct_users_count"] == 6


def test_password_spraying_rule_does_not_trigger_on_single_user() -> None:
    rule = PasswordSprayingRule(min_distinct_users=4)
    events = [make_event(EventType.SSH_AUTH_FAIL, user="root") for _ in range(10)]
    assert rule.evaluate(events) is None


def test_data_exfiltration_rule_triggers_on_high_bytes_and_ratio() -> None:
    rule = DataExfiltrationRule(min_bytes_sent=5_000_000, min_bytes_ratio=8.0)
    events = [
        make_event(EventType.NETWORK_FLOW, bytes_sent=20_000_000, bytes_recv=100_000),
    ]
    match = rule.evaluate(events, entity="10.0.4.15")

    assert match is not None
    assert match.rule_id == "RULE-DATA-EXFILTRATION"
    assert match.severity == RuleSeverity.HIGH


def test_data_exfiltration_rule_does_not_trigger_on_normal_traffic() -> None:
    rule = DataExfiltrationRule(min_bytes_sent=5_000_000)
    events = [
        make_event(EventType.NETWORK_FLOW, bytes_sent=10_000, bytes_recv=50_000),
    ]
    assert rule.evaluate(events) is None


def test_privilege_escalation_rule() -> None:
    rule = PrivilegeEscalationRule(min_sudo_fails=2)
    events = [
        make_event(EventType.SUDO_AUTH_FAIL, user="juan"),
        make_event(EventType.SUDO_AUTH_FAIL, user="juan"),
    ]
    match = rule.evaluate(events)
    assert match is not None
    assert match.rule_id == "RULE-PRIVILEGE-ESCALATION"


def test_port_scan_rule() -> None:
    rule = PortScanRule(min_unique_ports=5)
    events = [
        make_event(EventType.NETWORK_FLOW, dst_port=p) for p in [21, 22, 23, 25, 80, 443]
    ]
    match = rule.evaluate(events)
    assert match is not None
    assert match.rule_id == "RULE-PORT-SCAN"
    assert match.details["unique_ports_count"] == 6


def test_heuristic_rule_engine_composite() -> None:
    engine = HeuristicRuleEngine()
    events = [
        make_event(EventType.SSH_AUTH_FAIL, user="admin") for _ in range(10)
    ]
    matches = engine.evaluate_events(events, entity="1.2.3.4")
    assert len(matches) >= 1
    assert matches[0].rule_id == "RULE-SSH-BRUTE-FORCE"
