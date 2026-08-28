"""Heuristic correlation rules for threat identification and explainability."""

from __future__ import annotations

from collections import Counter
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from detector.features import FeatureVector
from detector.parser import EventType, LogEvent


class RuleSeverity(str, Enum):
    """Severity classification for matched heuristic rules."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleMatch(BaseModel):
    """Specific heuristic rule match finding."""
    model_config = ConfigDict(frozen=True)

    rule_id: str
    name: str
    severity: RuleSeverity
    confidence: float
    description: str
    entity: Optional[str] = None
    matched_events_count: int = 0
    details: Dict[str, Any] = Field(default_factory=dict)


class BaseRule:
    """Abstract base class for security heuristic rules."""

    rule_id: str = "RULE-BASE"
    name: str = "Base Rule"
    default_severity: RuleSeverity = RuleSeverity.MEDIUM

    def evaluate(self, events: List[LogEvent], entity: Optional[str] = None) -> Optional[RuleMatch]:
        raise NotImplementedError


class SSHBruteForceRule(BaseRule):
    """Detects high-frequency SSH password attempts targeting few accounts."""

    rule_id = "RULE-SSH-BRUTE-FORCE"
    name = "SSH Authentication Brute Force"
    default_severity = RuleSeverity.HIGH

    def __init__(self, min_failures: int = 5, max_distinct_users: int = 3) -> None:
        self.min_failures = min_failures
        self.max_distinct_users = max_distinct_users

    def evaluate(self, events: List[LogEvent], entity: Optional[str] = None) -> Optional[RuleMatch]:
        failed_events = [
            e for e in events
            if e.event_type in (EventType.SSH_AUTH_FAIL, EventType.SSH_INVALID_USER) or e.status == "failed"
        ]
        
        if len(failed_events) < self.min_failures:
            return None

        users = {e.user for e in failed_events if e.user}
        if len(users) > self.max_distinct_users:
            return None  # Likely password spraying instead

        severity = RuleSeverity.CRITICAL if len(failed_events) >= 20 else RuleSeverity.HIGH
        confidence = min(0.70 + (len(failed_events) * 0.015), 0.99)

        return RuleMatch(
            rule_id=self.rule_id,
            name=self.name,
            severity=severity,
            confidence=round(confidence, 2),
            description=f"Detected {len(failed_events)} failed authentication attempts targeting {len(users) or 1} user(s).",
            entity=entity or (failed_events[0].src_ip if failed_events[0].src_ip else None),
            matched_events_count=len(failed_events),
            details={"failed_count": len(failed_events), "targeted_users": sorted(list(users))},
        )


class PasswordSprayingRule(BaseRule):
    """Detects horizontal authentication spraying across many accounts from one IP."""

    rule_id = "RULE-PASSWORD-SPRAY"
    name = "Horizontal Password Spraying"
    default_severity = RuleSeverity.HIGH

    def __init__(self, min_distinct_users: int = 4, max_per_user_attempts: int = 4) -> None:
        self.min_distinct_users = min_distinct_users
        self.max_per_user_attempts = max_per_user_attempts

    def evaluate(self, events: List[LogEvent], entity: Optional[str] = None) -> Optional[RuleMatch]:
        failed_events = [
            e for e in events
            if e.event_type in (EventType.SSH_AUTH_FAIL, EventType.SSH_INVALID_USER) or e.status == "failed"
        ]

        if not failed_events:
            return None

        user_counts = Counter(e.user for e in failed_events if e.user)
        distinct_users = len(user_counts)

        if distinct_users < self.min_distinct_users:
            return None

        # Check that attempts per user are low (horizontal evasion characteristic)
        max_attempts_single_user = max(user_counts.values()) if user_counts else 0
        if max_attempts_single_user > self.max_per_user_attempts and distinct_users < 8:
            return None

        severity = RuleSeverity.CRITICAL if distinct_users >= 15 else RuleSeverity.HIGH
        confidence = min(0.75 + (distinct_users * 0.015), 0.99)

        return RuleMatch(
            rule_id=self.rule_id,
            name=self.name,
            severity=severity,
            confidence=round(confidence, 2),
            description=f"Detected password spraying targeting {distinct_users} distinct user accounts with low per-account frequency.",
            entity=entity or (failed_events[0].src_ip if failed_events[0].src_ip else None),
            matched_events_count=len(failed_events),
            details={
                "distinct_users_count": distinct_users,
                "sample_users": list(user_counts.keys())[:10],
                "total_failed_attempts": len(failed_events),
            },
        )


class DataExfiltrationRule(BaseRule):
    """Detects massive outbound data transfer or high asymmetric byte ratios."""

    rule_id = "RULE-DATA-EXFILTRATION"
    name = "Data Exfiltration Anomaly"
    default_severity = RuleSeverity.HIGH

    def __init__(self, min_bytes_sent: int = 5_000_000, min_bytes_ratio: float = 8.0) -> None:
        self.min_bytes_sent = min_bytes_sent
        self.min_bytes_ratio = min_bytes_ratio

    def evaluate(self, events: List[LogEvent], entity: Optional[str] = None) -> Optional[RuleMatch]:
        total_sent = sum(e.bytes_sent for e in events)
        total_recv = sum(e.bytes_recv for e in events)

        if total_sent < self.min_bytes_sent:
            return None

        ratio = (total_sent + 1.0) / (total_recv + 1.0)
        if ratio < self.min_bytes_ratio:
            return None

        severity = RuleSeverity.CRITICAL if total_sent >= 50_000_000 else RuleSeverity.HIGH
        confidence = min(0.80 + (total_sent / 100_000_000.0) * 0.15, 0.98)

        return RuleMatch(
            rule_id=self.rule_id,
            name=self.name,
            severity=severity,
            confidence=round(confidence, 2),
            description=f"High outbound transfer detected: {total_sent / 1_000_000:.2f} MB sent with asymmetric byte ratio {ratio:.1f}.",
            entity=entity or (events[0].src_ip if events and events[0].src_ip else None),
            matched_events_count=len(events),
            details={
                "bytes_sent_mb": round(total_sent / 1_000_000.0, 2),
                "bytes_recv_mb": round(total_recv / 1_000_000.0, 2),
                "bytes_ratio": round(ratio, 2),
            },
        )


class PrivilegeEscalationRule(BaseRule):
    """Detects sudo authentication failures or rapid privilege escalation attempts."""

    rule_id = "RULE-PRIVILEGE-ESCALATION"
    name = "Privilege Escalation Attempt"
    default_severity = RuleSeverity.MEDIUM

    def __init__(self, min_sudo_fails: int = 2) -> None:
        self.min_sudo_fails = min_sudo_fails

    def evaluate(self, events: List[LogEvent], entity: Optional[str] = None) -> Optional[RuleMatch]:
        sudo_fails = [e for e in events if e.event_type == EventType.SUDO_AUTH_FAIL]
        sudo_cmds = [e for e in events if e.event_type == EventType.SUDO_COMMAND]

        if len(sudo_fails) >= self.min_sudo_fails or (len(sudo_fails) >= 1 and len(sudo_cmds) >= 3):
            severity = RuleSeverity.HIGH if len(sudo_fails) >= 3 else RuleSeverity.MEDIUM
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                severity=severity,
                confidence=0.85,
                description=f"Detected {len(sudo_fails)} sudo authentication failures.",
                entity=entity or (sudo_fails[0].user if sudo_fails and sudo_fails[0].user else None),
                matched_events_count=len(sudo_fails) + len(sudo_cmds),
                details={
                    "sudo_failures": len(sudo_fails),
                    "sudo_commands": len(sudo_cmds),
                },
            )
        return None


class PortScanRule(BaseRule):
    """Detects rapid connection attempts across many destination ports."""

    rule_id = "RULE-PORT-SCAN"
    name = "Network Port Reconnaissance"
    default_severity = RuleSeverity.MEDIUM

    def __init__(self, min_unique_ports: int = 8) -> None:
        self.min_unique_ports = min_unique_ports

    def evaluate(self, events: List[LogEvent], entity: Optional[str] = None) -> Optional[RuleMatch]:
        ports = {e.dst_port for e in events if e.dst_port is not None}
        if len(ports) >= self.min_unique_ports:
            return RuleMatch(
                rule_id=self.rule_id,
                name=self.name,
                severity=RuleSeverity.MEDIUM,
                confidence=0.80,
                description=f"Detected connection attempts across {len(ports)} unique destination ports.",
                entity=entity or (events[0].src_ip if events and events[0].src_ip else None),
                matched_events_count=len(events),
                details={"unique_ports_count": len(ports), "ports": sorted(list(ports))[:20]},
            )
        return None


class HeuristicRuleEngine:
    """Composite heuristic evaluation engine for correlation and explainability."""

    def __init__(self, rules: Optional[List[BaseRule]] = None) -> None:
        self.rules: List[BaseRule] = rules or [
            SSHBruteForceRule(),
            PasswordSprayingRule(),
            DataExfiltrationRule(),
            PrivilegeEscalationRule(),
            PortScanRule(),
        ]

    def evaluate_events(self, events: List[LogEvent], entity: Optional[str] = None) -> List[RuleMatch]:
        """Run all registered heuristic rules over a collection of events."""
        matches: List[RuleMatch] = []
        for rule in self.rules:
            match = rule.evaluate(events, entity=entity)
            if match:
                matches.append(match)
        return matches
