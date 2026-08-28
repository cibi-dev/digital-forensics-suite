"""Alert generation engine with PII/secret sanitization and threat scoring."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from detector.engine import AnomalyScoreResult
from detector.rules import RuleMatch, RuleSeverity


class AlertSeverity(str, Enum):
    """Normalized alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatAlert(BaseModel):
    """Sanitized structured security incident alert."""
    model_config = ConfigDict(frozen=True)

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity
    threat_score: float  # Calibrated [0.0 - 1.0]
    anomaly_score: float
    z_score: float
    entity: str
    rule_matches: List[RuleMatch] = Field(default_factory=list)
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    sanitized: bool = True

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize alert to JSON string."""
        return self.model_dump_json(indent=indent)

    def to_syslog_str(self) -> str:
        """Format as standard SIEM syslog event."""
        rules_str = ",".join(r.rule_id for r in self.rule_matches) or "NONE"
        ts_iso = self.timestamp.isoformat()
        return (
            f"CEF:0|cibi-dev|threat-log-detector|0.1.0|{self.severity.value}|"
            f"{self.summary}|{int(self.threat_score * 10)}|msg={self.summary} "
            f"src={self.entity} cat=intrusion cs1Label=Rules cs1={rules_str} "
            f"cfp1Label=ThreatScore cfp1={self.threat_score:.2f} rt={ts_iso}"
        )


# Sanitization regexes for CWE-209 / Information Exposure
RE_PASSWORDS = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|auth_token)\s*[:=]\s*([^\s;,\"\'&]+)"
)
RE_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{16,}")
RE_PRIVATE_KEYS = re.compile(r"-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----.*?-----END\s+([A-Z\s]+)?PRIVATE\s+KEY-----", re.DOTALL)
RE_GENERIC_API_KEYS = re.compile(r"\b(?:sk_[a-zA-Z0-9_\-]{16,}|gh[a-zA-Z0-9]_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b")

SENSITIVE_KEY_NAMES = {"password", "passwd", "pwd", "secret", "token", "api_key", "auth_token", "private_key"}


def sanitize_text(text: str) -> str:
    """Sanitize secrets, passwords, and sensitive tokens from log text (CWE-209 Safe)."""
    if not text:
        return ""

    sanitized = text

    # Redact private key blocks
    sanitized = RE_PRIVATE_KEYS.sub("[REDACTED_PRIVATE_KEY]", sanitized)

    # Redact Authorization: Bearer tokens
    sanitized = RE_BEARER_TOKEN.sub("Bearer [REDACTED]", sanitized)

    # Redact known API key patterns
    sanitized = RE_GENERIC_API_KEYS.sub("[REDACTED]", sanitized)

    # Redact password / secret key-value assignments
    sanitized = RE_PASSWORDS.sub(r"\1=[REDACTED]", sanitized)

    return sanitized


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize dictionary keys and values."""
    clean: Dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, dict):
            clean[k] = sanitize_dict(v)
        elif isinstance(v, list):
            clean[k] = [
                sanitize_text(item) if isinstance(item, str) else (
                    sanitize_dict(item) if isinstance(item, dict) else item
                )
                for item in v
            ]
        elif any(sk == k.lower() for sk in SENSITIVE_KEY_NAMES):
            clean[k] = "[REDACTED]"
        elif isinstance(v, str):
            clean[k] = sanitize_text(v)
        else:
            clean[k] = v
    return clean


class AlertGenerator:
    """Generates sanitized, deduplicated threat alerts with fused scoring."""

    def __init__(self, cooldown_seconds: float = 300.0) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._last_alert_ts: Dict[str, float] = {}

    def generate_alert(
        self,
        entity: str,
        detection: AnomalyScoreResult,
        rule_matches: Optional[List[RuleMatch]] = None,
        context_details: Optional[Dict[str, Any]] = None,
        force_alert: bool = False,
    ) -> Optional[ThreatAlert]:
        """Generate a structured ThreatAlert if threat score exceeds threshold or rules match."""
        rules = rule_matches or []
        
        # Calculate fused threat score
        max_rule_conf = max([r.confidence for r in rules], default=0.0)
        # Fused threat score balances ML anomaly score and rule confidence
        if rules:
            threat_score = max(detection.anomaly_score, max_rule_conf)
        else:
            threat_score = detection.anomaly_score

        threat_score = round(min(max(threat_score, 0.0), 1.0), 4)

        # Check if an alert should be triggered
        has_critical_rule = any(r.severity in (RuleSeverity.HIGH, RuleSeverity.CRITICAL) for r in rules)
        is_threat = (detection.is_anomaly or has_critical_rule or threat_score >= 0.50 or force_alert)

        if not is_threat:
            return None

        # Determine alert severity
        if threat_score >= 0.85 or any(r.severity == RuleSeverity.CRITICAL for r in rules):
            severity = AlertSeverity.CRITICAL
        elif threat_score >= 0.70 or any(r.severity == RuleSeverity.HIGH for r in rules):
            severity = AlertSeverity.HIGH
        elif threat_score >= 0.50 or any(r.severity == RuleSeverity.MEDIUM for r in rules):
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        # Cooldown check for deduplication (unless CRITICAL severity)
        now_ts = datetime.now(timezone.utc).timestamp()
        if severity != AlertSeverity.CRITICAL and not force_alert:
            last_ts = self._last_alert_ts.get(entity, 0.0)
            if (now_ts - last_ts) < self.cooldown_seconds:
                return None  # Suppressed by cooldown

        self._last_alert_ts[entity] = now_ts

        # Formulate human-readable summary
        if rules:
            primary_rule = max(rules, key=lambda r: r.confidence)
            summary = f"Security Alert: {primary_rule.name} detected on entity '{entity}' (Threat Score: {threat_score:.2f})"
        else:
            summary = f"Statistical Anomaly Detected on entity '{entity}' (Threat Score: {threat_score:.2f})"

        details = dict(context_details or {})
        details["feature_contributions"] = detection.feature_contributions
        sanitized_details = sanitize_dict(details)

        return ThreatAlert(
            severity=severity,
            threat_score=threat_score,
            anomaly_score=detection.anomaly_score,
            z_score=detection.z_score,
            entity=sanitize_text(entity),
            rule_matches=rules,
            summary=sanitize_text(summary),
            details=sanitized_details,
            sanitized=True,
        )

    def reset_cooldown(self) -> None:
        """Reset deduplication state cache."""
        self._last_alert_ts.clear()
