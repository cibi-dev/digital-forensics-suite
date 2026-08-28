"""Threat Log Detector: Enterprise Unsupervised Intrusion Detection Engine."""

from detector.alerting import (
    AlertGenerator,
    AlertSeverity,
    ThreatAlert,
    sanitize_dict,
    sanitize_text,
)
from detector.engine import (
    AnomalyScoreResult,
    EngineConfig,
    IntrusionEngine,
    ModelArtifact,
)
from detector.features import (
    FEATURE_NAMES,
    FeatureExtractor,
    FeatureVector,
    SlidingWindowBuffer,
    group_by_sliding_window,
)
from detector.parser import (
    EventType,
    LogEvent,
    LogParser,
    SourceType,
)
from detector.rules import (
    DataExfiltrationRule,
    HeuristicRuleEngine,
    PasswordSprayingRule,
    PortScanRule,
    PrivilegeEscalationRule,
    RuleMatch,
    RuleSeverity,
    SSHBruteForceRule,
)
from detector.synthetic import (
    DatasetConfig,
    SyntheticDataset,
    SyntheticLogGenerator,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SourceType",
    "EventType",
    "LogEvent",
    "LogParser",
    "FEATURE_NAMES",
    "FeatureVector",
    "SlidingWindowBuffer",
    "FeatureExtractor",
    "group_by_sliding_window",
    "EngineConfig",
    "AnomalyScoreResult",
    "ModelArtifact",
    "IntrusionEngine",
    "RuleSeverity",
    "RuleMatch",
    "SSHBruteForceRule",
    "PasswordSprayingRule",
    "DataExfiltrationRule",
    "PrivilegeEscalationRule",
    "PortScanRule",
    "HeuristicRuleEngine",
    "AlertSeverity",
    "ThreatAlert",
    "sanitize_text",
    "sanitize_dict",
    "AlertGenerator",
    "DatasetConfig",
    "SyntheticDataset",
    "SyntheticLogGenerator",
]
