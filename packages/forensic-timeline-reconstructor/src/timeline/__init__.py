"""Forensic Timeline Reconstructor.

Enterprise-grade IR forensic correlation engine for canonical UTC timeline reconstruction
and timestomping detection.
"""

from timeline.normalizer import ForensicEvent, normalize_to_utc, normalize_severity
from timeline.correlator import TimelineCorrelator, correlate_streams
from timeline.integrity import IntegrityAnalyzer, IntegrityAnomaly, AnomalyType, AnomalySeverity

__version__ = "0.1.0"
__all__ = [
    "ForensicEvent",
    "normalize_to_utc",
    "normalize_severity",
    "TimelineCorrelator",
    "correlate_streams",
    "IntegrityAnalyzer",
    "IntegrityAnomaly",
    "AnomalyType",
    "AnomalySeverity",
]
