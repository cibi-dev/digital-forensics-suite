"""Forensic integrity and timestomping detection engine.

Detects negative clock jumps (clock rollback / timestomping), anomalous deletion gaps,
timestamp overlaps, future timestamps, and burst injection inconsistencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import logging
import os
from typing import Any, Dict, Iterable, Iterator, List, Optional

from pydantic import BaseModel, Field

from timeline.correlator import detect_parser_for_file
from timeline.normalizer import ForensicEvent, normalize_to_utc

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Categorization of timeline integrity anomalies."""

    NEGATIVE_CLOCK_JUMP = "NEGATIVE_CLOCK_JUMP"
    ANOMALOUS_GAP = "ANOMALOUS_GAP"
    TIMESTAMP_OVERLAP = "TIMESTAMP_OVERLAP"
    FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"
    BURST_INCONSISTENCY = "BURST_INCONSISTENCY"


class AnomalySeverity(str, Enum):
    """Severity ratings for forensic anomalies."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IntegrityAnomaly(BaseModel):
    """Canonical model representing a detected forensic integrity violation."""

    model_config = {"extra": "forbid"}

    anomaly_id: str = ""
    anomaly_type: str
    severity: str
    source_file: str
    start_line: int
    end_line: int
    start_time: datetime
    end_time: datetime
    delta_seconds: float
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.anomaly_id:
            raw = f"{self.anomaly_type}:{self.source_file}:{self.start_line}:{self.end_line}:{self.start_time.isoformat()}"
            self.anomaly_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        """Convert anomaly to dictionary with ISO formatted timestamps."""
        data = self.model_dump()
        data["start_time"] = self.start_time.isoformat()
        data["end_time"] = self.end_time.isoformat()
        return data


class IntegrityAnalyzer:
    """Deterministic detector of timestomping and chronological tampering."""

    def __init__(
        self,
        max_allowed_gap_seconds: float = 3600.0,
        burst_threshold_events_per_sec: int = 200,
        future_skew_tolerance_seconds: float = 120.0,
        reference_now: Optional[datetime] = None,
    ) -> None:
        self.max_allowed_gap_seconds = max_allowed_gap_seconds
        self.burst_threshold_events_per_sec = burst_threshold_events_per_sec
        self.future_skew_tolerance_seconds = future_skew_tolerance_seconds
        self.reference_now = (
            normalize_to_utc(reference_now)
            if reference_now is not None
            else datetime.now(timezone.utc)
        )

    def analyze_stream(self, events: Iterable[ForensicEvent]) -> Iterator[IntegrityAnomaly]:
        """Streamingly inspect events within a single log source to detect timeline anomalies."""
        prev_evt: Optional[ForensicEvent] = None
        burst_counter = 0
        burst_current_second: Optional[int] = None
        burst_start_evt: Optional[ForensicEvent] = None

        for evt in events:
            # 1. Future timestamp check
            if self.reference_now:
                time_diff = (evt.timestamp - self.reference_now).total_seconds()
                if time_diff > self.future_skew_tolerance_seconds:
                    yield IntegrityAnomaly(
                        anomaly_type=AnomalyType.FUTURE_TIMESTAMP.value,
                        severity=AnomalySeverity.HIGH.value,
                        source_file=evt.source_file,
                        start_line=evt.line_number,
                        end_line=evt.line_number,
                        start_time=self.reference_now,
                        end_time=evt.timestamp,
                        delta_seconds=round(time_diff, 6),
                        description=(
                            f"Event at line {evt.line_number} has future timestamp {evt.timestamp.isoformat()} "
                            f"(+{round(time_diff, 2)}s relative to reference time)"
                        ),
                        evidence={"raw_log": evt.raw_log, "reference_now": self.reference_now.isoformat()},
                    )

            if prev_evt is not None and prev_evt.source_file == evt.source_file:
                delta_sec = (evt.timestamp - prev_evt.timestamp).total_seconds()

                # 2. Negative Clock Jump / Timestomping (t_{i+1} < t_i)
                if delta_sec < 0:
                    yield IntegrityAnomaly(
                        anomaly_type=AnomalyType.NEGATIVE_CLOCK_JUMP.value,
                        severity=AnomalySeverity.CRITICAL.value,
                        source_file=evt.source_file,
                        start_line=prev_evt.line_number,
                        end_line=evt.line_number,
                        start_time=prev_evt.timestamp,
                        end_time=evt.timestamp,
                        delta_seconds=round(delta_sec, 6),
                        description=(
                            f"Negative clock jump (timestomping) detected between line {prev_evt.line_number} "
                            f"({prev_evt.timestamp.isoformat()}) and line {evt.line_number} "
                            f"({evt.timestamp.isoformat()}): {round(delta_sec, 3)} seconds"
                        ),
                        evidence={
                            "prev_log": prev_evt.raw_log,
                            "current_log": evt.raw_log,
                            "jump_magnitude_seconds": abs(delta_sec),
                        },
                    )

                # 3. Anomalous Deletion Gap
                elif delta_sec > self.max_allowed_gap_seconds:
                    yield IntegrityAnomaly(
                        anomaly_type=AnomalyType.ANOMALOUS_GAP.value,
                        severity=AnomalySeverity.MEDIUM.value,
                        source_file=evt.source_file,
                        start_line=prev_evt.line_number,
                        end_line=evt.line_number,
                        start_time=prev_evt.timestamp,
                        end_time=evt.timestamp,
                        delta_seconds=round(delta_sec, 6),
                        description=(
                            f"Anomalous inactivity / deletion gap detected between line {prev_evt.line_number} "
                            f"and line {evt.line_number}: {round(delta_sec, 1)} seconds "
                            f"(threshold: {self.max_allowed_gap_seconds}s)"
                        ),
                        evidence={
                            "prev_timestamp": prev_evt.timestamp.isoformat(),
                            "next_timestamp": evt.timestamp.isoformat(),
                            "gap_seconds": delta_sec,
                        },
                    )

                # 4. Burst / High-frequency Injection detection
                evt_sec = int(evt.timestamp.timestamp())
                if burst_current_second == evt_sec:
                    burst_counter += 1
                else:
                    if burst_counter > self.burst_threshold_events_per_sec and burst_start_evt is not None:
                        yield IntegrityAnomaly(
                            anomaly_type=AnomalyType.BURST_INCONSISTENCY.value,
                            severity=AnomalySeverity.LOW.value,
                            source_file=burst_start_evt.source_file,
                            start_line=burst_start_evt.line_number,
                            end_line=prev_evt.line_number,
                            start_time=burst_start_evt.timestamp,
                            end_time=prev_evt.timestamp,
                            delta_seconds=0.0,
                            description=(
                                f"High-frequency log burst ({burst_counter} events in 1 second) "
                                f"detected between lines {burst_start_evt.line_number}-{prev_evt.line_number}"
                            ),
                            evidence={"burst_rate": burst_counter, "threshold": self.burst_threshold_events_per_sec},
                        )
                    burst_current_second = evt_sec
                    burst_counter = 1
                    burst_start_evt = evt

            else:
                burst_current_second = int(evt.timestamp.timestamp())
                burst_counter = 1
                burst_start_evt = evt

            prev_evt = evt

        # Final burst check at stream termination
        if burst_counter > self.burst_threshold_events_per_sec and burst_start_evt is not None and prev_evt is not None:
            yield IntegrityAnomaly(
                anomaly_type=AnomalyType.BURST_INCONSISTENCY.value,
                severity=AnomalySeverity.LOW.value,
                source_file=burst_start_evt.source_file,
                start_line=burst_start_evt.line_number,
                end_line=prev_evt.line_number,
                start_time=burst_start_evt.timestamp,
                end_time=prev_evt.timestamp,
                delta_seconds=0.0,
                description=(
                    f"High-frequency log burst ({burst_counter} events in 1 second) "
                    f"detected between lines {burst_start_evt.line_number}-{prev_evt.line_number}"
                ),
                evidence={"burst_rate": burst_counter, "threshold": self.burst_threshold_events_per_sec},
            )

    def analyze_file(self, filepath: str) -> list[IntegrityAnomaly]:
        """Analyze a single log file and return all detected integrity anomalies."""
        parser = detect_parser_for_file(filepath)
        events = parser.parse_file(filepath)
        return list(self.analyze_stream(events))

    def analyze_multi_file(self, filepaths: list[str]) -> list[IntegrityAnomaly]:
        """Analyze multiple log files independently and aggregate all anomalies."""
        anomalies: list[IntegrityAnomaly] = []
        for fp in filepaths:
            anomalies.extend(self.analyze_file(fp))
        return anomalies

    def generate_integrity_summary(self, anomalies: list[IntegrityAnomaly]) -> dict[str, Any]:
        """Generate executive metrics summary of detected integrity anomalies."""
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        files_affected: set[str] = set()

        for a in anomalies:
            by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1
            by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
            files_affected.add(a.source_file)

        return {
            "total_anomalies": len(anomalies),
            "status": "COMPROMISED" if anomalies else "CLEAN",
            "files_affected_count": len(files_affected),
            "files_affected": sorted(list(files_affected)),
            "by_severity": by_severity,
            "by_type": by_type,
        }
