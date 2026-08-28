"""Feature engineering over time sliding windows for intrusion anomaly detection."""

from __future__ import annotations

import math
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from detector.parser import EventType, LogEvent


FEATURE_NAMES: List[str] = [
    "event_count",
    "events_per_sec",
    "failed_auth_count",
    "failed_auth_ratio",
    "success_auth_count",
    "unique_users_count",
    "unique_ips_count",
    "unique_ports_count",
    "user_to_event_ratio",
    "invalid_user_count",
    "invalid_user_ratio",
    "bytes_sent_total",
    "bytes_recv_total",
    "bytes_sent_rate",
    "bytes_ratio",
    "duration_mean",
    "duration_std",
    "user_entropy",
    "inter_arrival_mean",
    "inter_arrival_cv",
    "sudo_count",
]


class FeatureVector(BaseModel):
    """Extracted numeric feature vector representing a time window."""
    model_config = ConfigDict(frozen=True)

    entity: Optional[str] = None
    window_start: datetime
    window_end: datetime
    event_count: int
    features: List[float]
    feature_names: List[str] = Field(default_factory=lambda: list(FEATURE_NAMES))
    is_anomaly: Optional[bool] = None

    def to_numpy(self) -> np.ndarray:
        """Convert features to float64 numpy array."""
        return np.array(self.features, dtype=np.float64)


class SlidingWindowBuffer:
    """Bounded streaming sliding window buffer mitigating CWE-400."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_events: int = 50000,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._buffer: Deque[LogEvent] = deque()

    def add(self, event: LogEvent) -> None:
        """Append an event and purge expired entries."""
        self._buffer.append(event)
        self._evict_expired(event.timestamp)

    def _evict_expired(self, current_ts: datetime) -> None:
        """Evict items older than window_seconds or exceeding max_events."""
        cutoff = current_ts.timestamp() - self.window_seconds
        while self._buffer and self._buffer[0].timestamp.timestamp() < cutoff:
            self._buffer.popleft()

        # Hard bounded capacity safeguard (CWE-400 Anti-DoS)
        while len(self._buffer) > self.max_events:
            self._buffer.popleft()

    def get_events(self) -> List[LogEvent]:
        """Return list of events currently in the buffer."""
        return list(self._buffer)

    def clear(self) -> None:
        """Clear all buffer events."""
        self._buffer.clear()

    def __len__(self) -> int:
        return len(self._buffer)


class FeatureExtractor:
    """Deterministic feature extractor from event sequences."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = max(window_seconds, 1.0)

    def calculate_shannon_entropy(self, items: List[str]) -> float:
        """Calculate Shannon entropy for categorical sequences."""
        if not items:
            return 0.0
        counts = Counter(items)
        total = len(items)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return float(entropy)

    def extract_vector(
        self,
        events: List[LogEvent],
        entity: Optional[str] = None,
        force_window_start: Optional[datetime] = None,
        force_window_end: Optional[datetime] = None,
    ) -> FeatureVector:
        """Compute the 21-dimensional numeric feature vector for a list of events."""
        if not events:
            now = datetime.now(timezone.utc)
            start_ts = force_window_start or now
            end_ts = force_window_end or now
            return FeatureVector(
                entity=entity,
                window_start=start_ts,
                window_end=end_ts,
                event_count=0,
                features=[0.0] * len(FEATURE_NAMES),
                is_anomaly=False,
            )

        # Sort events deterministically by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp.timestamp())
        start_ts = force_window_start or sorted_events[0].timestamp
        end_ts = force_window_end or sorted_events[-1].timestamp
        
        duration_window = max(end_ts.timestamp() - start_ts.timestamp(), 1.0)
        n_events = len(sorted_events)

        # Counters & stats
        failed_auth_count = 0
        success_auth_count = 0
        invalid_user_count = 0
        sudo_count = 0

        users: List[str] = []
        ips: List[str] = []
        ports: List[int] = []
        bytes_sent_total = 0
        bytes_recv_total = 0
        durations: List[float] = []
        has_anomaly_label = False

        for ev in sorted_events:
            if ev.is_anomaly:
                has_anomaly_label = True

            if ev.event_type in (EventType.SSH_AUTH_FAIL, EventType.SUDO_AUTH_FAIL) or ev.status == "failed":
                failed_auth_count += 1
            elif ev.event_type == EventType.SSH_AUTH_SUCCESS or ev.status == "success":
                success_auth_count += 1

            if ev.event_type == EventType.SSH_INVALID_USER:
                invalid_user_count += 1
                failed_auth_count += 1

            if ev.event_type in (EventType.SUDO_COMMAND, EventType.SUDO_AUTH_FAIL):
                sudo_count += 1

            if ev.user:
                users.append(ev.user)
            if ev.src_ip:
                ips.append(ev.src_ip)
            if ev.dst_ip:
                ips.append(ev.dst_ip)
            if ev.src_port:
                ports.append(ev.src_port)
            if ev.dst_port:
                ports.append(ev.dst_port)

            bytes_sent_total += ev.bytes_sent
            bytes_recv_total += ev.bytes_recv
            durations.append(ev.duration)

        # Feature 1 & 2: event count and rate
        event_count = float(n_events)
        events_per_sec = float(n_events / duration_window)

        # Feature 3 & 4: failed auth
        f_auth_cnt = float(failed_auth_count)
        f_auth_ratio = float(failed_auth_count / max(n_events, 1))

        # Feature 5: success auth
        s_auth_cnt = float(success_auth_count)

        # Feature 6, 7, 8: unique counts
        unique_users = float(len(set(users)))
        unique_ips = float(len(set(ips)))
        unique_ports = float(len(set(ports)))

        # Feature 9: user to event ratio (Password Spraying indicator)
        user_to_event_ratio = float(unique_users / max(n_events, 1))

        # Feature 10 & 11: invalid users
        inv_user_cnt = float(invalid_user_count)
        inv_user_ratio = float(invalid_user_count / max(n_events, 1))

        # Feature 12, 13, 14, 15: bytes and rates (Exfiltration indicators)
        b_sent = float(bytes_sent_total)
        b_recv = float(bytes_recv_total)
        b_sent_rate = float(bytes_sent_total / duration_window)
        b_ratio = float((bytes_sent_total + 1.0) / (bytes_recv_total + 1.0))

        # Feature 16 & 17: duration mean and std
        dur_arr = np.array(durations, dtype=np.float64) if durations else np.array([0.0])
        dur_mean = float(np.mean(dur_arr))
        dur_std = float(np.std(dur_arr)) if len(dur_arr) > 1 else 0.0

        # Feature 18: user entropy
        user_entropy = self.calculate_shannon_entropy(users)

        # Feature 19 & 20: inter-arrival mean and CV (automation/burst index)
        if n_events > 1:
            timestamps = [e.timestamp.timestamp() for e in sorted_events]
            diffs = np.diff(timestamps)
            diffs = np.maximum(diffs, 0.0)
            ia_mean = float(np.mean(diffs))
            ia_std = float(np.std(diffs))
            ia_cv = float(ia_std / (ia_mean + 1e-6))
        else:
            ia_mean = 0.0
            ia_cv = 0.0

        # Feature 21: sudo count
        sudo_cnt = float(sudo_count)

        feature_values = [
            event_count,
            events_per_sec,
            f_auth_cnt,
            f_auth_ratio,
            s_auth_cnt,
            unique_users,
            unique_ips,
            unique_ports,
            user_to_event_ratio,
            inv_user_cnt,
            inv_user_ratio,
            b_sent,
            b_recv,
            b_sent_rate,
            b_ratio,
            dur_mean,
            dur_std,
            user_entropy,
            ia_mean,
            ia_cv,
            sudo_cnt,
        ]

        # Ensure no NaNs or Infs
        clean_features = [0.0 if (math.isnan(v) or math.isinf(v)) else float(v) for v in feature_values]

        return FeatureVector(
            entity=entity,
            window_start=start_ts,
            window_end=end_ts,
            event_count=n_events,
            features=clean_features,
            is_anomaly=has_anomaly_label,
        )

    def extract_matrix(self, windows: List[List[LogEvent]], entities: Optional[List[Optional[str]]] = None) -> Tuple[np.ndarray, List[str]]:
        """Extract a 2D float64 numpy feature matrix for multiple windows."""
        vectors = []
        for i, win in enumerate(windows):
            ent = entities[i] if (entities and i < len(entities)) else None
            vec = self.extract_vector(win, entity=ent)
            vectors.append(vec.features)

        if not vectors:
            return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64), list(FEATURE_NAMES)

        matrix = np.array(vectors, dtype=np.float64)
        matrix = np.nan_to_num(matrix, nan=0.0, posinf=1e9, neginf=-1e9)
        return matrix, list(FEATURE_NAMES)


def group_by_sliding_window(
    events: List[LogEvent],
    window_seconds: float = 60.0,
    step_seconds: float = 30.0,
    group_by_entity: bool = True,
) -> List[Tuple[Optional[str], List[LogEvent]]]:
    """Slice a chronological event list into time-stepped sliding windows."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp.timestamp())
    min_ts = sorted_events[0].timestamp.timestamp()
    max_ts = sorted_events[-1].timestamp.timestamp()

    windows: List[Tuple[Optional[str], List[LogEvent]]] = []
    curr_start = min_ts

    while curr_start <= max_ts:
        curr_end = curr_start + window_seconds
        
        # Filter events in [curr_start, curr_end]
        win_events = [
            e for e in sorted_events
            if curr_start <= e.timestamp.timestamp() <= curr_end
        ]

        if win_events:
            if group_by_entity:
                # Group by src_ip or user if present
                entity_map: Dict[str, List[LogEvent]] = {}
                for ev in win_events:
                    ent = ev.src_ip or ev.user or "global"
                    entity_map.setdefault(ent, []).append(ev)

                for ent, ent_events in entity_map.items():
                    windows.append((ent, ent_events))
            else:
                windows.append((None, win_events))

        curr_start += max(step_seconds, 1.0)

    return windows
