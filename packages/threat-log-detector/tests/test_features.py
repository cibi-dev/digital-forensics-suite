"""Unit tests for FeatureExtractor and SlidingWindowBuffer."""

import math
from datetime import datetime, timedelta, timezone
import numpy as np
import pytest

from detector.features import (
    FEATURE_NAMES,
    FeatureExtractor,
    FeatureVector,
    SlidingWindowBuffer,
    group_by_sliding_window,
)
from detector.parser import EventType, LogEvent, SourceType


@pytest.fixture
def sample_events() -> list[LogEvent]:
    base_ts = datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    # 5 failed attempts from same IP
    for i in range(5):
        events.append(LogEvent(
            timestamp=base_ts + timedelta(seconds=i * 2),
            source_type=SourceType.AUTH_LOG,
            event_type=EventType.SSH_AUTH_FAIL,
            src_ip="198.51.100.42",
            src_port=50000 + i,
            user="root",
            status="failed",
            bytes_sent=0,
            bytes_recv=0,
            duration=0.1,
        ))
    return events


def test_sliding_window_buffer_add_and_evict() -> None:
    buf = SlidingWindowBuffer(window_seconds=10.0, max_events=100)
    base_ts = datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)

    # Add 3 events in first 5 seconds
    buf.add(LogEvent(timestamp=base_ts, source_type=SourceType.GENERIC, event_type=EventType.GENERIC_EVENT))
    buf.add(LogEvent(timestamp=base_ts + timedelta(seconds=3), source_type=SourceType.GENERIC, event_type=EventType.GENERIC_EVENT))
    buf.add(LogEvent(timestamp=base_ts + timedelta(seconds=5), source_type=SourceType.GENERIC, event_type=EventType.GENERIC_EVENT))
    assert len(buf) == 3

    # Add event at 15 seconds -> events at 0s and 3s should be evicted (15 - 10 = 5)
    buf.add(LogEvent(timestamp=base_ts + timedelta(seconds=15), source_type=SourceType.GENERIC, event_type=EventType.GENERIC_EVENT))
    events = buf.get_events()
    assert len(events) == 2  # Events at 5s and 15s
    assert events[0].timestamp == base_ts + timedelta(seconds=5)


def test_sliding_window_buffer_capacity_limit_dos_guard() -> None:
    buf = SlidingWindowBuffer(window_seconds=1000.0, max_events=5)
    base_ts = datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(20):
        buf.add(LogEvent(timestamp=base_ts + timedelta(seconds=i), source_type=SourceType.GENERIC, event_type=EventType.GENERIC_EVENT))

    assert len(buf) == 5
    buf.clear()
    assert len(buf) == 0


def test_shannon_entropy_calculation() -> None:
    extractor = FeatureExtractor()
    # Empty sequence
    assert extractor.calculate_shannon_entropy([]) == 0.0

    # Homogeneous sequence (all same user) -> 0 entropy
    assert extractor.calculate_shannon_entropy(["root", "root", "root"]) == 0.0

    # Binary uniform sequence (2 users equal count) -> log2(2) = 1.0 bit
    assert math.isclose(extractor.calculate_shannon_entropy(["userA", "userB"]), 1.0, rel_tol=1e-5)

    # 4 distinct users equally distributed -> log2(4) = 2.0 bits
    assert math.isclose(extractor.calculate_shannon_entropy(["u1", "u2", "u3", "u4"]), 2.0, rel_tol=1e-5)


def test_extract_vector_empty_events() -> None:
    extractor = FeatureExtractor()
    vec = extractor.extract_vector([], entity="192.168.1.1")
    assert vec.entity == "192.168.1.1"
    assert vec.event_count == 0
    assert len(vec.features) == len(FEATURE_NAMES)
    assert all(f == 0.0 for f in vec.features)
    assert isinstance(vec.to_numpy(), np.ndarray)


def test_extract_vector_deterministic_computations(sample_events: list[LogEvent]) -> None:
    extractor = FeatureExtractor(window_seconds=60.0)
    vec = extractor.extract_vector(sample_events, entity="198.51.100.42")

    assert vec.event_count == 5
    assert vec.entity == "198.51.100.42"
    
    # Feature 0: event_count
    assert vec.features[0] == 5.0
    # Feature 2: failed_auth_count
    assert vec.features[2] == 5.0
    # Feature 3: failed_auth_ratio
    assert vec.features[3] == 1.0
    # Feature 5: unique_users_count
    assert vec.features[5] == 1.0
    # Feature 6: unique_ips_count
    assert vec.features[6] == 1.0
    # Feature 7: unique_ports_count
    assert vec.features[7] == 5.0
    # Feature 17: user_entropy
    assert vec.features[17] == 0.0

    # Verify zero NaNs or Infs
    arr = vec.to_numpy()
    assert not np.isnan(arr).any()
    assert not np.isinf(arr).any()


def test_extract_matrix_multiple_windows(sample_events: list[LogEvent]) -> None:
    extractor = FeatureExtractor(window_seconds=60.0)
    windows = [sample_events, sample_events[:2], []]
    matrix, names = extractor.extract_matrix(windows)

    assert matrix.shape == (3, len(FEATURE_NAMES))
    assert names == FEATURE_NAMES
    assert matrix[0, 0] == 5.0
    assert matrix[1, 0] == 2.0
    assert matrix[2, 0] == 0.0


def test_extract_matrix_empty_list() -> None:
    extractor = FeatureExtractor()
    matrix, names = extractor.extract_matrix([])
    assert matrix.shape == (0, len(FEATURE_NAMES))
    assert names == FEATURE_NAMES


def test_group_by_sliding_window() -> None:
    base_ts = datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        LogEvent(timestamp=base_ts + timedelta(seconds=0), source_type=SourceType.AUTH_LOG, event_type=EventType.SSH_AUTH_FAIL, src_ip="1.1.1.1"),
        LogEvent(timestamp=base_ts + timedelta(seconds=10), source_type=SourceType.AUTH_LOG, event_type=EventType.SSH_AUTH_FAIL, src_ip="1.1.1.1"),
        LogEvent(timestamp=base_ts + timedelta(seconds=40), source_type=SourceType.AUTH_LOG, event_type=EventType.SSH_AUTH_SUCCESS, src_ip="2.2.2.2"),
        LogEvent(timestamp=base_ts + timedelta(seconds=70), source_type=SourceType.AUTH_LOG, event_type=EventType.SSH_AUTH_SUCCESS, src_ip="2.2.2.2"),
    ]

    windows = group_by_sliding_window(events, window_seconds=60.0, step_seconds=30.0, group_by_entity=True)
    assert len(windows) > 0
    entities = {w[0] for w in windows}
    assert "1.1.1.1" in entities or "2.2.2.2" in entities

    # Test empty event grouping
    assert group_by_sliding_window([]) == []
