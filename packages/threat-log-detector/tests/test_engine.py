"""Unit tests for IntrusionEngine ML detection and safe serialization."""

import json
from pathlib import Path
import numpy as np
import pytest

from detector.engine import EngineConfig, IntrusionEngine, ModelArtifact
from detector.features import FEATURE_NAMES, FeatureExtractor, FeatureVector, group_by_sliding_window
from detector.synthetic import DatasetConfig, SyntheticLogGenerator


@pytest.fixture
def sample_feature_matrix() -> tuple[np.ndarray, list[str]]:
    np.random.seed(42)
    # 50 normal samples
    X_normal = np.random.normal(loc=1.0, scale=0.5, size=(50, len(FEATURE_NAMES)))
    return X_normal, list(FEATURE_NAMES)


def test_engine_fit_validation_errors() -> None:
    engine = IntrusionEngine()
    # 1D array
    with pytest.raises(ValueError, match="Expected 2D array"):
        engine.fit(np.array([1.0, 2.0, 3.0]))

    # < 5 samples
    with pytest.raises(ValueError, match="Need at least 5 samples"):
        engine.fit(np.ones((4, len(FEATURE_NAMES))))


def test_engine_predict_before_fit_raises() -> None:
    engine = IntrusionEngine()
    with pytest.raises(RuntimeError, match="must be fitted"):
        engine.predict_scores(np.ones((1, len(FEATURE_NAMES))))


def test_engine_fit_and_detect_structure(sample_feature_matrix: tuple[np.ndarray, list[str]]) -> None:
    X, feat_names = sample_feature_matrix
    engine = IntrusionEngine(config=EngineConfig(n_estimators=10, max_samples=32))
    engine.fit(X, feature_names=feat_names)

    assert engine.is_fitted is True

    # Test single vector detection
    res = engine.detect(X[0])
    assert 0.0 <= res.anomaly_score <= 1.0
    assert 0.0 <= res.iso_score <= 1.0
    assert 0.0 <= res.z_score <= 1.0
    assert isinstance(res.is_anomaly, bool)
    assert len(res.feature_contributions) == len(FEATURE_NAMES)


def test_engine_safe_serialization_json_roundtrip(tmp_path: Path, sample_feature_matrix: tuple[np.ndarray, list[str]]) -> None:
    X, feat_names = sample_feature_matrix
    engine = IntrusionEngine(config=EngineConfig(n_estimators=10, max_samples=32, anomaly_threshold=0.75))
    engine.fit(X, feature_names=feat_names)

    model_file = tmp_path / "model.json"
    engine.save_json(model_file)
    assert model_file.exists()

    # Verify model is pure JSON (CWE-502 safe)
    with open(model_file, "r", encoding="utf-8") as f:
        raw_json = json.load(f)
    assert "version" in raw_json
    assert "trees" in raw_json
    assert "cov_inv" in raw_json

    # Deserialization from JSON
    loaded_engine = IntrusionEngine.load_json(model_file)
    assert loaded_engine.is_fitted is True
    assert loaded_engine.feature_names == feat_names

    # Verify exact prediction match
    orig_hybrid, orig_iso, orig_mdist, orig_z = engine.predict_scores(X[:5])
    load_hybrid, load_iso, load_mdist, load_z = loaded_engine.predict_scores(X[:5])

    np.testing.assert_allclose(orig_hybrid, load_hybrid, atol=1e-5)
    np.testing.assert_allclose(orig_iso, load_iso, atol=1e-5)
    np.testing.assert_allclose(orig_mdist, load_mdist, atol=1e-5)
    np.testing.assert_allclose(orig_z, load_z, atol=1e-5)


def test_engine_load_non_existent_or_corrupted(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        IntrusionEngine.load_json(tmp_path / "does_not_exist.json")

    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("invalid json content", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to safely deserialize"):
        IntrusionEngine.load_json(corrupt_file)


def test_engine_evaluation_metrics_and_f1_gate() -> None:
    # Synthesize dataset and test F1 >= 0.95
    gen = SyntheticLogGenerator(DatasetConfig(
        n_normal_events=3000,
        n_brute_force_events=400,
        n_password_spray_events=250,
        n_exfiltration_events=150,
        random_seed=42,
    ))
    dataset = gen.generate()
    extractor = FeatureExtractor(window_seconds=60.0)
    windows = group_by_sliding_window(
        dataset.events, window_seconds=60.0, step_seconds=15.0, group_by_entity=True
    )

    y_true = []
    raw_windows = []
    for entity, win_events in windows:
        is_anom = any(e.is_anomaly for e in win_events)
        y_true.append(1 if is_anom else 0)
        raw_windows.append(win_events)

    X, feat_names = extractor.extract_matrix(raw_windows)
    y_arr = np.array(y_true, dtype=int)

    X_train = X[y_arr == 0]
    engine = IntrusionEngine(config=EngineConfig(
        n_estimators=15,
        max_samples=128,
        contamination=0.01,
        anomaly_threshold=0.75,
        random_state=42,
    ))
    engine.fit(X_train, feature_names=feat_names)

    metrics = engine.evaluate(X, y_arr)
    assert metrics["f1_score"] >= 0.95
    assert metrics["precision"] >= 0.90
    assert metrics["recall"] >= 0.95
    assert metrics["accuracy"] >= 0.99
