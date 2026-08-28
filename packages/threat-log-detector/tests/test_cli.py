"""Unit tests for CLI commands."""

import json
from pathlib import Path
import pytest

from detector.cli import main
from detector.synthetic import DatasetConfig, SyntheticLogGenerator


@pytest.fixture
def synthetic_bundle(tmp_path: Path) -> dict[str, str]:
    config = DatasetConfig(
        n_normal_events=100,
        n_brute_force_events=20,
        n_password_spray_events=10,
        n_exfiltration_events=10,
        random_seed=42,
    )
    gen = SyntheticLogGenerator(config=config)
    ds = gen.generate()
    return ds.to_file_bundle(tmp_path / "data")


def test_cli_train_command(tmp_path: Path, synthetic_bundle: dict[str, str]) -> None:
    model_out = tmp_path / "trained_model.json"
    rc = main([
        "train",
        "--data", synthetic_bundle["logs"],
        "--model-out", str(model_out),
        "--n-estimators", "10",
        "--window-seconds", "30.0",
        "--step-seconds", "15.0",
    ])
    assert rc == 0
    assert model_out.exists()


def test_cli_detect_command(tmp_path: Path, synthetic_bundle: dict[str, str]) -> None:
    model_out = tmp_path / "trained_model.json"
    # First train
    main([
        "train",
        "--data", synthetic_bundle["logs"],
        "--model-out", str(model_out),
        "--n-estimators", "10",
        "--window-seconds", "30.0",
        "--step-seconds", "15.0",
    ])

    alerts_out = tmp_path / "alerts.json"
    rc = main([
        "detect",
        "--data", synthetic_bundle["logs"],
        "--model", str(model_out),
        "--output", str(alerts_out),
        "--window-seconds", "30.0",
        "--step-seconds", "15.0",
    ])
    assert rc == 0
    assert alerts_out.exists()
    alerts_data = json.loads(alerts_out.read_text(encoding="utf-8"))
    assert isinstance(alerts_data, list)


def test_cli_evaluate_command(tmp_path: Path, synthetic_bundle: dict[str, str]) -> None:
    model_out = tmp_path / "trained_model.json"
    main([
        "train",
        "--data", synthetic_bundle["logs"],
        "--model-out", str(model_out),
        "--n-estimators", "10",
        "--window-seconds", "30.0",
        "--step-seconds", "15.0",
    ])

    rc = main([
        "evaluate",
        "--test-data", synthetic_bundle["logs"],
        "--model", str(model_out),
        "--ground-truth", synthetic_bundle["ground_truth"],
        "--window-seconds", "30.0",
        "--step-seconds", "15.0",
    ])
    assert rc == 0


def test_cli_benchmark_command(tmp_path: Path) -> None:
    out_json = tmp_path / "bench.json"
    rc = main([
        "benchmark",
        "--n-events", "200",
        "--batch-size", "100",
        "--output", str(out_json),
    ])
    assert rc == 0
    assert out_json.exists()


def test_cli_errors_on_missing_files(tmp_path: Path) -> None:
    # Missing training data
    rc = main(["train", "--data", str(tmp_path / "non_existent.log")])
    assert rc == 1

    # Missing model in detect
    rc = main(["detect", "--data", str(tmp_path / "any.log"), "--model", str(tmp_path / "non_existent.json")])
    assert rc == 1
