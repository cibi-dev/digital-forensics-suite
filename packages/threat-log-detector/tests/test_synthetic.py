"""Unit tests for SyntheticLogGenerator."""

from pathlib import Path
import pytest

from detector.synthetic import DatasetConfig, SyntheticLogGenerator


def test_synthetic_generation_reproducibility() -> None:
    config = DatasetConfig(
        n_normal_events=100,
        n_brute_force_events=20,
        n_password_spray_events=15,
        n_exfiltration_events=10,
        random_seed=42,
    )
    gen1 = SyntheticLogGenerator(config=config)
    ds1 = gen1.generate()

    gen2 = SyntheticLogGenerator(config=config)
    ds2 = gen2.generate()

    assert len(ds1.events) == len(ds2.events)
    assert len(ds1.events) == 145
    assert ds1.raw_logs[0] == ds2.raw_logs[0]
    assert ds1.labels == ds2.labels
    assert ds1.attack_types == ds2.attack_types


def test_synthetic_to_file_bundle(tmp_path: Path) -> None:
    config = DatasetConfig(
        n_normal_events=50,
        n_brute_force_events=10,
        n_password_spray_events=5,
        n_exfiltration_events=5,
        random_seed=42,
    )
    gen = SyntheticLogGenerator(config=config)
    ds = gen.generate()

    bundle = ds.to_file_bundle(tmp_path / "dataset")
    log_file = Path(bundle["logs"])
    gt_file = Path(bundle["ground_truth"])

    assert log_file.exists()
    assert gt_file.exists()
    assert len(log_file.read_text(encoding="utf-8").strip().splitlines()) == 70
