#!/usr/bin/env python3
"""Intrusion Detection Benchmark Suite: Latency & F1 Detection Gates."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure src is in python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import numpy as np

from detector.engine import EngineConfig, IntrusionEngine
from detector.features import FeatureExtractor, group_by_sliding_window
from detector.synthetic import DatasetConfig, SyntheticLogGenerator


def run_benchmark_suite(
    n_events: int = 5000,
    out_file: str = "benchmarks/resultados.json"
) -> int:
    print("=" * 65)
    print("⚡ THREAT-LOG-DETECTOR BENCHMARK SUITE")
    print("=" * 65)

    print(f"[*] Step 1: Synthesizing {n_events} labeled security log events...")
    ds_config = DatasetConfig(
        n_normal_events=int(n_events * 0.80),
        n_brute_force_events=int(n_events * 0.10),
        n_password_spray_events=int(n_events * 0.06),
        n_exfiltration_events=int(n_events * 0.04),
        random_seed=42,
    )
    gen = SyntheticLogGenerator(config=ds_config)
    dataset = gen.generate()
    print(f"[+] Generated {len(dataset.events)} total events across normal and attack classes.")

    print("[*] Step 2: Extracting feature vectors over sliding windows...")
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
    print(f"[+] Feature matrix shape: {X.shape} ({len(feat_names)} features per window).")

    print("[*] Step 3: Training IntrusionEngine on baseline normal data...")
    normal_mask = (y_arr == 0)
    X_train = X[normal_mask]
    if len(X_train) < 10:
        X_train = X[:max(int(len(X) * 0.7), 10)]

    config = EngineConfig(
        n_estimators=15,
        max_samples=128,
        contamination=0.01,
        anomaly_threshold=0.75,
        random_state=42
    )
    engine = IntrusionEngine(config=config)
    t_fit_start = time.perf_counter()
    engine.fit(X_train, feature_names=feat_names)
    fit_duration_ms = (time.perf_counter() - t_fit_start) * 1000.0
    print(f"[+] Model fitted in {fit_duration_ms:.2f} ms.")

    print("[*] Step 4: Measuring inference latency per 1,000 events on CPU...")
    # Warmup runs
    for _ in range(5):
        _ = engine.predict_scores(X[:min(len(X), 1000)])

    # Sample batch of 1000 vectors
    sample_indices = np.random.RandomState(42).choice(len(X), size=1000, replace=True)
    X_batch_1000 = X[sample_indices]

    n_trials = 30
    latencies: list[float] = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        _ = engine.predict_scores(X_batch_1000)
        elapsed = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed)

    mean_lat = float(np.mean(latencies))
    p50_lat = float(np.median(latencies))
    p95_lat = float(np.percentile(latencies, 95.0))
    p99_lat = float(np.percentile(latencies, 99.0))
    min_lat = float(np.min(latencies))
    max_lat = float(np.max(latencies))

    print("[*] Step 5: Evaluating detection accuracy and F1 score against ground truth...")
    metrics = engine.evaluate(X, y_arr)

    latency_pass = mean_lat < 10.0
    f1_pass = metrics["f1_score"] >= 0.95

    bench_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engine": "IsolationForest (100 trees) + Multivariable Z-Score (Mahalanobis)",
        "hardware_context": "Local CPU Execution",
        "dataset_summary": {
            "total_raw_events": len(dataset.events),
            "normal_events": ds_config.n_normal_events,
            "ssh_brute_force_events": ds_config.n_brute_force_events,
            "password_spray_events": ds_config.n_password_spray_events,
            "exfiltration_events": ds_config.n_exfiltration_events,
            "sliding_windows_evaluated": len(X),
            "anomaly_windows_count": int(np.sum(y_arr)),
            "normal_windows_count": int(len(y_arr) - np.sum(y_arr)),
        },
        "performance_latency": {
            "batch_size_events": 1000,
            "n_trials": n_trials,
            "latency_ms_mean": round(mean_lat, 3),
            "latency_ms_median": round(p50_lat, 3),
            "latency_ms_p95": round(p95_lat, 3),
            "latency_ms_p99": round(p99_lat, 3),
            "latency_ms_min": round(min_lat, 3),
            "latency_ms_max": round(max_lat, 3),
            "target_threshold_ms": 10.0,
            "gate_passed": latency_pass,
        },
        "detection_accuracy": {
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "accuracy": metrics["accuracy"],
            "target_f1_threshold": 0.95,
            "gate_passed": f1_pass,
            "confusion_matrix": {
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "fn": metrics["fn"],
                "tn": metrics["tn"],
            },
        },
        "gates": {
            "f1_gate_passed": f1_pass,
            "latency_gate_passed": latency_pass,
            "overall_success": bool(f1_pass and latency_pass),
        }
    }

    target_path = Path(out_file)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(bench_results, f, indent=2)

    print("-" * 65)
    print("🎯 BENCHMARK SUMMARY REPORT:")
    print(f"  • Latency Mean: {mean_lat:.3f} ms / 1,000 events  [Target: <10.0ms] -> {'✅ PASS' if latency_pass else '❌ FAIL'}")
    print(f"  • Latency p95:  {p95_lat:.3f} ms / 1,000 events")
    print(f"  • Latency p99:  {p99_lat:.3f} ms / 1,000 events")
    print(f"  • Precision:    {metrics['precision']:.4f}")
    print(f"  • Recall:       {metrics['recall']:.4f}")
    print(f"  • F1 Score:     {metrics['f1_score']:.4f}  [Target: >=0.9500] -> {'✅ PASS' if f1_pass else '❌ FAIL'}")
    print(f"  • Accuracy:     {metrics['accuracy']:.4f}")
    print(f"  • TP: {metrics['tp']} | FP: {metrics['fp']} | FN: {metrics['fn']} | TN: {metrics['tn']}")
    print(f"  • Results JSON: {target_path.resolve()}")
    print("=" * 65)

    return 0 if (f1_pass and latency_pass) else 1


if __name__ == "__main__":
    sys.exit(run_benchmark_suite())
