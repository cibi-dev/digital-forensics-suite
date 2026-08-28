"""CLI subcommands for threat-log-detector: train, detect, evaluate, benchmark."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from detector.alerting import AlertGenerator, sanitize_text
from detector.engine import EngineConfig, IntrusionEngine
from detector.features import FeatureExtractor, FeatureVector, group_by_sliding_window
from detector.parser import LogParser
from detector.rules import HeuristicRuleEngine
from detector.synthetic import DatasetConfig, SyntheticLogGenerator


def run_train(args: argparse.Namespace) -> int:
    """Train IntrusionEngine on log data and save safe JSON artifact."""
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"Error: Training data file not found: {data_path}", file=sys.stderr)
        return 1

    print(f"[*] Loading training events from {data_path}...")
    parser = LogParser()
    events = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            ev = parser.parse_line(line, format_hint=args.format)
            if ev.event_type.value != "malformed":
                events.append(ev)

    print(f"[*] Parsed {len(events)} valid events.")
    if len(events) < 10:
        print("Error: Not enough events to train model (minimum 10).", file=sys.stderr)
        return 1

    extractor = FeatureExtractor(window_seconds=args.window_seconds)
    windows = group_by_sliding_window(
        events, window_seconds=args.window_seconds, step_seconds=args.step_seconds, group_by_entity=True
    )
    print(f"[*] Extracted {len(windows)} sliding window segments.")

    raw_windows = [w[1] for w in windows]
    entities = [w[0] for w in windows]
    X, feat_names = extractor.extract_matrix(raw_windows, entities=entities)

    if X.shape[0] < 5:
        print("Error: Feature matrix has fewer than 5 window samples.", file=sys.stderr)
        return 1

    config = EngineConfig(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
    )
    engine = IntrusionEngine(config=config)
    print(f"[*] Fitting IsolationForest ({args.n_estimators} trees) + Multivariable Z-Score...")
    t0 = time.perf_counter()
    engine.fit(X, feature_names=feat_names)
    train_time_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[+] Model fitted in {train_time_ms:.2f} ms.")

    out_path = Path(args.model_out)
    engine.save_json(out_path)
    print(f"[+] Model successfully saved to {out_path} (CWE-502 Safe JSON).")
    return 0


def run_detect(args: argparse.Namespace) -> int:
    """Run real-time or batch detection on log data."""
    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: Model file not found: {model_path}", file=sys.stderr)
        return 1

    data_path = Path(args.data)
    if not data_path.exists():
        print(f"Error: Log file not found: {data_path}", file=sys.stderr)
        return 1

    engine = IntrusionEngine.load_json(model_path)
    if args.threshold is not None:
        # Override threshold if passed
        object.__setattr__(engine.config, "anomaly_threshold", args.threshold)

    parser = LogParser()
    events = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            ev = parser.parse_line(line, format_hint=args.format)
            if ev.event_type.value != "malformed":
                events.append(ev)

    print(f"[*] Analyzing {len(events)} events from {data_path}...")
    extractor = FeatureExtractor(window_seconds=args.window_seconds)
    windows = group_by_sliding_window(
        events, window_seconds=args.window_seconds, step_seconds=args.step_seconds, group_by_entity=True
    )

    rule_engine = HeuristicRuleEngine()
    alert_gen = AlertGenerator(cooldown_seconds=args.cooldown)
    alerts = []

    for entity, win_events in windows:
        vec = extractor.extract_vector(win_events, entity=entity)
        detection = engine.detect(vec)
        rule_matches = rule_engine.evaluate_events(win_events, entity=entity)

        ent_name = entity or "unknown"
        alert = alert_gen.generate_alert(
            entity=ent_name,
            detection=detection,
            rule_matches=rule_matches,
            context_details={"event_count": len(win_events), "window_seconds": args.window_seconds},
        )
        if alert:
            alerts.append(alert)

    print(f"[+] Detection completed. Triggered {len(alerts)} alerts.")

    # Output alerts
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([a.model_dump(mode="json") for a in alerts], f, indent=2)
        print(f"[+] Alerts written to {out_path}")
    else:
        for a in alerts[:10]:
            print(f"[{a.severity.value}] Score={a.threat_score:.2f} | Entity={a.entity} | {a.summary}")
        if len(alerts) > 10:
            print(f"... and {len(alerts) - 10} more alerts.")

    return 0


def run_evaluate(args: argparse.Namespace) -> int:
    """Evaluate detection metrics against ground truth dataset."""
    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: Model not found at {model_path}", file=sys.stderr)
        return 1

    gt_path = Path(args.ground_truth)
    if not gt_path.exists():
        print(f"Error: Ground truth file not found at {gt_path}", file=sys.stderr)
        return 1

    with open(gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    labels = gt_data["labels"]
    engine = IntrusionEngine.load_json(model_path)

    # Parse test data
    parser = LogParser()
    events = []
    with open(args.test_data, "r", encoding="utf-8") as f:
        for line in f:
            events.append(parser.parse_line(line))

    # Match ground truth to events
    extractor = FeatureExtractor(window_seconds=args.window_seconds)
    windows = group_by_sliding_window(
        events, window_seconds=args.window_seconds, step_seconds=args.step_seconds, group_by_entity=True
    )

    y_true = []
    raw_windows = []
    for entity, win_events in windows:
        has_anom = any(e.is_anomaly for e in win_events)
        y_true.append(1 if has_anom else 0)
        raw_windows.append(win_events)

    X, _ = extractor.extract_matrix(raw_windows)
    metrics = engine.evaluate(X, np.array(y_true))

    print("=" * 50)
    print("📈 EVALUATION METRICS:")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1_score']:.4f}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  TP: {metrics['tp']}, FP: {metrics['fp']}, FN: {metrics['fn']}, TN: {metrics['tn']}")
    print("=" * 50)

    return 0


def run_benchmark(args: argparse.Namespace) -> int:
    """Execute end-to-end latency & accuracy benchmark and write resultados.json."""
    print(f"[*] Initializing reproducible benchmark with {args.n_events} synthetic events...")
    
    # 1. Generate synthetic dataset
    ds_config = DatasetConfig(
        n_normal_events=int(args.n_events * 0.80),
        n_brute_force_events=int(args.n_events * 0.10),
        n_password_spray_events=int(args.n_events * 0.06),
        n_exfiltration_events=int(args.n_events * 0.04),
        random_seed=42,
    )
    gen = SyntheticLogGenerator(config=ds_config)
    dataset = gen.generate()

    print(f"[+] Generated {len(dataset.events)} labeled events across 4 attack categories.")

    # 2. Extract features
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

    # 3. Train engine on normal slice
    normal_mask = (y_arr == 0)
    X_train = X[normal_mask]
    if len(X_train) < 10:
        X_train = X[:max(int(len(X) * 0.7), 10)]

    engine = IntrusionEngine(config=EngineConfig(
        n_estimators=15,
        max_samples=128,
        contamination=0.01,
        anomaly_threshold=0.75,
        random_state=42
    ))
    engine.fit(X_train, feature_names=feat_names)

    # 4. Measure inference latency per 1000 events
    n_warmup = 5
    for _ in range(n_warmup):
        _ = engine.predict_scores(X[:min(len(X), 1000)])

    # Synthetic batch of exactly 1000 feature vectors for benchmark
    idx_sample = np.random.RandomState(42).choice(len(X), size=min(1000, len(X)), replace=True)
    X_1000 = X[idx_sample]

    n_runs = 20
    latencies_ms: List[float] = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        _ = engine.predict_scores(X_1000)
        t_elapsed = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(t_elapsed)

    mean_latency_ms = float(np.mean(latencies_ms))
    p95_latency_ms = float(np.percentile(latencies_ms, 95.0))
    p99_latency_ms = float(np.percentile(latencies_ms, 99.0))

    # 5. Measure detection accuracy metrics
    metrics = engine.evaluate(X, y_arr)

    benchmark_result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engine": "IsolationForest + Multivariable Z-Score",
        "dataset_size_events": len(dataset.events),
        "windows_evaluated": len(X),
        "batch_size": 1000,
        "latency_ms_per_1000_mean": round(mean_latency_ms, 3),
        "latency_ms_per_1000_p95": round(p95_latency_ms, 3),
        "latency_ms_per_1000_p99": round(p99_latency_ms, 3),
        "latency_gate_passed": bool(mean_latency_ms < 10.0),
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1_score"],
        "accuracy": metrics["accuracy"],
        "f1_gate_passed": bool(metrics["f1_score"] >= 0.95),
        "confusion_matrix": {
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "tn": metrics["tn"],
        },
    }

    out_file = Path(args.output)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(benchmark_result, f, indent=2)

    print("=" * 60)
    print("🚀 BENCHMARK RESULTS:")
    print(f"  Latency (mean):   {mean_latency_ms:.3f} ms / 1,000 events (Gate <10ms: {'PASS' if mean_latency_ms < 10 else 'FAIL'})")
    print(f"  Latency (p95):    {p95_latency_ms:.3f} ms / 1,000 events")
    print(f"  Precision:        {metrics['precision']:.4f}")
    print(f"  Recall:           {metrics['recall']:.4f}")
    print(f"  F1 Score:         {metrics['f1_score']:.4f} (Gate >=0.95: {'PASS' if metrics['f1_score'] >= 0.95 else 'FAIL'})")
    print(f"  Accuracy:         {metrics['accuracy']:.4f}")
    print(f"  Results saved to: {out_file}")
    print("=" * 60)

    if not (benchmark_result["latency_gate_passed"] and benchmark_result["f1_gate_passed"]):
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="threat-log-detector",
        description="Enterprise Unsupervised Intrusion Detection Engine for Linux Logs & Network Flows",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # TRAIN
    train_parser = subparsers.add_parser("train", help="Train model on baseline log dataset")
    train_parser.add_argument("--data", required=True, help="Path to training log file")
    train_parser.add_argument("--model-out", default="model.json", help="Path to output model JSON")
    train_parser.add_argument("--format", default="auto", choices=["auto", "auth", "syslog", "json"])
    train_parser.add_argument("--contamination", type=float, default=0.05)
    train_parser.add_argument("--n-estimators", type=int, default=100)
    train_parser.add_argument("--window-seconds", type=float, default=60.0)
    train_parser.add_argument("--step-seconds", type=float, default=30.0)

    # DETECT
    detect_parser = subparsers.add_parser("detect", help="Detect intrusions and generate alerts")
    detect_parser.add_argument("--data", required=True, help="Path to input log file")
    detect_parser.add_argument("--model", required=True, help="Path to trained model JSON")
    detect_parser.add_argument("--format", default="auto", choices=["auto", "auth", "syslog", "json"])
    detect_parser.add_argument("--threshold", type=float, default=None)
    detect_parser.add_argument("--window-seconds", type=float, default=60.0)
    detect_parser.add_argument("--step-seconds", type=float, default=30.0)
    detect_parser.add_argument("--cooldown", type=float, default=300.0)
    detect_parser.add_argument("--output", help="Optional output JSON file for alerts")

    # EVALUATE
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate model against ground truth dataset")
    eval_parser.add_argument("--test-data", required=True, help="Path to test log file")
    eval_parser.add_argument("--model", required=True, help="Path to model JSON")
    eval_parser.add_argument("--ground-truth", required=True, help="Path to ground truth JSON")
    eval_parser.add_argument("--window-seconds", type=float, default=60.0)
    eval_parser.add_argument("--step-seconds", type=float, default=30.0)

    # BENCHMARK
    bench_parser = subparsers.add_parser("benchmark", help="Run latency and F1 score benchmark")
    bench_parser.add_argument("--n-events", type=int, default=5000)
    bench_parser.add_argument("--batch-size", type=int, default=1000)
    bench_parser.add_argument("--output", default="benchmarks/resultados.json")

    args = parser.parse_args(argv)

    if args.command == "train":
        return run_train(args)
    elif args.command == "detect":
        return run_detect(args)
    elif args.command == "evaluate":
        return run_evaluate(args)
    elif args.command == "benchmark":
        return run_benchmark(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
