"""Benchmark suite for streaming throughput and bounded RAM consumption (<50MB)."""

from datetime import datetime, timezone, timedelta
import json
import os
import resource
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict

# Ensure src/ is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from timeline.correlator import TimelineCorrelator
from timeline.exporters.jsonl import export_jsonl
from timeline.integrity import IntegrityAnalyzer


def generate_synthetic_data(base_dir: str, count_per_file: int = 25000) -> dict[str, str]:
    """Generate realistic synthetic logs for Syslog, Auth, Nginx, and JSON-Lines."""
    t0 = datetime(2023, 10, 11, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Syslog
    syslog_path = os.path.join(base_dir, "benchmark_syslog.log")
    with open(syslog_path, "w", encoding="utf-8") as f:
        for i in range(count_per_file):
            t = t0 + timedelta(milliseconds=i * 50)
            iso = t.isoformat().replace("+00:00", "Z")
            f.write(f'<165>1 {iso} host-srv{i % 5} worker 1234 ID{i % 100} - Task worker execution cycle {i} completed\n')

    # 2. Auth.log
    auth_path = os.path.join(base_dir, "benchmark_auth.log")
    with open(auth_path, "w", encoding="utf-8") as f:
        for i in range(count_per_file):
            t = t0 + timedelta(milliseconds=i * 50 + 10)
            ts_str = t.strftime("%b %d %H:%M:%S")
            ip = f"192.168.1.{i % 250 + 1}"
            if i % 10 == 0:
                f.write(f"{ts_str} auth-srv sshd[2000]: Accepted publickey for user_{i % 20} from {ip} port {40000 + i % 1000} ssh2\n")
            elif i % 10 == 1:
                f.write(f"{ts_str} auth-srv sudo:   user_{i % 20} : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/id\n")
            else:
                f.write(f"{ts_str} auth-srv sshd[2000]: Connection closed by {ip} port {40000 + i % 1000} [preauth]\n")

    # 3. Nginx Access Log
    nginx_path = os.path.join(base_dir, "benchmark_nginx.log")
    with open(nginx_path, "w", encoding="utf-8") as f:
        for i in range(count_per_file):
            t = t0 + timedelta(milliseconds=i * 50 + 20)
            ts_nginx = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = f"10.0.0.{i % 200 + 1}"
            status = 200 if i % 20 != 0 else 404
            f.write(f'{ip} - user_{i % 10} [{ts_nginx}] "GET /api/v1/resource/{i % 500} HTTP/1.1" {status} 512 "-" "Mozilla/5.0"\n')

    # 4. JSON-Lines
    jsonl_path = os.path.join(base_dir, "benchmark_events.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for i in range(count_per_file):
            t = t0 + timedelta(milliseconds=i * 50 + 30)
            rec = {
                "timestamp": t.isoformat(),
                "level": "info" if i % 50 != 0 else "warn",
                "host": f"node-{i % 10}",
                "service": "k8s-ingress",
                "client_ip": f"172.16.0.{i % 100 + 1}",
                "message": f"Ingress routing packet {i}",
                "metric_counter": i,
            }
            f.write(json.dumps(rec) + "\n")

    return {
        "syslog": syslog_path,
        "auth": auth_path,
        "nginx": nginx_path,
        "jsonl": jsonl_path,
    }


def run_benchmark() -> dict[str, Any]:
    """Execute streaming benchmark and return verified performance metrics."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        print("Generating synthetic datasets (100,000 log events across 4 formats)...")
        files_dict = generate_synthetic_data(tmp_dir, count_per_file=25000)
        file_list = list(files_dict.values())

        total_bytes = sum(os.path.getsize(p) for p in file_list)
        total_mb = total_bytes / (1024 * 1024)
        print(f"Total raw log dataset size: {total_mb:.2f} MB")

        output_jsonl = os.path.join(tmp_dir, "out_merged.jsonl")

        # Start memory tracking
        tracemalloc.start()
        start_time = time.perf_counter()

        correlator = TimelineCorrelator()
        merged_stream = correlator.merge_files(file_list)
        event_count = export_jsonl(merged_stream, target=output_jsonl)

        elapsed_seconds = time.perf_counter() - start_time
        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure integrity analysis time
        start_tamper = time.perf_counter()
        analyzer = IntegrityAnalyzer()
        anomalies = analyzer.analyze_multi_file(file_list)
        tamper_elapsed = time.perf_counter() - start_tamper

        peak_ram_mb = peak_ram / (1024 * 1024)
        throughput_mb_s = total_mb / elapsed_seconds if elapsed_seconds > 0 else 0.0
        throughput_events_s = event_count / elapsed_seconds if elapsed_seconds > 0 else 0.0

        metrics = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_events_processed": event_count,
            "raw_dataset_size_mb": round(total_mb, 2),
            "streaming_correlation_time_seconds": round(elapsed_seconds, 3),
            "throughput_mb_per_second": round(throughput_mb_s, 2),
            "throughput_events_per_second": round(throughput_events_s, 2),
            "peak_memory_consumption_mb": round(peak_ram_mb, 2),
            "memory_guardrail_limit_mb": 50.0,
            "memory_guardrail_passed": bool(peak_ram_mb < 50.0),
            "tamper_detection_time_seconds": round(tamper_elapsed, 3),
            "detected_anomalies_count": len(anomalies),
            "system_max_rss_mb": round(
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2
            ),
        }

        print("\n=== BENCHMARK PERFORMANCE RESULTS ===")
        print(f"Total Events: {event_count:,}")
        print(f"Data Volume: {total_mb:.2f} MB")
        print(f"Elapsed Time: {elapsed_seconds:.3f} s")
        print(f"Throughput: {throughput_mb_s:.2f} MB/s ({throughput_events_s:,.0f} events/s)")
        print(f"Peak RAM: {peak_ram_mb:.2f} MB (Limit: <50MB) -> {'PASSED ✅' if peak_ram_mb < 50.0 else 'FAILED ❌'}")
        print(f"Tamper Audit Time: {tamper_elapsed:.3f} s")

        # Save to benchmarks/resultados.json
        bench_dir = os.path.dirname(os.path.realpath(__file__))
        results_path = os.path.join(bench_dir, "resultados.json")
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"Results saved to: {results_path}")

        return metrics


if __name__ == "__main__":
    run_benchmark()
