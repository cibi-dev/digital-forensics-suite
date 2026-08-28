"""Performance benchmarking suite for Shannon entropy scanning and forensic file carving."""

from __future__ import annotations

import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

# Add project root and src to pythonpath
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root))

from carver.entropy import (
    calculate_entropy,
    calculate_entropy_blocks,
    calculate_entropy_sliding_window,
    generate_file_entropy_map,
)
from carver.extractor import Extractor
from carver.validator import FileValidator
from tests.test_signatures import (
    create_minimal_elf64,
    create_minimal_jpeg,
    create_minimal_pdf,
    create_minimal_pe,
    create_minimal_png,
    create_minimal_zip,
)


def generate_benchmark_dump(target_size_bytes: int = 20 * 1024 * 1024) -> bytes:
    """Generate a realistic synthetic forensic disk image with embedded files and varied entropy zones."""
    png = create_minimal_png()
    jpeg = create_minimal_jpeg()
    zip_buf = create_minimal_zip()
    pdf = create_minimal_pdf()
    elf = create_minimal_elf64()
    pe = create_minimal_pe()

    # Reusable blocks
    zero_block = b"\x00" * 65536
    text_block = (
        b"Digital forensics memory dump sample chunk with normal ASCII text. " * 1024
    )[:65536]
    noise_block = (bytes(range(256)) * 256)[:65536]

    chunks: list[bytes] = []
    current_size = 0

    while current_size < target_size_bytes:
        chunks.append(zero_block)
        chunks.append(png)
        chunks.append(text_block)
        chunks.append(jpeg)
        chunks.append(noise_block)
        chunks.append(zip_buf)
        chunks.append(elf)
        chunks.append(text_block)
        chunks.append(pe)
        chunks.append(pdf)
        current_size = sum(len(c) for c in chunks)

    data = b"".join(chunks)
    return data[:target_size_bytes]


def run_benchmarks() -> dict:
    """Execute all performance benchmarks and return structured results."""
    print("==================================================================")
    print("  Entropy File Carver - Performance Benchmarks")
    print("==================================================================")
    print(f"Platform:       {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Version: {platform.python_version()}")
    print("------------------------------------------------------------------")

    target_mb = 20
    target_bytes = target_mb * 1024 * 1024
    print(f"Generating synthetic forensic test dump ({target_mb} MB)...")
    data = generate_benchmark_dump(target_bytes)
    print(f"Dump generated: {len(data):,} bytes.\n")

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        },
        "test_dataset": {
            "size_bytes": len(data),
            "size_mb": target_mb,
        },
        "benchmarks": {},
    }

    # 1. Raw Shannon Entropy Throughput
    print("[1/5] Benchmarking Raw Shannon Entropy Calculation (4KB blocks)...")
    block_size = 4096
    num_blocks = len(data) // block_size
    t0 = time.perf_counter()
    for i in range(num_blocks):
        calculate_entropy(data[i * block_size : (i + 1) * block_size])
    t1 = time.perf_counter()
    duration_raw = t1 - t0
    throughput_raw = target_mb / duration_raw if duration_raw > 0 else 0
    print(f"      -> Time: {duration_raw:.4f}s | Throughput: {throughput_raw:.2f} MB/s")
    results["benchmarks"]["raw_shannon_entropy"] = {
        "duration_seconds": round(duration_raw, 4),
        "throughput_mb_s": round(throughput_raw, 2),
        "blocks_processed": num_blocks,
    }

    # 2. Sliding Window Entropy
    print("[2/5] Benchmarking Sliding Window Entropy (window=1024, step=512 over 2MB sample)...")
    sample_2mb = data[: 2 * 1024 * 1024]
    t0 = time.perf_counter()
    sw_results = calculate_entropy_sliding_window(sample_2mb, window_size=1024, step_size=512)
    t1 = time.perf_counter()
    duration_sw = t1 - t0
    throughput_sw = 2.0 / duration_sw if duration_sw > 0 else 0
    print(f"      -> Windows: {len(sw_results):,} | Time: {duration_sw:.4f}s | Throughput: {throughput_sw:.2f} MB/s")
    results["benchmarks"]["sliding_window_entropy"] = {
        "duration_seconds": round(duration_sw, 4),
        "throughput_mb_s": round(throughput_sw, 2),
        "windows_evaluated": len(sw_results),
    }

    # 3. Block-based Entropy Mapping
    print("[3/5] Benchmarking Block-based Entropy Mapping (4KB blocks across 20MB)...")
    t0 = time.perf_counter()
    emap = calculate_entropy_blocks(data, block_size=4096)
    t1 = time.perf_counter()
    duration_map = t1 - t0
    throughput_map = target_mb / duration_map if duration_map > 0 else 0
    print(f"      -> Blocks: {len(emap.blocks):,} | Time: {duration_map:.4f}s | Throughput: {throughput_map:.2f} MB/s")
    results["benchmarks"]["entropy_mapping"] = {
        "duration_seconds": round(duration_map, 4),
        "throughput_mb_s": round(throughput_map, 2),
        "total_blocks": len(emap.blocks),
    }

    # 4. Memory-mapped File Carving
    print("[4/5] Benchmarking Full Memory-Mapped Signature Scanning & Carving...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        dump_file = Path(tmp_dir) / "bench_dump.raw"
        dump_file.write_bytes(data)
        out_carve_dir = Path(tmp_dir) / "carved"

        extractor = Extractor(validate_integrity=True)
        t0 = time.perf_counter()
        res = extractor.carve_file(dump_file, output_dir=out_carve_dir)
        t1 = time.perf_counter()
        duration_carve = t1 - t0
        throughput_carve = target_mb / duration_carve if duration_carve > 0 else 0
        files_per_sec = res.files_carved / duration_carve if duration_carve > 0 else 0
        print(f"      -> Files Carved: {res.files_carved} | Time: {duration_carve:.4f}s | Throughput: {throughput_carve:.2f} MB/s ({files_per_sec:.1f} files/sec)")
        results["benchmarks"]["mmap_file_carving"] = {
            "duration_seconds": round(duration_carve, 4),
            "throughput_mb_s": round(throughput_carve, 2),
            "files_carved": res.files_carved,
            "files_per_second": round(files_per_sec, 2),
        }

    # 5. Format Validation Throughput
    print("[5/5] Benchmarking Forensic Format Validation & Stego Analysis (1,000 files)...")
    png_sample = create_minimal_png()
    t0 = time.perf_counter()
    for _ in range(1000):
        FileValidator.validate_png(png_sample)
    t1 = time.perf_counter()
    duration_val = t1 - t0
    val_rate = 1000.0 / duration_val if duration_val > 0 else 0
    print(f"      -> Validations: 1,000 | Time: {duration_val:.4f}s | Rate: {val_rate:,.1f} validations/sec")
    results["benchmarks"]["format_validation"] = {
        "duration_seconds": round(duration_val, 4),
        "validations_per_second": round(val_rate, 2),
    }

    print("------------------------------------------------------------------")
    print("  Benchmark Suite Completed Successfully.")
    print("==================================================================\n")

    # Save to resultados.json
    out_json = Path(__file__).parent / "resultados.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {out_json}")

    return results


if __name__ == "__main__":
    run_benchmarks()
