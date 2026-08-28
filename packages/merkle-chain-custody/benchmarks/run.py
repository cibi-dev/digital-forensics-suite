"""
Reproducible Benchmark Suite for merkle-chain-custody.
Measures hashing throughput, Merkle tree construction, proof generation/verification,
certificate signing, and SQLite immutable ingestion throughput.
Outputs metrics directly to benchmarks/resultados.json.
"""

import json
import os
import platform
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict

# Ensure src/ is on python path
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CURRENT_DIR.parent
sys.path.insert(0, str(PROJECT_DIR / "src"))

from custody.certificate import generate_certificate, verify_certificate
from custody.evidence import EvidenceItem, EvidenceMetadata, utcnow_iso
from custody.hasher import HashAlgorithm, hash_bytes, StreamingHasher
from custody.merkle import MerkleTree
from custody.storage import CustodyStorage


def benchmark_hashing_throughput(data_size_mb: int = 10) -> Dict[str, Any]:
    """Benchmark SHA-256 and BLAKE3 streaming hashing throughput."""
    total_bytes = data_size_mb * 1024 * 1024
    chunk_size = 65536
    sample_chunk = secrets.token_bytes(chunk_size)
    num_chunks = total_bytes // chunk_size

    results = {}
    for algo in (HashAlgorithm.SHA256, HashAlgorithm.BLAKE3):
        hasher = StreamingHasher(algo)
        start_time = time.perf_counter()
        for _ in range(num_chunks):
            hasher.update(sample_chunk)
        digest = hasher.hexdigest()
        elapsed_sec = time.perf_counter() - start_time
        mb_per_sec = data_size_mb / elapsed_sec if elapsed_sec > 0 else 0.0

        results[algo.value] = {
            "data_size_mb": data_size_mb,
            "elapsed_seconds": round(elapsed_sec, 4),
            "throughput_mb_s": round(mb_per_sec, 2),
            "sample_digest_prefix": digest[:16],
        }

    return results


def benchmark_merkle_tree_construction() -> Dict[str, Any]:
    """Benchmark tree construction and proof latency across leaf counts."""
    leaf_counts = [100, 1000, 5000, 10000]
    results = {}

    for count in leaf_counts:
        leaves = [hash_bytes(f"leaf-payload-{i}".encode("utf-8"), "sha256") for i in range(count)]
        
        # Build Tree
        start_build = time.perf_counter()
        tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
        build_elapsed = time.perf_counter() - start_build
        
        # Proof Generation (sample 100 proofs)
        sample_indices = [int(i * (count - 1) / 99) for i in range(100)]
        start_proof = time.perf_counter()
        proofs = [tree.get_proof(idx) for idx in sample_indices]
        proof_elapsed = time.perf_counter() - start_proof
        avg_proof_us = (proof_elapsed / 100) * 1_000_000

        # Proof Verification
        start_ver = time.perf_counter()
        for p in proofs:
            assert p.verify() is True
        ver_elapsed = time.perf_counter() - start_ver
        avg_ver_us = (ver_elapsed / 100) * 1_000_000

        results[f"leaves_{count}"] = {
            "leaf_count": count,
            "tree_height": tree.height,
            "build_time_ms": round(build_elapsed * 1000, 3),
            "proof_generation_us": round(avg_proof_us, 2),
            "proof_verification_us": round(avg_ver_us, 2),
            "root_prefix": tree.root[:16],
        }

    return results


def benchmark_certificate_operations(item_count: int = 500) -> Dict[str, Any]:
    """Benchmark HMAC-SHA256 non-repudiation certificate generation and verification."""
    secret_key = "benchmark_secret_key_forensic_chain"
    items = []
    for i in range(item_count):
        meta = EvidenceMetadata(
            source_path=f"/evidence/disk_{i}.raw",
            file_size_bytes=1048576,
            custody_officer="Officer-Bench",
            case_id="BENCH-CASE",
        )
        item = EvidenceItem(
            evidence_id=f"EV-BENCH-{i:05d}",
            hash_value=hash_bytes(f"bench-{i}".encode(), "sha256"),
            metadata=meta,
        )
        items.append(item)

    root_hash = hash_bytes(b"bench_root_hash", "sha256")

    # Generation
    start_gen = time.perf_counter()
    cert = generate_certificate(
        root_hash=root_hash,
        evidence_items=items,
        secret_key=secret_key,
        signer_identity="ForensicBenchAuthority",
        case_id="BENCH-CASE",
    )
    gen_time_ms = (time.perf_counter() - start_gen) * 1000

    # Verification
    start_ver = time.perf_counter()
    ver_res = verify_certificate(cert, secret_key=secret_key)
    assert ver_res.is_valid is True
    ver_time_ms = (time.perf_counter() - start_ver) * 1000

    return {
        "item_count": item_count,
        "certificate_id": cert.certificate_id,
        "generation_time_ms": round(gen_time_ms, 3),
        "verification_time_ms": round(ver_time_ms, 3),
    }


def benchmark_sqlite_ingestion(item_count: int = 1000) -> Dict[str, Any]:
    """Benchmark immutable SQLite write throughput with triggers active."""
    items = []
    for i in range(item_count):
        meta = EvidenceMetadata(
            source_path=f"/data/ev_{i}.dd",
            file_size_bytes=2048,
            custody_officer="Investigator-1",
            case_id="CASE-SQL-BENCH",
        )
        items.append(EvidenceItem(
            evidence_id=f"EV-SQL-{i:05d}",
            hash_value=hash_bytes(f"sql-bench-{i}".encode(), "sha256"),
            metadata=meta,
        ))

    with CustodyStorage(":memory:") as storage:
        start_write = time.perf_counter()
        for it in items:
            storage.store_evidence(it)
        write_elapsed = time.perf_counter() - start_write
        items_per_sec = item_count / write_elapsed if write_elapsed > 0 else 0.0

        # Read benchmark
        start_read = time.perf_counter()
        evs = storage.list_evidences(case_id="CASE-SQL-BENCH")
        read_elapsed = time.perf_counter() - start_read
        assert len(evs) == item_count

    return {
        "total_items": item_count,
        "write_elapsed_seconds": round(write_elapsed, 4),
        "write_throughput_items_per_sec": round(items_per_sec, 2),
        "read_all_latency_ms": round(read_elapsed * 1000, 3),
    }


def run_all_benchmarks() -> Dict[str, Any]:
    print("=" * 60)
    print("🚀 Running merkle-chain-custody Performance Benchmark Suite")
    print("=" * 60)

    t0 = time.perf_counter()
    
    print("\n[1/4] Measuring Streaming Hashing Throughput (10 MB)...")
    hash_metrics = benchmark_hashing_throughput(data_size_mb=10)
    print(f"      SHA-256: {hash_metrics['sha256']['throughput_mb_s']} MB/s")
    print(f"      BLAKE3 : {hash_metrics['blake3']['throughput_mb_s']} MB/s")

    print("\n[2/4] Measuring Balanced Merkle Tree Construction & Proofs...")
    merkle_metrics = benchmark_merkle_tree_construction()
    for k, v in merkle_metrics.items():
        print(f"      {k}: build={v['build_time_ms']}ms, proof_gen={v['proof_generation_us']}µs, proof_ver={v['proof_verification_us']}µs")

    print("\n[3/4] Measuring Non-Repudiation Certificate Operations (500 items)...")
    cert_metrics = benchmark_certificate_operations(item_count=500)
    print(f"      Sign : {cert_metrics['generation_time_ms']} ms")
    print(f"      Verify: {cert_metrics['verification_time_ms']} ms")

    print("\n[4/4] Measuring SQLite Ingestion with Triggers (1,000 items)...")
    db_metrics = benchmark_sqlite_ingestion(item_count=1000)
    print(f"      Throughput: {db_metrics['write_throughput_items_per_sec']} items/sec")
    print(f"      Read All  : {db_metrics['read_all_latency_ms']} ms")

    total_elapsed = time.perf_counter() - t0

    system_info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }

    full_results = {
        "timestamp": utcnow_iso(),
        "benchmark_duration_seconds": round(total_elapsed, 3),
        "system": system_info,
        "hashing_throughput": hash_metrics,
        "merkle_tree": merkle_metrics,
        "certificate_operations": cert_metrics,
        "sqlite_ingestion": db_metrics,
    }

    out_path = CURRENT_DIR / "resultados.json"
    out_path.write_text(json.dumps(full_results, indent=2), encoding="utf-8")
    print(f"\n[+] Benchmark results saved to: {out_path}")
    print("=" * 60)
    return full_results


if __name__ == "__main__":
    run_all_benchmarks()
