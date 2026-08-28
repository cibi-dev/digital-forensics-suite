"""
benchmarks/run.py - Enterprise Performance Benchmark for Criminal Graph Analysis.

Measures graph ingestion, PageRank calculation, Louvain community detection,
and bounded fraud ring discovery on a realistic graph with 10^5 (100,000) edges.
Target SLA: CPU execution time < 3.0 seconds.
"""

import json
import os
import resource
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add src to sys.path for standalone execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import networkx as nx
import numpy as np

from network.centrality import calculate_degree_centrality, calculate_pagerank
from network.communities import detect_communities_louvain
from network.fraud_rings import FraudRingDetector
from network.graph_store import CrimeNetworkGraph, EntityType, RelationType


def run_benchmark(num_nodes: int = 10000, avg_degree: int = 10, seed: int = 42) -> dict:
    """
    Executes high-throughput forensic graph analysis on 100,000 edges.
    """
    print(f"===========================================================")
    print(f"🚀 INITIATING FORENSIC GRAPH BENCHMARK (10^5 EDGES)")
    print(f"===========================================================")

    t_start_total = time.perf_counter()

    # 1. SYNTHETIC TOPOLOGY GENERATION (10^5 Edges)
    print(f"[*] Phase 1: Generating synthetic clustered crime network ({num_nodes} nodes, ~100,000 edges)...")
    t0 = time.perf_counter()

    np.random.seed(seed)
    n_clusters = 50
    nodes_per_cluster = num_nodes // n_clusters

    intra_src_list = []
    intra_dst_list = []
    for c in range(n_clusters):
        base = c * nodes_per_cluster
        s = np.random.randint(base, base + nodes_per_cluster, size=1600, dtype=np.int32)
        d = np.random.randint(base, base + nodes_per_cluster, size=1600, dtype=np.int32)
        intra_src_list.append(s)
        intra_dst_list.append(d)

    inter_src = np.random.randint(0, num_nodes, size=20000, dtype=np.int32)
    inter_dst = np.random.randint(0, num_nodes, size=20000, dtype=np.int32)

    src_nodes = np.concatenate(intra_src_list + [inter_src])
    dst_nodes = np.concatenate(intra_dst_list + [inter_dst])

    # Filter self-loops
    mask = src_nodes != dst_nodes
    src_nodes = src_nodes[mask]
    dst_nodes = dst_nodes[mask]
    amounts = np.random.exponential(scale=1500.0, size=len(src_nodes))

    cg = CrimeNetworkGraph(name="ForensicScaleBenchmark")
    raw_g = cg.raw_graph

    # Fast batch node loading
    for i in range(num_nodes):
        raw_g.add_node(
            f"N_{i}",
            id=f"N_{i}",
            entity_type="SUSPECT" if i % 5 == 0 else "BANK_ACCOUNT",
            label=f"Node_{i}",
            risk_score=float(i % 100) / 100.0,
        )

    # Fast batch edge loading
    edge_tuples = [
        (f"N_{src_nodes[i]}", f"N_{dst_nodes[i]}", {"weight": 1.0, "amount": float(amounts[i]), "relation_type": "TRANSACTION"})
        for i in range(len(src_nodes))
    ]
    raw_g.add_edges_from(edge_tuples)

    t_gen = time.perf_counter() - t0
    print(f"    -> Ingested {cg.num_nodes} nodes, {cg.num_edges} edges in {t_gen:.4f}s")

    # 2. DEGREE & PAGERANK CALCULATION
    print(f"[*] Phase 2: Computing Degree & PageRank metrics (Power Iteration)...")
    t0 = time.perf_counter()
    deg_metrics = calculate_degree_centrality(cg)
    pr_metrics = calculate_pagerank(cg, alpha=0.85, max_iter=50, tol=1e-5)
    t_cent = time.perf_counter() - t0
    print(f"    -> Centralities computed in {t_cent:.4f}s")

    # 3. LOUVAIN COMMUNITY DETECTION
    print(f"[*] Phase 3: Partitioning syndicates via Louvain Modular Optimization...")
    t0 = time.perf_counter()
    comm_report = detect_communities_louvain(cg, resolution=1.0, threshold=1e-4, max_level=3, seed=seed)
    t_comm = time.perf_counter() - t0
    print(f"    -> Partitioned {comm_report.num_communities} cells (Modularity: {comm_report.modularity}) in {t_comm:.4f}s")

    # 4. BOUNDED FRAUD RING & CYCLE DETECTION (CWE-400)
    print(f"[*] Phase 4: Scanning for circular fraud rings (k-cycles)...")
    t0 = time.perf_counter()
    detector = FraudRingDetector(cg)
    rings = detector.find_circular_transfers(min_length=3, max_length=4, max_cycles=50)
    mules = detector.find_mule_accounts(ratio_tolerance=0.2, min_tx_count=5)
    t_fraud = time.perf_counter() - t0
    print(f"    -> Found {len(rings)} rings and {len(mules)} mules in {t_fraud:.4f}s")

    t_total = time.perf_counter() - t_start_total

    # Memory usage in MB
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    max_rss_mb = round(rusage.ru_maxrss / 1024.0, 2)  # Linux ru_maxrss is in KB

    print(f"\n===========================================================")
    print(f"📊 BENCHMARK SUMMARY & PERFORMANCE GATE")
    print(f"===========================================================")
    print(f"Total Edges Analyzed:      {cg.num_edges:,}")
    print(f"Total Nodes Analyzed:      {cg.num_nodes:,}")
    print(f"Peak Memory (RSS):         {max_rss_mb} MB")
    print(f"Total CPU Time:            {t_total:.4f} seconds")
    
    passed = t_total < 3.0
    status_str = "✅ PASSED (< 3.0s SLA)" if passed else "❌ FAILED (>= 3.0s SLA)"
    print(f"Gate Status:               {status_str}")
    print(f"===========================================================\n")

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "graph_metrics": {
            "node_count": cg.num_nodes,
            "edge_count": cg.num_edges,
            "communities_detected": comm_report.num_communities,
            "modularity_score": comm_report.modularity,
            "fraud_rings_found": len(rings),
            "mules_found": len(mules),
        },
        "timings": {
            "ingestion_and_build_sec": round(t_gen, 4),
            "centrality_pagerank_sec": round(t_cent, 4),
            "louvain_communities_sec": round(t_comm, 4),
            "fraud_rings_detection_sec": round(t_fraud, 4),
            "total_execution_sec": round(t_total, 4),
        },
        "performance_gate": {
            "sla_threshold_sec": 3.0,
            "actual_time_sec": round(t_total, 4),
            "peak_rss_mb": max_rss_mb,
            "status": "PASS" if passed else "FAIL",
        },
    }

    out_file = Path(__file__).resolve().parent / "resultados.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Benchmark metrics saved to: {out_file}")

    return results


if __name__ == "__main__":
    run_benchmark()
