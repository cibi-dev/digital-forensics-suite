"""
cli.py - Command-Line Interface for Crime Network Analyzer.

Provides CLI subcommands: build, analyze, find-rings, export, benchmark.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from network.centrality import calculate_all_centralities, identify_kingpins_and_brokers
from network.communities import detect_communities_louvain, find_cross_community_brokers
from network.exporters import export_to_gexf, export_to_graphml, export_to_json
from network.fraud_rings import FraudRingDetector
from network.graph_store import CrimeNetworkGraph


def create_parser() -> argparse.ArgumentParser:
    """Constructs the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="crime-analyzer",
        description="Enterprise Criminal Network Analyzer & Fraud Ring Detector",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand to execute")

    # 1. BUILD
    build_p = subparsers.add_parser("build", help="Build network graph from CSV or JSON files")
    build_p.add_argument("--nodes", type=str, help="Path to nodes CSV file")
    build_p.add_argument("--edges", type=str, help="Path to edges CSV file")
    build_p.add_argument("--input-json", type=str, help="Path to graph JSON file")
    build_p.add_argument("--name", type=str, default="CrimeNetwork", help="Name of the graph")
    build_p.add_argument("--out", type=str, help="Output JSON path to save graph")

    # 2. ANALYZE
    analyze_p = subparsers.add_parser("analyze", help="Calculate centralities and community detection")
    analyze_p.add_argument("--input", "-i", type=str, required=True, help="Path to graph JSON file")
    analyze_p.add_argument("--alpha", type=float, default=0.85, help="PageRank damping factor (default: 0.85)")
    analyze_p.add_argument("--top-k", type=int, default=5, help="Number of top entities to highlight")
    analyze_p.add_argument("--resolution", type=float, default=1.0, help="Louvain resolution parameter")
    analyze_p.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    analyze_p.add_argument("--out", type=str, help="Output JSON path to save analysis results")

    # 3. FIND-RINGS
    rings_p = subparsers.add_parser("find-rings", help="Detect circular transfer rings, mule accounts, and smurfing")
    rings_p.add_argument("--input", "-i", type=str, required=True, help="Path to graph JSON file")
    rings_p.add_argument("--min-len", type=int, default=3, help="Minimum cycle length (default: 3)")
    rings_p.add_argument("--max-len", type=int, default=6, help="Maximum cycle length (default: 6)")
    rings_p.add_argument("--max-cycles", type=int, default=500, help="Maximum cycles to report (default: 500)")
    rings_p.add_argument("--mule-tolerance", type=float, default=0.25, help="Flow difference tolerance for mules")
    rings_p.add_argument("--fan-threshold", type=int, default=3, help="Smurfing fan threshold")
    rings_p.add_argument("--out", type=str, help="Output JSON path to save fraud report")

    # 4. EXPORT
    export_p = subparsers.add_parser("export", help="Export graph to GEXF (Gephi), GraphML, or JSON")
    export_p.add_argument("--input", "-i", type=str, required=True, help="Path to graph JSON file")
    export_p.add_argument("--format", "-f", choices=["gexf", "graphml", "json"], default="gexf", help="Export format")
    export_p.add_argument("--out", "-o", type=str, required=True, help="Destination output file path")
    export_p.add_argument("--redact-pii", action="store_true", help="Redact PII in labels and attributes (CWE-209)")

    # 5. BENCHMARK
    bench_p = subparsers.add_parser("benchmark", help="Run synthetic graph analysis benchmark")
    bench_p.add_argument("--edges", type=int, default=100000, help="Target edge count (default: 100000)")
    bench_p.add_argument("--out", type=str, help="Output JSON path to save benchmark metrics")

    return parser


def handle_build(args: argparse.Namespace) -> int:
    """Handles 'build' subcommand."""
    if args.nodes and args.edges:
        graph = CrimeNetworkGraph.from_csv(args.nodes, args.edges, name=args.name)
    elif args.input_json:
        graph = CrimeNetworkGraph.from_json(args.input_json)
    else:
        print("Error: Specify either (--nodes and --edges) or (--input-json).", file=sys.stderr)
        return 1

    print(f"Graph '{graph.name}' built successfully: {graph.num_nodes} nodes, {graph.num_edges} edges.")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(graph.to_dict(), f, indent=2)
        print(f"Graph saved to: {out_path}")

    return 0


def handle_analyze(args: argparse.Namespace) -> int:
    """Handles 'analyze' subcommand."""
    graph = CrimeNetworkGraph.from_json(args.input)
    print(f"Analyzing graph '{graph.name}' ({graph.num_nodes} nodes, {graph.num_edges} edges)...")

    # Centralities
    cent_report = calculate_all_centralities(graph, alpha=args.alpha, top_k=args.top_k)
    roles = identify_kingpins_and_brokers(cent_report, top_k=args.top_k)

    # Communities
    comm_report = detect_communities_louvain(graph, resolution=args.resolution, seed=args.seed)
    cross_brokers = find_cross_community_brokers(graph, comm_report.partition_map)

    print("\n--- CENTRALITY HIGHLIGHTS ---")
    print(f"Top PageRank (Influencers): {cent_report.top_influencers[:args.top_k]}")
    print(f"Top Betweenness (Brokers): {cent_report.top_brokers[:args.top_k]}")
    print(f"Top Hubs (Degree):         {cent_report.top_hubs[:args.top_k]}")
    print(f"Top Composite Risk:        {cent_report.top_highest_risk[:args.top_k]}")

    print("\n--- COMMUNITY HIGHLIGHTS ---")
    print(f"Cells Identified:          {comm_report.num_communities} (Modularity: {comm_report.modularity})")
    print(f"Cross-Syndicate Brokers:   {len(cross_brokers)}")

    if args.out:
        out_data = {
            "centrality_report": cent_report.model_dump(),
            "roles": roles,
            "community_report": comm_report.model_dump(),
            "cross_community_brokers": cross_brokers,
        }
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2)
        print(f"\nAnalysis saved to: {out_path}")

    return 0


def handle_find_rings(args: argparse.Namespace) -> int:
    """Handles 'find-rings' subcommand."""
    graph = CrimeNetworkGraph.from_json(args.input)
    detector = FraudRingDetector(graph)

    report = detector.detect_all(
        min_cycle_len=args.min_len,
        max_cycle_len=args.max_len,
        max_cycles=args.max_cycles,
        mule_ratio_tolerance=args.mule_tolerance,
        fan_threshold=args.fan_threshold,
    )

    print(f"Fraud Detection Complete:")
    print(f" - Circular Rings (k-cycles): {report.total_cycles_detected}")
    print(f" - Identified Mule Accounts: {len(report.mule_accounts)}")
    print(f" - Smurfing Patterns:        {len(report.smurfing_patterns)}")
    print(f" - Suspicious Volume Total:  ${report.suspicious_volume_total:,.2f}")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2)
        print(f"Fraud report saved to: {out_path}")

    return 0


def handle_export(args: argparse.Namespace) -> int:
    """Handles 'export' subcommand."""
    graph = CrimeNetworkGraph.from_json(args.input)
    fmt = args.format.lower()
    out_path = Path(args.out)

    if fmt == "gexf":
        cent_report = calculate_all_centralities(graph)
        comm_report = detect_communities_louvain(graph)
        export_to_gexf(graph, filepath=out_path, centralities=cent_report, communities=comm_report, redact_pii=args.redact_pii)
    elif fmt == "graphml":
        export_to_graphml(graph, filepath=out_path, redact_pii=args.redact_pii)
    elif fmt == "json":
        export_to_json(graph, filepath=out_path, redact_pii=args.redact_pii)
    else:
        print(f"Error: Unknown format '{fmt}'.", file=sys.stderr)
        return 1

    print(f"Exported graph to {fmt.upper()}: {out_path} (PII Redacted: {args.redact_pii})")
    return 0


def handle_benchmark(args: argparse.Namespace) -> int:
    """Handles 'benchmark' subcommand."""
    import networkx as nx

    print(f"Generating synthetic forensic graph with {args.edges} edges...")
    t0 = time.perf_counter()

    num_nodes = int(args.edges // 10)
    g = nx.fast_gnp_random_graph(n=num_nodes, p=20.0 / num_nodes, directed=True, seed=42)
    
    cg = CrimeNetworkGraph(name="BenchmarkGraph")
    for n in g.nodes():
        cg.add_node(str(n), entity_type="SUSPECT", risk_score=0.5)
    for u, v in g.edges():
        cg.add_edge((str(u), str(v)), amount=100.0)

    t_gen = time.perf_counter() - t0

    # Analysis phase
    t_start_ana = time.perf_counter()
    cent_report = calculate_all_centralities(cg, top_k=5)
    comm_report = detect_communities_louvain(cg, seed=42)
    detector = FraudRingDetector(cg)
    rings = detector.find_circular_transfers(min_length=3, max_length=4, max_cycles=100)
    t_ana = time.perf_counter() - t_start_ana

    total_time = t_gen + t_ana
    print(f"\n--- BENCHMARK RESULTS ---")
    print(f"Nodes: {cg.num_nodes} | Edges: {cg.num_edges}")
    print(f"Generation & Ingestion: {t_gen:.4f}s")
    print(f"Analysis & Louvain:     {t_ana:.4f}s")
    print(f"Total Execution Time:   {total_time:.4f}s")

    metrics = {
        "nodes": cg.num_nodes,
        "edges": cg.num_edges,
        "generation_time_sec": round(t_gen, 4),
        "analysis_time_sec": round(t_ana, 4),
        "total_time_sec": round(total_time, 4),
        "status": "PASS" if total_time < 3.0 else "FAIL",
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"Results saved to: {out_path}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command == "build":
        return handle_build(args)
    elif args.command == "analyze":
        return handle_analyze(args)
    elif args.command == "find-rings":
        return handle_find_rings(args)
    elif args.command == "export":
        return handle_export(args)
    elif args.command == "benchmark":
        return handle_benchmark(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
