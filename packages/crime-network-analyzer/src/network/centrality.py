"""
centrality.py - Deterministic Network Centralities for Forensic Intelligence.

Computes in-degree, out-degree, betweenness, closeness, and PageRank metrics
to identify criminal kingpins, brokers, couriers, and financial hubs.
"""

from __future__ import annotations

from typing import Any, Sequence
import networkx as nx
import numpy as np
from pydantic import BaseModel, Field

from network.graph_store import CrimeNetworkGraph, EntityType


class NodeCentrality(BaseModel):
    """Container for individual node centrality metrics."""

    node_id: str
    entity_type: str = "SUSPECT"
    label: str = ""
    in_degree: float = 0.0
    out_degree: float = 0.0
    total_degree: float = 0.0
    betweenness: float = 0.0
    closeness: float = 0.0
    pagerank: float = 0.0
    base_risk: float = 0.0
    composite_risk: float = Field(default=0.0, ge=0.0, le=1.0)


class CentralityReport(BaseModel):
    """Aggregated centrality analysis report."""

    total_nodes: int
    top_influencers: list[str] = Field(description="Top nodes ranked by PageRank")
    top_brokers: list[str] = Field(description="Top nodes ranked by Betweenness")
    top_hubs: list[str] = Field(description="Top nodes ranked by Degree")
    top_highest_risk: list[str] = Field(description="Top nodes ranked by composite risk score")
    nodes: dict[str, NodeCentrality] = Field(description="Map of node_id to metrics")
    summary: dict[str, Any] = Field(default_factory=dict)


def calculate_degree_centrality(graph: CrimeNetworkGraph) -> dict[str, dict[str, float]]:
    """
    Compute in-degree, out-degree, and normalized degree centralities.
    """
    g = graph.raw_graph
    n = g.number_of_nodes()
    scale = 1.0 / (n - 1) if n > 1 else 1.0

    in_deg = nx.in_degree_centrality(g) if n > 1 else {node: float(g.in_degree(node)) for node in g.nodes()}
    out_deg = nx.out_degree_centrality(g) if n > 1 else {node: float(g.out_degree(node)) for node in g.nodes()}
    deg = nx.degree_centrality(g) if n > 1 else {node: float(g.degree(node)) for node in g.nodes()}

    return {
        node: {
            "in_degree": float(in_deg.get(node, 0.0)),
            "out_degree": float(out_deg.get(node, 0.0)),
            "degree": float(deg.get(node, 0.0)),
        }
        for node in g.nodes()
    }


def calculate_betweenness_centrality(
    graph: CrimeNetworkGraph,
    weight: str | None = None,
    normalized: bool = True,
    seed: int = 42,
) -> dict[str, float]:
    """
    Deterministic calculation of Betweenness Centrality.
    High betweenness indicates bridge nodes, couriers, or middleman accounts.
    """
    g = graph.raw_graph
    if g.number_of_nodes() == 0:
        return {}
    if g.number_of_nodes() <= 2:
        return {node: 0.0 for node in g.nodes()}

    bc = nx.betweenness_centrality(
        g,
        weight=weight,
        normalized=normalized,
        seed=seed,
    )
    return {node: float(score) for node, score in bc.items()}


def calculate_closeness_centrality(
    graph: CrimeNetworkGraph,
    wf_improved: bool = True,
) -> dict[str, float]:
    """
    Deterministic Closeness Centrality.
    Measures shortest path distance from a node to all reachable nodes.
    """
    g = graph.raw_graph
    if g.number_of_nodes() == 0:
        return {}
    cc = nx.closeness_centrality(g, wf_improved=wf_improved)
    return {node: float(score) for node, score in cc.items()}


def calculate_pagerank(
    graph: CrimeNetworkGraph,
    alpha: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6,
    weight: str | None = "weight",
) -> dict[str, float]:
    """
    Computes PageRank over the directed criminological network.
    Measures flow of influence, authority, or recursive capital routing.
    """
    g = graph.raw_graph
    if g.number_of_nodes() == 0:
        return {}
    if g.number_of_edges() == 0:
        n = g.number_of_nodes()
        return {node: 1.0 / n for node in g.nodes()}

    try:
        pr = nx.pagerank(
            g,
            alpha=alpha,
            max_iter=max_iter,
            tol=tol,
            weight=weight,
        )
    except nx.PowerIterationFailedConvergence:
        # Fallback to standard uniform distribution if power iteration fails
        n = g.number_of_nodes()
        pr = {node: 1.0 / n for node in g.nodes()}

    return {node: float(score) for node, score in pr.items()}


def calculate_all_centralities(
    graph: CrimeNetworkGraph,
    alpha: float = 0.85,
    top_k: int = 5,
) -> CentralityReport:
    """
    Computes all standard centralities and produces an aggregated CentralityReport.
    """
    g = graph.raw_graph
    n = g.number_of_nodes()

    if n == 0:
        return CentralityReport(
            total_nodes=0,
            top_influencers=[],
            top_brokers=[],
            top_hubs=[],
            top_highest_risk=[],
            nodes={},
            summary={"message": "Empty graph"},
        )

    deg_dict = calculate_degree_centrality(graph)
    betw_dict = calculate_betweenness_centrality(graph)
    close_dict = calculate_closeness_centrality(graph)
    page_dict = calculate_pagerank(graph, alpha=alpha)

    # Normalize metrics for composite risk score
    max_pr = max(page_dict.values()) if page_dict else 1.0
    max_bc = max(betw_dict.values()) if betw_dict else 1.0
    max_deg = max((d["degree"] for d in deg_dict.values()), default=1.0)

    nodes_data: dict[str, NodeCentrality] = {}
    for node_id in g.nodes():
        node_attr = g.nodes[node_id]
        base_risk = float(node_attr.get("risk_score", 0.0))
        label = str(node_attr.get("label", node_id))
        ent_type = str(node_attr.get("entity_type", "SUSPECT"))

        pr_val = page_dict.get(node_id, 0.0)
        bc_val = betw_dict.get(node_id, 0.0)
        deg_info = deg_dict.get(node_id, {"in_degree": 0.0, "out_degree": 0.0, "degree": 0.0})

        norm_pr = pr_val / max_pr if max_pr > 0 else 0.0
        norm_bc = bc_val / max_bc if max_bc > 0 else 0.0
        norm_deg = deg_info["degree"] / max_deg if max_deg > 0 else 0.0

        # Composite risk formula: 35% PageRank + 25% Betweenness + 20% Degree + 20% Base Risk
        comp_risk = float(
            np.clip(
                0.35 * norm_pr + 0.25 * norm_bc + 0.20 * norm_deg + 0.20 * base_risk,
                0.0,
                1.0,
            )
        )

        nodes_data[node_id] = NodeCentrality(
            node_id=node_id,
            entity_type=ent_type,
            label=label,
            in_degree=deg_info["in_degree"],
            out_degree=deg_info["out_degree"],
            total_degree=deg_info["degree"],
            betweenness=bc_val,
            closeness=close_dict.get(node_id, 0.0),
            pagerank=pr_val,
            base_risk=base_risk,
            composite_risk=round(comp_risk, 4),
        )

    # Rank top lists
    top_pr = sorted(page_dict.keys(), key=lambda x: page_dict[x], reverse=True)[:top_k]
    top_bc = sorted(betw_dict.keys(), key=lambda x: betw_dict[x], reverse=True)[:top_k]
    top_deg = sorted(deg_dict.keys(), key=lambda x: deg_dict[x]["degree"], reverse=True)[:top_k]
    top_risk = sorted(nodes_data.keys(), key=lambda x: nodes_data[x].composite_risk, reverse=True)[:top_k]

    return CentralityReport(
        total_nodes=n,
        top_influencers=top_pr,
        top_brokers=top_bc,
        top_hubs=top_deg,
        top_highest_risk=top_risk,
        nodes=nodes_data,
        summary={
            "avg_betweenness": float(np.mean(list(betw_dict.values()))) if betw_dict else 0.0,
            "avg_pagerank": float(np.mean(list(page_dict.values()))) if page_dict else 0.0,
            "max_composite_risk": float(max((nd.composite_risk for nd in nodes_data.values()), default=0.0)),
        },
    )


def identify_kingpins_and_brokers(
    report: CentralityReport,
    top_k: int = 5,
) -> dict[str, list[dict[str, Any]]]:
    """
    Classifies key network figures into Kingpins (high influence/flow),
    Brokers (high betweenness), and Operational Hubs (high connectivity).
    """
    kingpins = [
        {
            "node_id": nid,
            "pagerank": report.nodes[nid].pagerank,
            "composite_risk": report.nodes[nid].composite_risk,
            "role": "KINGPIN_CANDIDATE",
        }
        for nid in report.top_influencers[:top_k]
        if nid in report.nodes
    ]

    brokers = [
        {
            "node_id": nid,
            "betweenness": report.nodes[nid].betweenness,
            "composite_risk": report.nodes[nid].composite_risk,
            "role": "BROKER_FACILITATOR",
        }
        for nid in report.top_brokers[:top_k]
        if nid in report.nodes
    ]

    hubs = [
        {
            "node_id": nid,
            "degree": report.nodes[nid].total_degree,
            "in_degree": report.nodes[nid].in_degree,
            "out_degree": report.nodes[nid].out_degree,
            "role": "OPERATIONAL_HUB",
        }
        for nid in report.top_hubs[:top_k]
        if nid in report.nodes
    ]

    return {
        "kingpins": kingpins,
        "brokers": brokers,
        "hubs": hubs,
    }
