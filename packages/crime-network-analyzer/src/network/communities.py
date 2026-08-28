"""
communities.py - Criminal Syndicate & Cell Community Detection.

Identifies cohesive criminal subgroups, drug cartels, and fraud syndicates
using Louvain modularity optimization with deterministic seeding.
"""

from __future__ import annotations

from typing import Any, Sequence
import networkx as nx
from networkx.algorithms.community import louvain_communities, modularity
from pydantic import BaseModel, Field

from network.graph_store import CrimeNetworkGraph


class CriminalCell(BaseModel):
    """Represents a cohesive criminal community/cell."""

    community_id: int
    label: str
    member_count: int
    members: list[str]
    internal_density: float = 0.0
    total_internal_weight: float = 0.0
    leaders: list[str] = Field(default_factory=list, description="Top internal hubs of the cell")
    entity_type_distribution: dict[str, int] = Field(default_factory=dict)


class CommunityReport(BaseModel):
    """Comprehensive community detection report with modularity score."""

    num_communities: int
    modularity: float
    communities: list[CriminalCell]
    partition_map: dict[str, int] = Field(default_factory=dict, description="Map of node_id to community_id")
    inter_community_edges_count: int = 0
    inter_community_volume: float = 0.0


def detect_communities_louvain(
    graph: CrimeNetworkGraph,
    weight: str = "weight",
    resolution: float = 1.0,
    threshold: float = 1e-4,
    max_level: int | None = None,
    seed: int = 42,
) -> CommunityReport:
    """
    Applies Louvain community detection to partition the crime graph into cells.
    Works on undirected projection to ensure symmetric modularity optimization.
    """
    g = graph.raw_graph
    if g.number_of_nodes() == 0:
        return CommunityReport(
            num_communities=0,
            modularity=0.0,
            communities=[],
            partition_map={},
            inter_community_edges_count=0,
            inter_community_volume=0.0,
        )

    undirected_g = g.to_undirected()

    # Louvain partition
    raw_communities = louvain_communities(
        undirected_g,
        weight=weight,
        resolution=resolution,
        threshold=threshold,
        max_level=max_level,
        seed=seed,
    )

    # Sort communities by size descending
    sorted_comms = sorted(raw_communities, key=len, reverse=True)

    # Build partition map
    partition_map: dict[str, int] = {}
    for idx, comm in enumerate(sorted_comms):
        for node in comm:
            partition_map[node] = idx

    # Calculate Modularity
    mod_score = 0.0
    if len(sorted_comms) > 1 and undirected_g.number_of_edges() > 0:
        try:
            mod_score = float(modularity(undirected_g, sorted_comms, weight=weight))
        except Exception:
            mod_score = 0.0

    # Build cell objects
    cells: list[CriminalCell] = []
    for idx, comm in enumerate(sorted_comms):
        comm_nodes = list(comm)
        sub_nx = undirected_g.subgraph(comm_nodes)
        
        # Internal density
        density = nx.density(sub_nx) if len(comm_nodes) > 1 else 1.0

        # Internal weight
        int_weight = sum(d.get(weight, 1.0) for _, _, d in sub_nx.edges(data=True))

        # Internal leaders (highest internal degree)
        int_degrees = dict(sub_nx.degree())
        top_leaders = sorted(int_degrees.keys(), key=lambda x: int_degrees[x], reverse=True)[:3]

        # Entity type distribution
        type_dist: dict[str, int] = {}
        for nid in comm_nodes:
            etype = g.nodes[nid].get("entity_type", "OTHER")
            type_dist[etype] = type_dist.get(etype, 0) + 1

        cell = CriminalCell(
            community_id=idx,
            label=f"Criminal_Cell_{idx + 1:02d}",
            member_count=len(comm_nodes),
            members=comm_nodes,
            internal_density=round(float(density), 4),
            total_internal_weight=round(float(int_weight), 2),
            leaders=top_leaders,
            entity_type_distribution=type_dist,
        )
        cells.append(cell)

    # Calculate inter-community interactions
    inter_edges_count = 0
    inter_vol = 0.0
    for u, v, d in g.edges(data=True):
        comm_u = partition_map.get(u)
        comm_v = partition_map.get(v)
        if comm_u is not None and comm_v is not None and comm_u != comm_v:
            inter_edges_count += 1
            inter_vol += float(d.get("amount", d.get(weight, 1.0)) or 1.0)

    return CommunityReport(
        num_communities=len(cells),
        modularity=round(mod_score, 4),
        communities=cells,
        partition_map=partition_map,
        inter_community_edges_count=inter_edges_count,
        inter_community_volume=round(inter_vol, 2),
    )


def get_inter_community_links(
    graph: CrimeNetworkGraph,
    partition_map: dict[str, int],
) -> list[dict[str, Any]]:
    """
    Returns edges bridging distinct criminal communities (cross-cell liaisons).
    """
    g = graph.raw_graph
    bridges: list[dict[str, Any]] = []

    for u, v, d in g.edges(data=True):
        comm_u = partition_map.get(u)
        comm_v = partition_map.get(v)
        if comm_u is not None and comm_v is not None and comm_u != comm_v:
            bridges.append({
                "source": u,
                "target": v,
                "source_community": comm_u,
                "target_community": comm_v,
                "relation_type": d.get("relation_type", "UNKNOWN"),
                "weight": d.get("weight", 1.0),
                "amount": d.get("amount"),
            })
    return bridges


def find_cross_community_brokers(
    graph: CrimeNetworkGraph,
    partition_map: dict[str, int],
) -> list[dict[str, Any]]:
    """
    Identifies entities that connect multiple disparate criminal syndicates.
    """
    g = graph.raw_graph
    broker_stats: dict[str, set[int]] = {}

    for u, v in g.edges():
        c_u = partition_map.get(u)
        c_v = partition_map.get(v)
        if c_u is not None and c_v is not None:
            broker_stats.setdefault(u, set()).add(c_u)
            broker_stats.setdefault(u, set()).add(c_v)
            broker_stats.setdefault(v, set()).add(c_u)
            broker_stats.setdefault(v, set()).add(c_v)

    cross_brokers: list[dict[str, Any]] = []
    for nid, comms in broker_stats.items():
        if len(comms) > 1:
            cross_brokers.append({
                "node_id": nid,
                "entity_type": g.nodes[nid].get("entity_type", "UNKNOWN"),
                "connected_communities": sorted(list(comms)),
                "span_count": len(comms),
            })

    cross_brokers.sort(key=lambda x: x["span_count"], reverse=True)
    return cross_brokers
