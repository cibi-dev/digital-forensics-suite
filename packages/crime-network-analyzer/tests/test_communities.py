"""
Unit tests for communities.py: Louvain community partitioning and criminal syndicate detection.
"""

import pytest
from network.communities import (
    detect_communities_louvain,
    find_cross_community_brokers,
    get_inter_community_links,
)
from network.graph_store import CrimeNetworkGraph, EntityType


def test_empty_graph_community_detection() -> None:
    empty_g = CrimeNetworkGraph(name="Empty")
    report = detect_communities_louvain(empty_g)
    assert report.num_communities == 0
    assert report.modularity == 0.0
    assert report.communities == []


def test_two_distinct_criminal_cliques() -> None:
    """
    Two isolated 3-cliques: Cell A (A1, A2, A3) and Cell B (B1, B2, B3)
    connected by a single weak cross-edge (A3 -> B1).
    """
    g = CrimeNetworkGraph(name="TwoCliques")

    # Clique 1
    for nid in ["A1", "A2", "A3"]:
        g.add_node(nid, entity_type=EntityType.SUSPECT)
    g.add_edge(("A1", "A2"), weight=5.0)
    g.add_edge(("A2", "A1"), weight=5.0)
    g.add_edge(("A2", "A3"), weight=5.0)
    g.add_edge(("A3", "A2"), weight=5.0)
    g.add_edge(("A1", "A3"), weight=5.0)
    g.add_edge(("A3", "A1"), weight=5.0)

    # Clique 2
    for nid in ["B1", "B2", "B3"]:
        g.add_node(nid, entity_type=EntityType.ORGANIZATION)
    g.add_edge(("B1", "B2"), weight=5.0)
    g.add_edge(("B2", "B1"), weight=5.0)
    g.add_edge(("B2", "B3"), weight=5.0)
    g.add_edge(("B3", "B2"), weight=5.0)
    g.add_edge(("B1", "B3"), weight=5.0)
    g.add_edge(("B3", "B1"), weight=5.0)

    # Single cross-cell link
    g.add_edge(("A3", "B1"), weight=1.0, amount=15000.0)

    report = detect_communities_louvain(g, seed=42)
    assert report.num_communities == 2
    assert report.modularity > 0.3  # Strong modular separation

    # Verify members
    comm0 = set(report.communities[0].members)
    comm1 = set(report.communities[1].members)
    assert (comm0 == {"A1", "A2", "A3"} and comm1 == {"B1", "B2", "B3"}) or \
           (comm0 == {"B1", "B2", "B3"} and comm1 == {"A1", "A2", "A3"})

    # Check cell internal density and distribution
    for cell in report.communities:
        assert cell.internal_density == 1.0
        assert len(cell.leaders) > 0

    # Test inter-community links
    bridges = get_inter_community_links(g, report.partition_map)
    assert len(bridges) == 1
    assert bridges[0]["source"] == "A3"
    assert bridges[0]["target"] == "B1"
    assert bridges[0]["amount"] == 15000.0

    # Test cross-community brokers
    cross_brokers = find_cross_community_brokers(g, report.partition_map)
    broker_ids = {b["node_id"] for b in cross_brokers}
    assert "A3" in broker_ids or "B1" in broker_ids


def test_disconnected_graph_communities() -> None:
    g = CrimeNetworkGraph(name="Disconnected")
    g.add_node("X1")
    g.add_node("X2")
    g.add_node("Y1")
    g.add_node("Y2")
    g.add_edge(("X1", "X2"))
    g.add_edge(("Y1", "Y2"))

    report = detect_communities_louvain(g)
    assert report.num_communities == 2


def test_cross_community_broker_no_cross_links() -> None:
    g = CrimeNetworkGraph(name="PureIsolated")
    g.add_edge(("A", "B"))
    partition = {"A": 0, "B": 0}
    brokers = find_cross_community_brokers(g, partition)
    assert len(brokers) == 0
