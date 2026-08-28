"""
Unit tests for centrality.py: Exact betweenness, PageRank, and composite risk metrics.
"""

import pytest
from network.centrality import (
    calculate_all_centralities,
    calculate_betweenness_centrality,
    calculate_closeness_centrality,
    calculate_degree_centrality,
    calculate_pagerank,
    identify_kingpins_and_brokers,
)
from network.graph_store import CrimeNetworkGraph, EntityType


def test_empty_and_trivial_graph_centrality() -> None:
    empty_g = CrimeNetworkGraph(name="Empty")
    report = calculate_all_centralities(empty_g)
    assert report.total_nodes == 0
    assert report.top_influencers == []

    deg = calculate_degree_centrality(empty_g)
    assert deg == {}

    bc = calculate_betweenness_centrality(empty_g)
    assert bc == {}

    pr = calculate_pagerank(empty_g)
    assert pr == {}

    single_g = CrimeNetworkGraph(name="Single")
    single_g.add_node("A")
    report_single = calculate_all_centralities(single_g)
    assert report_single.total_nodes == 1
    assert "A" in report_single.nodes
    assert report_single.nodes["A"].betweenness == 0.0


def test_bridge_and_broker_betweenness() -> None:
    """
    Construct a bowtie/bridge graph:
    Group 1: (A, B) connected to Broker C
    Group 2: (D, E) connected to Broker C
    Broker C should have the highest betweenness centrality.
    """
    g = CrimeNetworkGraph(name="Bowtie")
    for nid in ["A", "B", "C", "D", "E"]:
        g.add_node(nid, entity_type=EntityType.SUSPECT)

    # Undirected bidirectional edges
    edges = [
        ("A", "B"), ("B", "A"),
        ("A", "C"), ("C", "A"),
        ("B", "C"), ("C", "B"),
        ("C", "D"), ("D", "C"),
        ("C", "E"), ("E", "C"),
        ("D", "E"), ("E", "D"),
    ]
    for u, v in edges:
        g.add_edge((u, v))

    bc = calculate_betweenness_centrality(g)
    # C is the sole bridge between triangle ABC and triangle CDE
    assert bc["C"] > bc["A"]
    assert bc["C"] > bc["B"]
    assert bc["C"] > bc["D"]
    assert bc["C"] > bc["E"]


def test_star_graph_pagerank_and_degree() -> None:
    """
    Directed Star graph where 4 peripheral nodes point to central leader (Boss).
    """
    g = CrimeNetworkGraph(name="DirectedStar")
    g.add_node("Boss", entity_type=EntityType.SUSPECT, risk_score=1.0)
    for i in range(1, 5):
        worker = f"Worker_{i}"
        g.add_node(worker, entity_type=EntityType.SUSPECT, risk_score=0.2)
        g.add_edge((worker, "Boss"), amount=5000.0)

    deg = calculate_degree_centrality(g)
    assert deg["Boss"]["in_degree"] == 1.0  # Normalized: 4 / 4 = 1.0
    assert deg["Boss"]["out_degree"] == 0.0
    assert deg["Worker_1"]["in_degree"] == 0.0
    assert deg["Worker_1"]["out_degree"] == 0.25

    pr = calculate_pagerank(g, alpha=0.85)
    # Boss must have strictly highest PageRank
    assert pr["Boss"] > pr["Worker_1"]
    assert pr["Boss"] > pr["Worker_2"]


def test_closeness_centrality() -> None:
    # Line graph: A -> B -> C -> D
    g = CrimeNetworkGraph(name="Line")
    for nid in ["A", "B", "C", "D"]:
        g.add_node(nid)
    g.add_edge(("A", "B"))
    g.add_edge(("B", "C"))
    g.add_edge(("C", "D"))

    cc = calculate_closeness_centrality(g)
    assert len(cc) == 4
    # In directed NetworkX closeness, incoming paths to D from A, B, C mean cc["D"] > cc["A"]
    assert cc["D"] > cc["A"]


def test_composite_risk_and_role_identification() -> None:
    g = CrimeNetworkGraph(name="CrimeSyndicate")
    g.add_node("Kingpin", entity_type=EntityType.SUSPECT, risk_score=0.9)
    g.add_node("Broker", entity_type=EntityType.PERSON, risk_score=0.7)
    g.add_node("Operative1", entity_type=EntityType.SUSPECT, risk_score=0.3)
    g.add_node("Operative2", entity_type=EntityType.SUSPECT, risk_score=0.3)

    g.add_edge(("Operative1", "Broker"), amount=1000.0)
    g.add_edge(("Operative2", "Broker"), amount=2000.0)
    g.add_edge(("Broker", "Kingpin"), amount=3000.0)

    report = calculate_all_centralities(g, top_k=2)
    assert report.total_nodes == 4
    assert len(report.top_influencers) <= 2
    assert len(report.top_brokers) <= 2

    roles = identify_kingpins_and_brokers(report, top_k=2)
    assert "kingpins" in roles
    assert "brokers" in roles
    assert "hubs" in roles

    # Node data fields check
    kingpin_data = report.nodes["Kingpin"]
    assert kingpin_data.composite_risk >= 0.0
    assert kingpin_data.composite_risk <= 1.0


def test_pagerank_with_no_edges() -> None:
    g = CrimeNetworkGraph(name="NoEdges")
    g.add_node("N1")
    g.add_node("N2")
    pr = calculate_pagerank(g)
    assert pr["N1"] == 0.5
    assert pr["N2"] == 0.5


def test_centrality_top_hubs() -> None:
    g = CrimeNetworkGraph(name="HubTest")
    g.add_node("Hub")
    for i in range(5):
        spoke = f"Spoke_{i}"
        g.add_edge(("Hub", spoke))
    
    report = calculate_all_centralities(g, top_k=1)
    assert report.top_hubs[0] == "Hub"
