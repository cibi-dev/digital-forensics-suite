"""
Unit tests for graph_store.py: Node/Edge modeling, graph operations, bipartite projections, CSV/JSON I/O.
"""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from network.graph_store import (
    CrimeNetworkGraph,
    EdgeData,
    EntityType,
    NodeData,
    RelationType,
    mask_pii_value,
)


def test_node_creation_and_validation() -> None:
    # Valid node model
    node = NodeData(id="SUSPECT_01", entity_type=EntityType.SUSPECT, label="Boss", risk_score=0.9)
    assert node.id == "SUSPECT_01"
    assert node.entity_type == EntityType.SUSPECT
    assert node.display_label == "Boss"
    assert node.risk_score == 0.9

    # Default fallback
    node_default = NodeData(id="PHONE_01")
    assert node_default.entity_type == EntityType.SUSPECT
    assert node_default.display_label == "PHONE_01"

    # Validation errors
    with pytest.raises(ValidationError):
        NodeData(id="")

    with pytest.raises(ValidationError):
        NodeData(id="   ")

    with pytest.raises(ValidationError):
        NodeData(id="VALID", risk_score=1.5)  # > 1.0


def test_edge_creation_and_validation() -> None:
    # Valid edge model
    edge = EdgeData(
        source="ACC_01",
        target="ACC_02",
        relation_type=RelationType.TRANSACTION,
        weight=2.5,
        amount=50000.0,
    )
    assert edge.source == "ACC_01"
    assert edge.target == "ACC_02"
    assert edge.amount == 50000.0

    # Validation errors
    with pytest.raises(ValidationError):
        EdgeData(source="", target="B")

    with pytest.raises(ValidationError):
        EdgeData(source="A", target="B", weight=-1.0)

    with pytest.raises(ValidationError):
        EdgeData(source="A", target="B", amount=-100.0)


def test_enum_fallback_and_normalization() -> None:
    assert EntityType("suspect") == EntityType.SUSPECT
    assert EntityType("bank-account") == EntityType.BANK_ACCOUNT
    assert EntityType("unknown_custom") == EntityType.OTHER

    assert RelationType("transaction") == RelationType.TRANSACTION
    assert RelationType("associate-with") == RelationType.ASSOCIATE_WITH
    assert RelationType("random_relation") == RelationType.OTHER


def test_graph_add_nodes_and_edges() -> None:
    graph = CrimeNetworkGraph(name="TestNet")
    
    # Add nodes in various formats
    nid1 = graph.add_node("S1", entity_type=EntityType.SUSPECT, label="Suspect 1", risk_score=0.8)
    nid2 = graph.add_node({"id": "S2", "entity_type": "PERSON", "risk_score": 0.4})
    nid3 = graph.add_node(NodeData(id="S3", entity_type=EntityType.PHONE, label="+123456"))

    assert graph.num_nodes == 3
    assert graph.has_node("S1")
    assert graph.has_node("S2")
    assert graph.has_node("S3")
    assert not graph.has_node("NON_EXISTENT")

    # Add edges
    e1 = graph.add_edge(("S1", "S2"), relation_type=RelationType.CALL, weight=3.0)
    e2 = graph.add_edge({"source": "S2", "target": "S3", "relation_type": "OWNS", "weight": 1.0})
    e3 = graph.add_edge(EdgeData(source="S3", target="S1", relation_type=RelationType.TRANSACTION, amount=1200.0))

    assert graph.num_edges == 3
    assert graph.has_edge("S1", "S2")
    assert graph.has_edge("S2", "S3")
    assert graph.has_edge("S3", "S1")
    assert not graph.has_edge("S1", "S3")

    node_s1 = graph.get_node("S1")
    assert node_s1 is not None
    assert node_s1["entity_type"] == "SUSPECT"
    assert node_s1["risk_score"] == 0.8

    edge_s3_s1 = graph.get_edge("S3", "S1")
    assert edge_s3_s1 is not None
    assert edge_s3_s1["amount"] == 1200.0

    assert graph.get_node("UNKNOWN") is None
    assert graph.get_edge("A", "Z") is None


def test_batch_addition() -> None:
    graph = CrimeNetworkGraph()
    graph.add_nodes_from(["N1", "N2", "N3"])
    graph.add_edges_from([("N1", "N2"), ("N2", "N3")])
    assert graph.num_nodes == 3
    assert graph.num_edges == 2


def test_subgraphs_and_ego() -> None:
    graph = CrimeNetworkGraph()
    graph.add_node("P1", entity_type=EntityType.PERSON)
    graph.add_node("P2", entity_type=EntityType.PERSON)
    graph.add_node("PH1", entity_type=EntityType.PHONE)
    graph.add_node("ACC1", entity_type=EntityType.BANK_ACCOUNT)

    graph.add_edge(("P1", "PH1"), relation_type=RelationType.OWNS)
    graph.add_edge(("P2", "PH1"), relation_type=RelationType.CALL)
    graph.add_edge(("P1", "ACC1"), relation_type=RelationType.OWNS)

    # Subgraph by entity type
    person_graph = graph.subgraph_by_entity_types([EntityType.PERSON])
    assert person_graph.num_nodes == 2
    assert "PH1" not in person_graph.nodes

    # Subgraph by relation type
    call_graph = graph.subgraph_by_relation_types([RelationType.CALL])
    assert call_graph.num_edges == 1
    assert call_graph.has_edge("P2", "PH1")

    # Ego network
    ego = graph.extract_ego_graph("P1", radius=1)
    assert ego.has_node("P1")
    assert ego.has_node("PH1")
    assert ego.has_node("ACC1")
    assert not ego.has_node("P2")

    with pytest.raises(KeyError):
        graph.extract_ego_graph("NON_EXISTENT")


def test_bipartite_detection_and_projection() -> None:
    graph = CrimeNetworkGraph()
    # Bipartite topology: Suspects (S1, S2, S3) <-> Phones (P1, P2)
    graph.add_node("S1", entity_type=EntityType.SUSPECT)
    graph.add_node("S2", entity_type=EntityType.SUSPECT)
    graph.add_node("S3", entity_type=EntityType.SUSPECT)

    graph.add_node("P1", entity_type=EntityType.PHONE)
    graph.add_node("P2", entity_type=EntityType.PHONE)

    graph.add_edge(("S1", "P1"), relation_type=RelationType.CALL)
    graph.add_edge(("S2", "P1"), relation_type=RelationType.CALL)
    graph.add_edge(("S2", "P2"), relation_type=RelationType.CALL)
    graph.add_edge(("S3", "P2"), relation_type=RelationType.CALL)

    # Check bipartite
    assert graph.is_bipartite([EntityType.SUSPECT], [EntityType.PHONE])

    # Add a cross edge breaking bipartiteness
    graph.add_edge(("S1", "S2"), relation_type=RelationType.ASSOCIATE_WITH)
    assert not graph.is_bipartite([EntityType.SUSPECT], [EntityType.PHONE])

    # Re-test projection on clean bipartite
    clean_graph = CrimeNetworkGraph()
    clean_graph.add_node("S1", entity_type=EntityType.SUSPECT)
    clean_graph.add_node("S2", entity_type=EntityType.SUSPECT)
    clean_graph.add_node("P1", entity_type=EntityType.PHONE)
    clean_graph.add_edge(("S1", "P1"))
    clean_graph.add_edge(("S2", "P1"))

    projected = clean_graph.project_bipartite(nodes_to_keep=[EntityType.SUSPECT])
    assert projected.has_node("S1")
    assert projected.has_node("S2")
    assert projected.has_edge("S1", "S2")
    assert projected.get_edge("S1", "S2")["weight"] == 1.0


def test_json_and_csv_io(tmp_path: Path) -> None:
    graph = CrimeNetworkGraph(name="SerialTest")
    graph.add_node("A", entity_type=EntityType.SUSPECT, label="Alice", risk_score=0.7)
    graph.add_node("B", entity_type=EntityType.BANK_ACCOUNT, label="ES9121000418450200051332")
    graph.add_edge(("A", "B"), relation_type=RelationType.OWNS, amount=10000.0)

    # JSON Serialization & Deserialization
    json_file = tmp_path / "graph.json"
    data = graph.to_dict()
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    loaded_graph = CrimeNetworkGraph.from_json(json_file)
    assert loaded_graph.num_nodes == 2
    assert loaded_graph.num_edges == 1
    assert loaded_graph.get_node("A")["risk_score"] == 0.7

    # CSV Serialization & Parsing
    nodes_csv = tmp_path / "nodes.csv"
    edges_csv = tmp_path / "edges.csv"

    nodes_csv.write_text("id,entity_type,label,risk_score\nC,SUSPECT,Charlie,0.5\nD,PHONE,+34612345678,0.2\n")
    edges_csv.write_text("source,target,relation_type,weight,amount\nC,D,CALL,1.0,0.0\n")

    csv_graph = CrimeNetworkGraph.from_csv(nodes_csv, edges_csv, name="CSVLoaded")
    assert csv_graph.num_nodes == 2
    assert csv_graph.num_edges == 1
    assert csv_graph.has_edge("C", "D")


def test_from_dict_and_to_dict_roundtrip() -> None:
    g = CrimeNetworkGraph(name="Roundtrip")
    g.add_node("U1", entity_type=EntityType.SUSPECT, label="User 1", risk_score=0.3)
    g.add_node("U2", entity_type=EntityType.PHONE, label="+12345", risk_score=0.1)
    g.add_edge(("U1", "U2"), relation_type=RelationType.OWNS, weight=2.0)

    d = g.to_dict()
    reconstructed = CrimeNetworkGraph.from_dict(d)
    assert reconstructed.name == "Roundtrip"
    assert reconstructed.num_nodes == 2
    assert reconstructed.num_edges == 1
    assert reconstructed.has_edge("U1", "U2")
    assert reconstructed.get_edge("U1", "U2")["weight"] == 2.0


def test_to_undirected_view() -> None:
    g = CrimeNetworkGraph(name="Directed")
    g.add_edge(("A", "B"))
    undirected = g.to_undirected()
    assert undirected.has_edge("A", "B")
    assert undirected.has_edge("B", "A")


def test_invalid_edge_format_raises() -> None:
    g = CrimeNetworkGraph()
    with pytest.raises(ValueError):
        g.add_edge(123)  # type: ignore


def test_project_bipartite_custom_node_ids() -> None:
    g = CrimeNetworkGraph()
    g.add_node("S1")
    g.add_node("S2")
    g.add_node("A1")
    g.add_edge(("S1", "A1"))
    g.add_edge(("S2", "A1"))

    projected = g.project_bipartite(nodes_to_keep=["S1", "S2"])
    assert projected.has_edge("S1", "S2")
