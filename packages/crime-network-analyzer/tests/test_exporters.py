"""
Unit tests for exporters.py: GEXF, GraphML, and JSON schema compliance and integrity.
"""

import json
from pathlib import Path
import defusedxml.ElementTree as ET
import pytest

from network.centrality import calculate_all_centralities
from network.communities import detect_communities_louvain
from network.exporters import export_to_gexf, export_to_graphml, export_to_json, safe_xml_escape
from network.graph_store import CrimeNetworkGraph, EntityType, RelationType


def test_safe_xml_escape() -> None:
    raw = 'Hello <world> & "goodbye" \'test\''
    escaped = safe_xml_escape(raw)
    assert "<" not in escaped
    assert ">" not in escaped
    assert "&quot;" in escaped
    assert "&apos;" in escaped
    assert "&amp;" in escaped

    # None handling
    assert safe_xml_escape(None) == ""


def test_gexf_export(tmp_path: Path) -> None:
    g = CrimeNetworkGraph(name="GEXF_Test")
    g.add_node("N1", entity_type=EntityType.SUSPECT, label="Suspect Alpha", risk_score=0.85)
    g.add_node("N2", entity_type=EntityType.BANK_ACCOUNT, label="ACC-9921", risk_score=0.4)
    g.add_edge(("N1", "N2"), relation_type=RelationType.OWNS, amount=50000.0, timestamp="2026-08-27T10:00:00Z")

    cent_report = calculate_all_centralities(g)
    comm_report = detect_communities_louvain(g)

    out_file = tmp_path / "network.gexf"
    xml_str = export_to_gexf(g, filepath=out_file, centralities=cent_report, communities=comm_report)

    assert out_file.exists()
    assert len(xml_str) > 0

    # Parse and validate XML syntax
    root = ET.fromstring(xml_str)
    assert root.tag.endswith("gexf")
    assert root.attrib.get("version") == "1.2"

    # Find nodes and edges
    nodes = list(root.iter("{http://www.gexf.net/1.2draft}node"))
    edges = list(root.iter("{http://www.gexf.net/1.2draft}edge"))
    assert len(nodes) == 2
    assert len(edges) == 1


def test_graphml_export(tmp_path: Path) -> None:
    g = CrimeNetworkGraph(name="GraphML_Test")
    g.add_node("P1", entity_type=EntityType.PHONE, label="+1-555-0100")
    g.add_node("P2", entity_type=EntityType.PHONE, label="+1-555-0200")
    g.add_edge(("P1", "P2"), relation_type=RelationType.CALL, weight=12.0)

    out_file = tmp_path / "network.graphml"
    xml_str = export_to_graphml(g, filepath=out_file)

    assert out_file.exists()
    root = ET.fromstring(xml_str)
    assert root.tag.endswith("graphml")

    nodes = list(root.iter("{http://graphml.graphdrawing.org/xmlns}node"))
    assert len(nodes) == 2


def test_json_export(tmp_path: Path) -> None:
    g = CrimeNetworkGraph(name="JSON_Test")
    g.add_node("S1", entity_type=EntityType.SUSPECT, label="Subject 1")
    g.add_node("S2", entity_type=EntityType.SUSPECT, label="Subject 2")
    g.add_edge(("S1", "S2"), relation_type=RelationType.ASSOCIATE_WITH)

    out_file = tmp_path / "network.json"
    json_str = export_to_json(g, filepath=out_file)

    assert out_file.exists()
    data = json.loads(json_str)
    assert data["name"] == "JSON_Test"
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1


def test_graphml_export_with_pii_redaction() -> None:
    g = CrimeNetworkGraph(name="RedactedGraphML")
    g.add_node("P1", entity_type=EntityType.PHONE, label="+34612345678")
    xml_str = export_to_graphml(g, redact_pii=True)
    assert "+34612345678" not in xml_str
    assert "[PHONE-***5678]" in xml_str


def test_json_export_without_filepath() -> None:
    g = CrimeNetworkGraph(name="MemoryOnly")
    g.add_node("A")
    json_str = export_to_json(g)
    data = json.loads(json_str)
    assert data["name"] == "MemoryOnly"
    assert len(data["nodes"]) == 1
