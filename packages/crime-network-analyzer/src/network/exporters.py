"""
exporters.py - Safe Graph & Forensic Export Formats (GEXF, GraphML, JSON).

Provides secure export to GEXF for Gephi, GraphML, and JSON with strict XML
entity escaping to prevent XML Injection (CWE-91) and PII redaction (CWE-209).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Sequence
from xml.sax.saxutils import escape, quoteattr

from network.centrality import CentralityReport
from network.communities import CommunityReport
from network.graph_store import CrimeNetworkGraph, EntityType, mask_pii_value


def safe_xml_escape(val: Any) -> str:
    """
    Strictly escapes characters for XML attributes and text elements (CWE-91 defense).
    Handles &, <, >, ", ', and control characters.
    """
    if val is None:
        return ""
    text = str(val)
    # xml.sax.saxutils.escape escapes &, <, >
    escaped = escape(text, entities={'"': "&quot;", "'": "&apos;"})
    # Remove unsafe control characters (excluding newline, cr, tab)
    clean_chars = [c for c in escaped if ord(c) in (0x9, 0xA, 0xD) or ord(c) >= 0x20]
    return "".join(clean_chars)


def export_to_gexf(
    graph: CrimeNetworkGraph,
    filepath: str | Path | None = None,
    centralities: CentralityReport | None = None,
    communities: CommunityReport | None = None,
    redact_pii: bool = False,
) -> str:
    """
    Exports CrimeNetworkGraph to valid GEXF 1.2 format compatible with Gephi.
    Implements XML injection defense and optional PII redaction.
    """
    g = graph.raw_graph
    eval_graph = graph.redact_pii() if redact_pii else graph
    raw_eval = eval_graph.raw_graph

    # Root XML node
    gexf = ET.Element(
        "gexf",
        {
            "xmlns": "http://www.gexf.net/1.2draft",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": "http://www.gexf.net/1.2draft http://www.gexf.net/1.2draft/gexf.xsd",
            "version": "1.2",
        },
    )

    # Meta
    meta = ET.SubElement(gexf, "meta", {"lastmodifieddate": "2026-08-27"})
    creator = ET.SubElement(meta, "creator")
    creator.text = "crime-network-analyzer"
    description = ET.SubElement(meta, "description")
    description.text = safe_xml_escape(f"Forensic Network: {graph.name}")

    # Graph
    graph_elem = ET.SubElement(gexf, "graph", {"defaultedgetype": "directed", "mode": "static"})

    # Node Attributes Definition
    node_attributes = ET.SubElement(graph_elem, "attributes", {"class": "node", "mode": "static"})
    node_attr_defs = [
        ("0", "entity_type", "string"),
        ("1", "risk_score", "float"),
        ("2", "betweenness", "float"),
        ("3", "pagerank", "float"),
        ("4", "community_id", "integer"),
        ("5", "in_degree", "float"),
        ("6", "out_degree", "float"),
    ]
    for attr_id, title, attr_type in node_attr_defs:
        ET.SubElement(node_attributes, "attribute", {"id": attr_id, "title": title, "type": attr_type})

    # Edge Attributes Definition
    edge_attributes = ET.SubElement(graph_elem, "attributes", {"class": "edge", "mode": "static"})
    edge_attr_defs = [
        ("0", "relation_type", "string"),
        ("1", "amount", "float"),
        ("2", "timestamp", "string"),
    ]
    for attr_id, title, attr_type in edge_attr_defs:
        ET.SubElement(edge_attributes, "attribute", {"id": attr_id, "title": title, "type": attr_type})

    # Nodes
    nodes_elem = ET.SubElement(graph_elem, "nodes")
    for nid, data in raw_eval.nodes(data=True):
        label_val = str(data.get("label", nid))
        node_xml = ET.SubElement(nodes_elem, "node", {"id": safe_xml_escape(nid), "label": safe_xml_escape(label_val)})
        attvalues = ET.SubElement(node_xml, "attvalues")

        # Basic attributes
        ET.SubElement(attvalues, "attvalue", {"for": "0", "value": safe_xml_escape(data.get("entity_type", "SUSPECT"))})
        ET.SubElement(attvalues, "attvalue", {"for": "1", "value": str(data.get("risk_score", 0.0))})

        # Centralities if provided
        if centralities and nid in centralities.nodes:
            cdata = centralities.nodes[nid]
            ET.SubElement(attvalues, "attvalue", {"for": "2", "value": str(round(cdata.betweenness, 6))})
            ET.SubElement(attvalues, "attvalue", {"for": "3", "value": str(round(cdata.pagerank, 6))})
            ET.SubElement(attvalues, "attvalue", {"for": "5", "value": str(cdata.in_degree)})
            ET.SubElement(attvalues, "attvalue", {"for": "6", "value": str(cdata.out_degree)})

        # Community if provided
        if communities and nid in communities.partition_map:
            ET.SubElement(attvalues, "attvalue", {"for": "4", "value": str(communities.partition_map[nid])})

    # Edges
    edges_elem = ET.SubElement(graph_elem, "edges")
    for idx, (u, v, data) in enumerate(raw_eval.edges(data=True)):
        weight_val = str(data.get("weight", 1.0))
        edge_xml = ET.SubElement(
            edges_elem,
            "edge",
            {
                "id": f"e{idx}",
                "source": safe_xml_escape(u),
                "target": safe_xml_escape(v),
                "weight": weight_val,
            },
        )
        attvalues = ET.SubElement(edge_xml, "attvalues")
        ET.SubElement(attvalues, "attvalue", {"for": "0", "value": safe_xml_escape(data.get("relation_type", "TRANSACTION"))})
        if data.get("amount") is not None:
            ET.SubElement(attvalues, "attvalue", {"for": "1", "value": str(data["amount"])})
        if data.get("timestamp") is not None:
            ET.SubElement(attvalues, "attvalue", {"for": "2", "value": safe_xml_escape(data["timestamp"])})

    xml_str = ET.tostring(gexf, encoding="utf-8", xml_declaration=True).decode("utf-8")

    if filepath is not None:
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(xml_str)

    return xml_str


def export_to_graphml(
    graph: CrimeNetworkGraph,
    filepath: str | Path | None = None,
    redact_pii: bool = False,
) -> str:
    """
    Exports CrimeNetworkGraph to safe GraphML format with XML injection prevention.
    """
    eval_graph = graph.redact_pii() if redact_pii else graph
    raw_eval = eval_graph.raw_graph

    graphml = ET.Element("graphml", {"xmlns": "http://graphml.graphdrawing.org/xmlns"})

    # Keys
    ET.SubElement(graphml, "key", {"id": "d0", "for": "node", "attr.name": "entity_type", "attr.type": "string"})
    ET.SubElement(graphml, "key", {"id": "d1", "for": "node", "attr.name": "label", "attr.type": "string"})
    ET.SubElement(graphml, "key", {"id": "d2", "for": "node", "attr.name": "risk_score", "attr.type": "double"})
    ET.SubElement(graphml, "key", {"id": "d3", "for": "edge", "attr.name": "relation_type", "attr.type": "string"})
    ET.SubElement(graphml, "key", {"id": "d4", "for": "edge", "attr.name": "weight", "attr.type": "double"})
    ET.SubElement(graphml, "key", {"id": "d5", "for": "edge", "attr.name": "amount", "attr.type": "double"})

    g_elem = ET.SubElement(graphml, "graph", {"id": safe_xml_escape(graph.name), "edgedefault": "directed"})

    for nid, data in raw_eval.nodes(data=True):
        node_el = ET.SubElement(g_elem, "node", {"id": safe_xml_escape(nid)})
        d0 = ET.SubElement(node_el, "data", {"key": "d0"})
        d0.text = safe_xml_escape(data.get("entity_type", "SUSPECT"))
        d1 = ET.SubElement(node_el, "data", {"key": "d1"})
        d1.text = safe_xml_escape(data.get("label", nid))
        d2 = ET.SubElement(node_el, "data", {"key": "d2"})
        d2.text = str(data.get("risk_score", 0.0))

    for idx, (u, v, data) in enumerate(raw_eval.edges(data=True)):
        edge_el = ET.SubElement(g_elem, "edge", {"id": f"e{idx}", "source": safe_xml_escape(u), "target": safe_xml_escape(v)})
        d3 = ET.SubElement(edge_el, "data", {"key": "d3"})
        d3.text = safe_xml_escape(data.get("relation_type", "TRANSACTION"))
        d4 = ET.SubElement(edge_el, "data", {"key": "d4"})
        d4.text = str(data.get("weight", 1.0))
        if data.get("amount") is not None:
            d5 = ET.SubElement(edge_el, "data", {"key": "d5"})
            d5.text = str(data["amount"])

    xml_str = ET.tostring(graphml, encoding="utf-8", xml_declaration=True).decode("utf-8")

    if filepath is not None:
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(xml_str)

    return xml_str


def export_to_json(
    graph: CrimeNetworkGraph,
    filepath: str | Path | None = None,
    format_type: str = "node_link",
    redact_pii: bool = False,
) -> str:
    """
    Exports CrimeNetworkGraph to JSON with optional PII redaction.
    """
    eval_graph = graph.redact_pii() if redact_pii else graph
    data = eval_graph.to_dict()
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if filepath is not None:
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str
