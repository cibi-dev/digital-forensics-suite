"""
Security tests for DevSecOps guardrails: CWE-209 (PII sanitization),
CWE-91/CWE-611 (XML Injection / XXE defense), and CWE-400 (Memory & recursion bounds).
"""

import time
from pathlib import Path
import defusedxml.ElementTree as ET
import networkx as nx
import pytest

from network.exporters import export_to_gexf, export_to_graphml, export_to_json, safe_xml_escape
from network.fraud_rings import FraudRingDetector
from network.graph_store import CrimeNetworkGraph, EntityType, mask_pii_value


def test_cwe_209_pii_masking_primitives() -> None:
    # Phone numbers
    assert mask_pii_value("+34 612 345 678", pii_type="phone") == "[PHONE-***5678]"
    assert mask_pii_value("+1-555-0199", pii_type="phone") == "[PHONE-***0199]"

    # IBAN / Bank accounts
    assert mask_pii_value("ES9121000418450200051332", pii_type="bank_account") == "ES91****1332"
    assert mask_pii_value("1234567890", pii_type="account") == "1234****7890"

    # IP addresses
    assert mask_pii_value("192.168.1.100", pii_type="ip") == "192.168.*.*"
    assert mask_pii_value("10.0.0.1", pii_type="ip") == "10.0.*.*"

    # General Names
    assert mask_pii_value("John Doe", pii_type="general") == "J*** D***"
    assert mask_pii_value("Al", pii_type="general") == "***"
    assert mask_pii_value("Alexander", pii_type="general") == "A***r"

    # Edge cases
    assert mask_pii_value(None) == "[REDACTED]"
    assert mask_pii_value("") == "[REDACTED]"


def test_cwe_209_graph_level_pii_redaction() -> None:
    g = CrimeNetworkGraph(name="SecretInvestigation")
    g.add_node("S1", entity_type=EntityType.PERSON, label="John Doe", attributes={"phone": "+34612345678", "ip": "192.168.1.50"})
    g.add_node("ACC1", entity_type=EntityType.BANK_ACCOUNT, label="ES9121000418450200051332")
    g.add_edge(("S1", "ACC1"), amount=25000.0)

    # Redact graph
    redacted_g = g.redact_pii()

    s1_data = redacted_g.get_node("S1")
    assert s1_data is not None
    assert s1_data["label"] == "J*** D***"
    assert s1_data["phone"] == "[PHONE-***5678]"
    assert s1_data["ip"] == "192.168.*.*"

    acc_data = redacted_g.get_node("ACC1")
    assert acc_data is not None
    assert acc_data["label"] == "ES91****1332"

    # Export with redact_pii=True
    json_out = export_to_json(g, redact_pii=True)
    assert "John Doe" not in json_out
    assert "ES9121000418450200051332" not in json_out
    assert "J*** D***" in json_out

    gexf_out = export_to_gexf(g, redact_pii=True)
    assert "John Doe" not in gexf_out


def test_cwe_91_xml_injection_defense_gexf_and_graphml() -> None:
    """
    Ensure malicious XML payloads in labels and IDs are escaped safely
    and do not compromise the XML structure or cause injection.
    """
    malicious_payloads = [
        '<script>alert("PWNED")</script>',
        '"><injected_node evil="true"/>',
        "&entity_test;",
        "<!-- Comment injection -->",
        ']]><![CDATA[evil]]>',
    ]

    g = CrimeNetworkGraph(name="MaliciousPayloadTest")
    for i, payload in enumerate(malicious_payloads):
        nid = f"MAL_{i}"
        g.add_node(nid, label=payload, entity_type=EntityType.SUSPECT, attributes={"custom": payload})
        g.add_edge((nid, "MAL_0"), amount=100.0)

    # 1. GEXF Export verification
    gexf_xml = export_to_gexf(g)
    # Must parse successfully as standard XML
    root_gexf = ET.fromstring(gexf_xml)
    assert root_gexf is not None

    # Verify no unescaped tags exist in XML text
    assert "<injected_node" not in gexf_xml
    assert "<script>" not in gexf_xml

    # 2. GraphML Export verification
    graphml_xml = export_to_graphml(g)
    root_graphml = ET.fromstring(graphml_xml)
    assert root_graphml is not None
    assert "<injected_node" not in graphml_xml


def test_cwe_400_bounded_recursion_and_memory() -> None:
    """
    Stress test on a complete graph K_10 (10 nodes, 90 directed edges)
    which contains thousands of cycles.
    The cycle finder must strictly obey max_cycles and max_length quotas.
    """
    k10_nx = nx.complete_graph(10, create_using=nx.DiGraph)
    cg = CrimeNetworkGraph(name="K10_Dense")
    for u, v in k10_nx.edges():
        cg.add_edge((str(u), str(v)), amount=50.0)

    detector = FraudRingDetector(cg)

    # Impose max_cycles=25 and max_length=4
    t0 = time.perf_counter()
    rings = detector.find_circular_transfers(min_length=3, max_length=4, max_cycles=25)
    elapsed = time.perf_counter() - t0

    assert len(rings) <= 25
    assert elapsed < 0.5  # Sub-second execution guaranteed by bound
    for r in rings:
        assert 3 <= r.cycle_length <= 4
