"""
Unit tests for fraud_rings.py: AML circular transfer rings, smurfing, and mule accounts.
"""

import pytest
from network.fraud_rings import FraudRingDetector
from network.graph_store import CrimeNetworkGraph, EntityType, RelationType


def test_no_fraud_on_empty_or_dag() -> None:
    empty_g = CrimeNetworkGraph(name="Empty")
    detector = FraudRingDetector(empty_g)
    report = detector.detect_all()
    assert report.total_cycles_detected == 0
    assert report.mule_accounts == []
    assert report.smurfing_patterns == []
    assert report.suspicious_volume_total == 0.0

    # Directed Acyclic Graph (DAG)
    dag = CrimeNetworkGraph(name="DAG")
    dag.add_edge(("A", "B"), amount=100.0)
    dag.add_edge(("B", "C"), amount=100.0)
    dag.add_edge(("A", "C"), amount=50.0)
    det_dag = FraudRingDetector(dag)
    rings = det_dag.find_circular_transfers()
    assert len(rings) == 0


def test_circular_transfer_ring_k3_k4() -> None:
    """
    Construct a 3-node cycle: ACC_1 -> ACC_2 -> ACC_3 -> ACC_1
    and a 4-node cycle: ACC_A -> ACC_B -> ACC_C -> ACC_D -> ACC_A
    """
    g = CrimeNetworkGraph(name="CircularFraud")

    # 3-cycle
    g.add_node("ACC_1", entity_type=EntityType.BANK_ACCOUNT)
    g.add_node("ACC_2", entity_type=EntityType.BANK_ACCOUNT)
    g.add_node("ACC_3", entity_type=EntityType.BANK_ACCOUNT)

    g.add_edge(("ACC_1", "ACC_2"), relation_type=RelationType.TRANSACTION, amount=10000.0)
    g.add_edge(("ACC_2", "ACC_3"), relation_type=RelationType.TRANSACTION, amount=9800.0)
    g.add_edge(("ACC_3", "ACC_1"), relation_type=RelationType.TRANSACTION, amount=9500.0)

    # 4-cycle
    for n in ["ACC_A", "ACC_B", "ACC_C", "ACC_D"]:
        g.add_node(n, entity_type=EntityType.BANK_ACCOUNT)
    g.add_edge(("ACC_A", "ACC_B"), amount=5000.0)
    g.add_edge(("ACC_B", "ACC_C"), amount=5000.0)
    g.add_edge(("ACC_C", "ACC_D"), amount=5000.0)
    g.add_edge(("ACC_D", "ACC_A"), amount=5000.0)

    detector = FraudRingDetector(g)
    rings = detector.find_circular_transfers(min_length=3, max_length=4)

    assert len(rings) == 2
    lengths = {r.cycle_length for r in rings}
    assert lengths == {3, 4}

    # Verify 3-cycle stats
    r3 = next(r for r in rings if r.cycle_length == 3)
    assert r3.total_amount == 29300.0
    assert r3.min_amount == 9500.0
    assert r3.max_amount == 10000.0
    assert len(r3.edge_details) == 3


def test_mule_account_detection() -> None:
    """
    Mule account M receives funds from 3 accounts and forwards almost identical funds to 3 targets.
    Inflow = 3 x $10,000 = $30,000. Outflow = 3 x $9,900 = $29,700.
    Difference is 1% -> Critical/High risk mule account.
    """
    g = CrimeNetworkGraph(name="MuleTest")
    g.add_node("MULE_01", entity_type=EntityType.BANK_ACCOUNT)

    # Inflows
    for i in range(1, 4):
        src = f"SRC_{i}"
        g.add_node(src)
        g.add_edge((src, "MULE_01"), amount=10000.0)

    # Outflows
    for i in range(1, 4):
        dst = f"DST_{i}"
        g.add_node(dst)
        g.add_edge(("MULE_01", dst), amount=9900.0)

    detector = FraudRingDetector(g)
    mules = detector.find_mule_accounts(ratio_tolerance=0.1, min_tx_count=2)

    assert len(mules) == 1
    m = mules[0]
    assert m.account_id == "MULE_01"
    assert m.inflow_total == 30000.0
    assert m.outflow_total == 29700.0
    assert m.flow_ratio <= 0.05
    assert m.risk_level in ("CRITICAL", "HIGH")


def test_smurfing_patterns() -> None:
    """
    Test Fan-In (Aggregation) and Fan-Out (Dispersion).
    """
    g = CrimeNetworkGraph(name="Smurfing")

    # Aggregator Hub (Fan-In: 5 small deposits)
    g.add_node("AGGREGATOR")
    for i in range(5):
        feeder = f"FEEDER_{i}"
        g.add_edge((feeder, "AGGREGATOR"), amount=2000.0)

    # Disperser Hub (Fan-Out: 5 small payouts)
    g.add_node("DISPERSER")
    for i in range(5):
        recv = f"RECV_{i}"
        g.add_edge(("DISPERSER", recv), amount=1900.0)

    detector = FraudRingDetector(g)
    patterns = detector.find_smurfing_patterns(fan_threshold=4)

    assert len(patterns) == 2
    types = {p.pattern_type for p in patterns}
    assert "FAN_IN_AGGREGATION" in types
    assert "FAN_OUT_DISPERSION" in types

    fan_in = next(p for p in patterns if p.pattern_type == "FAN_IN_AGGREGATION")
    assert fan_in.hub_node == "AGGREGATOR"
    assert fan_in.tx_count == 5
    assert fan_in.total_volume == 10000.0


def test_circular_transfers_with_transaction_only_filter() -> None:
    g = CrimeNetworkGraph(name="TxFilterTest")
    g.add_node("A")
    g.add_node("B")
    g.add_node("C")
    g.add_edge(("A", "B"), relation_type=RelationType.CALL)
    g.add_edge(("B", "C"), relation_type=RelationType.TRANSACTION, amount=100.0)
    g.add_edge(("C", "A"), relation_type=RelationType.TRANSACTION, amount=100.0)

    detector = FraudRingDetector(g)
    # With transaction_only=True, cycle should not form because A->B is CALL
    rings_tx = detector.find_circular_transfers(min_length=3, max_length=3, transaction_only=True)
    assert len(rings_tx) == 0

    # With transaction_only=False, cycle is found
    rings_all = detector.find_circular_transfers(min_length=3, max_length=3, transaction_only=False)
    assert len(rings_all) == 1


def test_fraud_detector_detect_all_aggregation() -> None:
    g = CrimeNetworkGraph(name="FullFraud")
    g.add_edge(("A", "B"), amount=100.0)
    g.add_edge(("B", "C"), amount=100.0)
    g.add_edge(("C", "A"), amount=100.0)

    detector = FraudRingDetector(g)
    report = detector.detect_all(min_cycle_len=3, max_cycle_len=3)
    assert report.total_cycles_detected == 1
    assert report.suspicious_volume_total > 0
