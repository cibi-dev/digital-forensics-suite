"""
Unified Command-Line Interface for Enterprise Digital Forensics Suite.

Provides access to all 6 forensic sub-engines:
- network: Criminal Network Analyzer & Fraud Ring Detector
- timeline: Forensic Timeline Reconstructor & Timestomping Detector
- carver: Entropy File Carver & Magic Signature Scanner
- custody: Merkle Chain of Custody (ISO/IEC 27037 compliant)
- sql: Deterministic Text-to-SQL Forensic Investigator
- threats: Unsupervised Threat Log & Intrusion Detector
- demo: End-to-end Integrated Incident Investigation Workflow
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

# Ensure subpackage paths are in sys.path
_ROOT = Path(__file__).resolve().parent
_PACKAGES_DIR = _ROOT / "packages"

_MODULE_PATHS = [
    _ROOT,
    _PACKAGES_DIR / "crime-network-analyzer" / "src",
    _PACKAGES_DIR / "forensic-timeline-reconstructor" / "src",
    _PACKAGES_DIR / "entropy-file-carver" / "src",
    _PACKAGES_DIR / "merkle-chain-custody" / "src",
    _PACKAGES_DIR / "text-to-sql-forensic-agent",
    _PACKAGES_DIR / "threat-log-detector" / "src",
]

for p in _MODULE_PATHS:
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

__version__ = "1.0.0"


def _run_network(argv: list[str]) -> int:
    import network.cli
    return network.cli.main(argv)


def _run_timeline(argv: list[str]) -> int:
    import timeline.cli
    return timeline.cli.main(argv)


def _run_carver(argv: list[str]) -> int:
    import carver.cli
    return carver.cli.main(argv)


def _run_custody(argv: list[str]) -> int:
    import custody.cli
    try:
        custody.cli.main(argv)  # type: ignore[func-returns-value]
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 0
    return 0


def _run_sql(argv: list[str]) -> int:
    import forensic_agent.cli
    return forensic_agent.cli.main(argv)


def _run_threats(argv: list[str]) -> int:
    import detector.cli
    return detector.cli.main(argv)


def _run_pipeline_demo() -> int:
    """Runs a complete end-to-end incident triage demonstration."""
    print("=" * 75)
    print("🔍 DIGITAL FORENSICS SUITE - ENTERPRISE MULTI-ENGINE INCIDENT TRIAGE")
    print("=" * 75)

    # 1. Threat Log Intrusion Detection
    print("\n[Step 1/6] 🛡️ Threat Log Intrusion Detection (Unsupervised ML)")
    from detector.synthetic import DatasetConfig, SyntheticLogGenerator
    from detector.features import FeatureExtractor, group_by_sliding_window
    from detector.engine import EngineConfig, IntrusionEngine

    gen = SyntheticLogGenerator(DatasetConfig(
        n_normal_events=200,
        n_brute_force_events=20,
        n_password_spray_events=10,
        n_exfiltration_events=10,
        random_seed=42,
    ))
    dataset = gen.generate()
    windows = group_by_sliding_window(dataset.events, window_seconds=60.0, step_seconds=20.0, group_by_entity=True)
    raw_windows = [w[1] for w in windows]

    extractor = FeatureExtractor(window_seconds=60.0)
    matrix, feat_names = extractor.extract_matrix(raw_windows)
    engine = IntrusionEngine(config=EngineConfig(n_estimators=10, max_samples=32, anomaly_threshold=0.6))
    engine.fit(matrix, feature_names=feat_names)
    scores, _, _, _ = engine.predict_scores(matrix)
    anom_count = sum(1 for s in scores if s > 0.6)
    print(f"  • Ingested {len(dataset.events)} auth/syslog records.")
    print(f"  • Extracted {len(raw_windows)} temporal windows across {len(feat_names)} forensic feature dimensions.")
    print(f"  • Isolation Forest Engine identified {anom_count} high-confidence threat clusters.")

    # 2. Crime Network & Money Laundering Analysis
    print("\n[Step 2/6] 🕸️ Crime Network Analysis & Fraud Ring Detection")
    from network.graph_store import CrimeNetworkGraph, EntityType, RelationType
    from network.centrality import calculate_all_centralities, identify_kingpins_and_brokers
    from network.communities import detect_communities_louvain
    from network.fraud_rings import FraudRingDetector

    g = CrimeNetworkGraph()
    g.add_node("SUSPECT_ALPHA", entity_type=EntityType.SUSPECT, label="Alpha")
    g.add_node("MULE_01", entity_type=EntityType.BANK_ACCOUNT, label="Mule 1")
    g.add_node("MULE_02", entity_type=EntityType.BANK_ACCOUNT, label="Mule 2")
    g.add_node("OFFSHORE_NODE", entity_type=EntityType.ORGANIZATION, label="Offshore Corp")

    g.add_edge(("SUSPECT_ALPHA", "MULE_01"), relation_type=RelationType.TRANSFER, weight=25000.0, amount=25000.0)
    g.add_edge(("MULE_01", "MULE_02"), relation_type=RelationType.TRANSFER, weight=24000.0, amount=24000.0)
    g.add_edge(("MULE_02", "SUSPECT_ALPHA"), relation_type=RelationType.TRANSFER, weight=23000.0, amount=23000.0)
    g.add_edge(("SUSPECT_ALPHA", "OFFSHORE_NODE"), relation_type=RelationType.TRANSFER, weight=150000.0, amount=150000.0)

    centralities = calculate_all_centralities(g)
    role_dict = identify_kingpins_and_brokers(centralities)
    comms = detect_communities_louvain(g)
    fraud_detector = FraudRingDetector(g)
    fraud_rep = fraud_detector.detect_all()
    print(f"  • Graph analyzed: {g.num_nodes} actors, {g.num_edges} financial transactions.")
    print(f"  • Communities detected: {len(comms.communities)}. Identified Kingpins: {len(role_dict['kingpins'])}, Brokers: {len(role_dict['brokers'])}.")
    print(f"  • Circular transaction laundering rings detected: {len(fraud_rep.circular_rings)} cycle(s).")

    # 3. Forensic Timeline Reconstruction & Timestomping Detection
    print("\n[Step 3/6] ⏱️ Multi-Source Timeline Reconstruction & Timestomping Analysis")
    from timeline.normalizer import ForensicEvent
    from timeline.integrity import IntegrityAnalyzer

    t0 = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 8, 28, 12, 5, 0, tzinfo=timezone.utc)
    events = [
        ForensicEvent(
            timestamp=t0,
            source_type="syslog",
            source_file="auth.log",
            line_number=101,
            host="SRV-PROD-01",
            user="admin",
            action="LOGIN_FAILED",
            message="Failed password for invalid user admin from 192.168.1.50",
            raw_log="Aug 28 12:00:00 SRV-PROD-01 sshd[1234]: Failed password for invalid user admin",
            event_id="EVT-001"
        ),
        ForensicEvent(
            timestamp=t1,
            source_type="syslog",
            source_file="syslog",
            line_number=142,
            host="SRV-PROD-01",
            user="cibi",
            action="PRIVILEGE_ESCALATION",
            message="COMMAND=/usr/bin/python3 exfiltrate.py",
            raw_log="Aug 28 12:05:00 SRV-PROD-01 sudo: COMMAND=/usr/bin/python3 exfiltrate.py",
            event_id="EVT-002"
        ),
    ]
    integrity = IntegrityAnalyzer()
    tamper_issues = list(integrity.analyze_stream(iter(events)))
    print(f"  • Correlated {len(events)} unified forensic events.")
    print(f"  • Negative clock jumps / timestomping anomalies flagged: {len(tamper_issues)}.")

    # 4. Shannon Entropy File Carver
    print("\n[Step 4/6] 🔬 Shannon Entropy & Binary Signature Carving")
    from carver.entropy import calculate_entropy
    from carver.signatures import FILE_SIGNATURES

    sample_stream = b"\x00" * 128 + b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + b"\x41" * 512 + b"\xFF\xD9" + b"\x00" * 64
    ent = calculate_entropy(sample_stream)
    print(f"  • Stream size: {len(sample_stream)} bytes | Computed Shannon entropy: {ent:.4f} bits/byte.")
    print(f"  • Signature catalog loaded: {len(FILE_SIGNATURES)} magic header/footer definitions.")

    # 5. Deterministic Text-to-SQL Forensic Ingestion & Query
    print("\n[Step 5/6] 💾 Deterministic Text-to-SQL Forensic Database")
    from forensic_agent.database import init_db
    from forensic_agent.executor import SQLExecutor

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        db_path = Path(tmp_db.name)
    try:
        init_db(db_path, seed=True)
        executor = SQLExecutor(db_path)
        res = executor.execute("SELECT count(*) AS total_suspects FROM suspects")
        total = res.rows[0][0] if res.rows and isinstance(res.rows[0], (list, tuple)) else res.rows
        print(f"  • Initialized isolated forensic SQLite store with strict SQL-Guard AST validation.")
        print(f"  • Verified schema execution: total seeded suspects = {total}.")
    finally:
        if db_path.exists():
            db_path.unlink()

    # 6. ISO/IEC 27037 Merkle Chain of Custody
    print("\n[Step 6/6] 🔒 Merkle Chain of Custody & Cryptographic Certification")
    from custody.hasher import hash_bytes, HashAlgorithm
    from custody.evidence import EvidenceItem, EvidenceMetadata
    from custody.merkle import MerkleTree
    from custody.certificate import generate_certificate

    h_val = hash_bytes(b"FORENSIC_TRIAGE_EVIDENCE_PAYLOAD", HashAlgorithm.SHA256)
    tree = MerkleTree([h_val])
    ev_item = EvidenceItem(
        evidence_id="EVD-CASE-2026-001",
        algorithm=HashAlgorithm.SHA256.value,
        hash_value=h_val,
        metadata=EvidenceMetadata(
            source_path="/var/log/audit.log",
            file_size_bytes=4096,
            custody_officer="Lead Incident Responder",
            case_id="CASE-2026-ALPHA"
        ),
        leaf_index=0
    )
    cert = generate_certificate(
        root_hash=tree.root,
        evidence_items=[ev_item],
        secret_key="SECRET_HMAC_FORENSIC_KEY",
        signer_identity="Forensic-Authority-01",
        case_id="CASE-2026-ALPHA"
    )
    print(f"  • Evidence ID: {ev_item.evidence_id} (SHA256: {h_val[:16]}...)")
    print(f"  • Merkle Tree Root: {tree.root}")
    print(f"  • Generated ISO/IEC 27037 Certificate: {cert.certificate_id} (Signer: {cert.signer_identity})")

    print("\n" + "=" * 75)
    print("✅ INTEGRATED FORENSIC INCIDENT TRIAGE PIPELINE COMPLETED WITH 0 ERRORS")
    print("=" * 75)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint for digital-forensics-suite."""
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="forensics",
        description="Enterprise Digital Forensics & Incident Response Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Engines:
  network      Crime Network Analyzer & Fraud Ring Detector
  timeline     Forensic Timeline Reconstructor & Timestomping Detector
  carver       Entropy File Carver & Embedded File Scanner
  custody      Merkle Chain of Custody & ISO/IEC 27037 Certification
  sql          Deterministic Text-to-SQL Forensic Investigator
  threats      Unsupervised Threat Log & Intrusion Detector
  demo         Run end-to-end integrated incident investigation pipeline
        """,
    )
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Forensic Engine / Command to execute")

    subparsers.add_parser("network", help="Crime network graph analysis and fraud ring detection", add_help=False)
    subparsers.add_parser("timeline", help="Forensic timeline normalization and timestomping analysis", add_help=False)
    subparsers.add_parser("carver", help="Entropy-based file carving and binary extraction", add_help=False)
    subparsers.add_parser("custody", help="ISO/IEC 27037 Merkle chain of custody and evidence audit", add_help=False)
    subparsers.add_parser("sql", help="Text-to-SQL deterministic forensic database queries", add_help=False)
    subparsers.add_parser("threats", help="Threat log parser, feature extraction, and ML anomaly detection", add_help=False)
    subparsers.add_parser("demo", help="Execute complete multi-engine incident triage demonstration")

    if not argv:
        parser.print_help()
        return 0

    command = argv[0]
    subargs = list(argv[1:])

    if command in ("--version", "-V"):
        print(f"forensics {__version__}")
        return 0

    if command in ("--help", "-h"):
        parser.print_help()
        return 0

    if command == "network":
        return _run_network(subargs)
    elif command == "timeline":
        return _run_timeline(subargs)
    elif command == "carver":
        return _run_carver(subargs)
    elif command == "custody":
        return _run_custody(subargs)
    elif command == "sql":
        return _run_sql(subargs)
    elif command == "threats":
        return _run_threats(subargs)
    elif command in ("demo", "pipeline"):
        return _run_pipeline_demo()
    else:
        print(f"Error: Unknown subcommand '{command}'. Run 'forensics --help' for usage.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
