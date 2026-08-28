"""
Integration and End-to-End Suite Verification Tests for Digital Forensics Suite.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import pytest

# Add package source paths
_ROOT = Path(__file__).resolve().parent.parent
_PACKAGES_DIR = _ROOT / "packages"

sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_PACKAGES_DIR / "crime-network-analyzer" / "src"))
sys.path.insert(0, str(_PACKAGES_DIR / "forensic-timeline-reconstructor" / "src"))
sys.path.insert(0, str(_PACKAGES_DIR / "entropy-file-carver" / "src"))
sys.path.insert(0, str(_PACKAGES_DIR / "merkle-chain-custody" / "src"))
sys.path.insert(0, str(_PACKAGES_DIR / "text-to-sql-forensic-agent"))
sys.path.insert(0, str(_PACKAGES_DIR / "threat-log-detector" / "src"))

import cli
from carver.entropy import calculate_entropy
from carver.signatures import FILE_SIGNATURES
from custody.certificate import generate_certificate, verify_certificate
from custody.evidence import EvidenceItem, EvidenceMetadata
from custody.hasher import HashAlgorithm, hash_bytes
from custody.merkle import MerkleTree
from detector.engine import EngineConfig, IntrusionEngine
from detector.features import FeatureExtractor, group_by_sliding_window
from detector.synthetic import DatasetConfig, SyntheticLogGenerator
from forensic_agent.database import init_db
from forensic_agent.executor import SQLExecutor
from forensic_agent.sql_guard import SQLSecurityViolationError
from network.centrality import calculate_all_centralities, identify_kingpins_and_brokers
from network.communities import detect_communities_louvain
from network.fraud_rings import FraudRingDetector
from network.graph_store import CrimeNetworkGraph, EntityType, RelationType
from timeline.integrity import IntegrityAnalyzer
from timeline.normalizer import ForensicEvent


def test_cli_help_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies that top-level CLI returns valid help and version info."""
    exit_code = cli.main(["--version"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "forensics 1.0.0" in captured.out

    exit_code = cli.main(["--help"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Enterprise Digital Forensics & Incident Response Suite" in captured.out


def test_cli_subcommands_help() -> None:
    """Verifies all 6 subcommands accept --help and exit with 0."""
    subcommands = ["network", "timeline", "carver", "custody", "sql", "threats"]
    for sub in subcommands:
        # La mayoría de subcomandos delega en CLIs de paquetes que lanzan
        # SystemExit(0) con --help; otros (p. ej. custody) capturan el exit y
        # devuelven el código. Ambos contratos son válidos.
        try:
            code: int | None = cli.main([sub, "--help"])
        except SystemExit as exc_info:
            code = exc_info.code
        assert code == 0


def test_cli_unknown_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies unknown subcommand handling."""
    exit_code = cli.main(["non_existent_command"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Unknown subcommand" in captured.out


def test_cli_demo_pipeline_e2e(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies end-to-end multi-engine triage demo execution."""
    exit_code = cli.main(["demo"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "INTEGRATED FORENSIC INCIDENT TRIAGE PIPELINE COMPLETED WITH 0 ERRORS" in captured.out


def test_crime_network_analyzer_integration() -> None:
    """Verifies graph store, centralities, Louvain communities, and circular ring detection."""
    g = CrimeNetworkGraph()
    g.add_node("SUSPECT_1", entity_type=EntityType.SUSPECT, label="Suspect 1")
    g.add_node("MULE_1", entity_type=EntityType.BANK_ACCOUNT, label="Mule 1")
    g.add_node("MULE_2", entity_type=EntityType.BANK_ACCOUNT, label="Mule 2")

    g.add_edge(("SUSPECT_1", "MULE_1"), relation_type=RelationType.TRANSFER, weight=10000.0, amount=10000.0)
    g.add_edge(("MULE_1", "MULE_2"), relation_type=RelationType.TRANSFER, weight=9500.0, amount=9500.0)
    g.add_edge(("MULE_2", "SUSPECT_1"), relation_type=RelationType.TRANSFER, weight=9000.0, amount=9000.0)

    assert g.num_nodes == 3
    assert g.num_edges == 3

    cents = calculate_all_centralities(g)
    assert cents.total_nodes == 3
    assert len(cents.nodes) == 3
    roles = identify_kingpins_and_brokers(cents)
    assert "kingpins" in roles

    comms = detect_communities_louvain(g)
    assert len(comms.communities) >= 1

    detector = FraudRingDetector(g)
    report = detector.detect_all()
    assert len(report.circular_rings) == 1
    assert report.circular_rings[0].cycle_length == 3


def test_timeline_reconstructor_integration() -> None:
    """Verifies timeline forensic event integrity and clock jump detection."""
    t0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 8, 28, 10, 1, 0, tzinfo=timezone.utc)

    events = [
        ForensicEvent(
            timestamp=t0,
            source_type="syslog",
            source_file="auth.log",
            line_number=1,
            host="HOST1",
            user="root",
            action="LOGIN",
            message="Accepted publickey for root",
            raw_log="Aug 28 10:00:00 HOST1 sshd[10]: Accepted publickey for root",
            event_id="EVT-01"
        ),
        ForensicEvent(
            timestamp=t1,
            source_type="syslog",
            source_file="auth.log",
            line_number=2,
            host="HOST1",
            user="root",
            action="COMMAND",
            message="SESSION_OPENED",
            raw_log="Aug 28 10:01:00 HOST1 sshd[10]: session opened",
            event_id="EVT-02"
        ),
    ]
    analyzer = IntegrityAnalyzer()
    anomalies = list(analyzer.analyze_stream(iter(events)))
    assert len(anomalies) == 0


def test_entropy_carver_integration() -> None:
    """Verifies Shannon entropy and magic byte signature definitions."""
    zeros = b"\x00" * 1024
    assert calculate_entropy(zeros) == 0.0

    random_data = bytes([i % 256 for i in range(1024)])
    ent = calculate_entropy(random_data)
    assert 7.9 <= ent <= 8.0
    assert len(FILE_SIGNATURES) >= 5


def test_merkle_custody_integration() -> None:
    """Verifies Merkle tree inclusion, multi-hash verification, and ISO/IEC 27037 certificates."""
    data = b"CONFIDENTIAL_EVIDENCE_PAYLOAD"
    sha_hash = hash_bytes(data, HashAlgorithm.SHA256)
    blake_hash = hash_bytes(data, HashAlgorithm.BLAKE3)
    assert len(sha_hash) == 64
    assert len(blake_hash) == 64

    tree = MerkleTree([sha_hash])
    assert tree.root == sha_hash

    item = EvidenceItem(
        evidence_id="EVD-TEST-001",
        algorithm=HashAlgorithm.SHA256.value,
        hash_value=sha_hash,
        metadata=EvidenceMetadata(
            source_path="/evidence/sample.raw",
            file_size_bytes=len(data),
            custody_officer="Officer-42",
            case_id="CASE-TEST-01"
        ),
        leaf_index=0
    )
    secret = "TEST_SECRET_KEY_12345"
    cert = generate_certificate(
        root_hash=tree.root,
        evidence_items=[item],
        secret_key=secret,
        signer_identity="Officer-42",
        case_id="CASE-TEST-01"
    )
    assert cert.total_evidences == 1
    assert cert.root_hash == tree.root

    verif = verify_certificate(cert, secret_key=secret)
    assert verif.is_valid is True
    assert "verified successfully" in verif.message.lower()


def test_text_to_sql_forensic_agent_integration(tmp_path: Path) -> None:
    """Verifies SQLite schema initialization, AST SQL guards, and query execution."""
    db_file = tmp_path / "forensic_test.db"
    init_db(db_file, seed=True)

    executor = SQLExecutor(db_file)
    result = executor.execute("SELECT count(*) FROM suspects")
    assert len(result.rows) == 1

    # Security Guard: Semicolon / Multi-statement injection attempt
    with pytest.raises(SQLSecurityViolationError):
        executor.execute("SELECT * FROM suspects; DROP TABLE suspects;")

    # Security Guard: Non-whitelisted table
    with pytest.raises(SQLSecurityViolationError):
        executor.execute("SELECT * FROM sqlite_master")


def test_threat_log_detector_integration() -> None:
    """Verifies synthetic dataset generation, temporal feature extraction, and ML fitting."""
    gen = SyntheticLogGenerator(DatasetConfig(
        n_normal_events=100,
        n_brute_force_events=10,
        random_seed=42,
    ))
    dataset = gen.generate()
    windows = group_by_sliding_window(dataset.events, window_seconds=60.0, step_seconds=20.0, group_by_entity=True)
    raw_windows = [w[1] for w in windows]
    assert len(raw_windows) > 0

    extractor = FeatureExtractor(window_seconds=60.0)
    matrix, feat_names = extractor.extract_matrix(raw_windows)
    assert matrix.shape[0] == len(raw_windows)
    assert matrix.shape[1] == len(feat_names)

    engine = IntrusionEngine(config=EngineConfig(n_estimators=10, max_samples=32))
    engine.fit(matrix, feature_names=feat_names)
    assert engine.is_fitted is True

    scores, _, _, _ = engine.predict_scores(matrix)
    assert len(scores) == len(raw_windows)
