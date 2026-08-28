"""
Tests for custody.storage module: immutable SQLite persistence, DDL triggers,
anti-UPDATE/DELETE enforcement, and parameterized SQL execution (CWE-89).
"""

import sqlite3
from pathlib import Path
import pytest

from custody.evidence import CustodyCertificateModel, EvidenceItem, EvidenceMetadata
from custody.storage import CustodyStorage


@pytest.fixture
def storage() -> CustodyStorage:
    return CustodyStorage(":memory:")


@pytest.fixture
def sample_evidence() -> EvidenceItem:
    meta = EvidenceMetadata(
        source_path="/evidence/sample_disk.dd",
        file_size_bytes=4096,
        custody_officer="Officer-Smith",
        case_id="CASE-2026-X",
        notes="First responder acquisition",
    )
    return EvidenceItem(
        evidence_id="EV-1001",
        algorithm="sha256",
        hash_value="a" * 64,
        metadata=meta,
    )


def test_storage_init_on_disk(tmp_path: Path) -> None:
    db_file = tmp_path / "subdir" / "custody_test.db"
    with CustodyStorage(db_file) as s:
        assert Path(s.db_path).exists()
        assert s.count_evidences() == 0


def test_store_and_retrieve_evidence(storage: CustodyStorage, sample_evidence: EvidenceItem) -> None:
    storage.store_evidence(sample_evidence)
    
    # Retrieve by ID
    retrieved = storage.get_evidence_by_id("EV-1001")
    assert retrieved is not None
    assert retrieved.evidence_id == "EV-1001"
    assert retrieved.hash_value == "a" * 64
    assert retrieved.metadata.source_path == "/evidence/sample_disk.dd"
    assert retrieved.metadata.case_id == "CASE-2026-X"

    # Retrieve by Hash
    by_hash = storage.get_evidence_by_hash("a" * 64)
    assert by_hash is not None
    assert by_hash.evidence_id == "EV-1001"

    # Non-existent lookup
    assert storage.get_evidence_by_id("NON-EXISTENT") is None
    assert storage.get_evidence_by_hash("f" * 64) is None


def test_list_and_count_evidences(storage: CustodyStorage) -> None:
    meta1 = EvidenceMetadata(source_path="/e1.bin", file_size_bytes=100, custody_officer="Off-1", case_id="CASE-A")
    meta2 = EvidenceMetadata(source_path="/e2.bin", file_size_bytes=200, custody_officer="Off-2", case_id="CASE-B")
    meta3 = EvidenceMetadata(source_path="/e3.bin", file_size_bytes=300, custody_officer="Off-1", case_id="CASE-A")

    storage.store_evidence(EvidenceItem(evidence_id="E1", hash_value="1" * 64, metadata=meta1))
    storage.store_evidence(EvidenceItem(evidence_id="E2", hash_value="2" * 64, metadata=meta2))
    storage.store_evidence(EvidenceItem(evidence_id="E3", hash_value="3" * 64, metadata=meta3))

    assert storage.count_evidences() == 3
    assert storage.count_evidences(case_id="CASE-A") == 2
    assert storage.count_evidences(case_id="CASE-B") == 1

    all_evs = storage.list_evidences()
    assert len(all_evs) == 3

    case_a_evs = storage.list_evidences(case_id="CASE-A")
    assert len(case_a_evs) == 2
    assert [e.evidence_id for e in case_a_evs] == ["E1", "E3"]


def test_immutability_trigger_blocks_evidence_update(storage: CustodyStorage, sample_evidence: EvidenceItem) -> None:
    storage.store_evidence(sample_evidence)
    
    # Attempt direct SQL UPDATE on evidences table
    with pytest.raises(sqlite3.DatabaseError, match="Custody evidence is immutable: UPDATE prohibited"):
        with storage._conn:
            storage._conn.execute(
                "UPDATE evidences SET notes = 'tampered_notes' WHERE id = ?",
                (sample_evidence.evidence_id,),
            )


def test_immutability_trigger_blocks_evidence_delete(storage: CustodyStorage, sample_evidence: EvidenceItem) -> None:
    storage.store_evidence(sample_evidence)
    
    # Attempt direct SQL DELETE on evidences table
    with pytest.raises(sqlite3.DatabaseError, match="Custody evidence is immutable: DELETE prohibited"):
        with storage._conn:
            storage._conn.execute(
                "DELETE FROM evidences WHERE id = ?",
                (sample_evidence.evidence_id,),
            )


def test_immutability_trigger_blocks_merkle_root_update(storage: CustodyStorage) -> None:
    root_id = storage.store_merkle_root("r" * 64, "sha256", 5, case_id="CASE-01")
    
    with pytest.raises(sqlite3.DatabaseError, match="Merkle root record is immutable: UPDATE prohibited"):
        with storage._conn:
            storage._conn.execute(
                "UPDATE merkle_roots SET root_hash = ? WHERE id = ?",
                ("tampered" + "0" * 56, root_id),
            )


def test_immutability_trigger_blocks_merkle_root_delete(storage: CustodyStorage) -> None:
    root_id = storage.store_merkle_root("r" * 64, "sha256", 5, case_id="CASE-01")
    
    with pytest.raises(sqlite3.DatabaseError, match="Merkle root record is immutable: DELETE prohibited"):
        with storage._conn:
            storage._conn.execute(
                "DELETE FROM merkle_roots WHERE id = ?",
                (root_id,),
            )


def test_immutability_trigger_blocks_certificate_update(storage: CustodyStorage) -> None:
    cert = CustodyCertificateModel(
        certificate_id="CERT-TEST-01",
        root_hash="1" * 64,
        algorithm="sha256",
        total_evidences=1,
        evidence_ids=["id-1"],
        evidence_hashes=["2" * 64],
        signer_identity="Auth",
        signature="3" * 64,
    )
    storage.store_certificate(cert)

    with pytest.raises(sqlite3.DatabaseError, match="Custody certificate is immutable: UPDATE prohibited"):
        with storage._conn:
            storage._conn.execute(
                "UPDATE certificates SET signature = ? WHERE certificate_id = ?",
                ("4" * 64, "CERT-TEST-01"),
            )


def test_immutability_trigger_blocks_certificate_delete(storage: CustodyStorage) -> None:
    cert = CustodyCertificateModel(
        certificate_id="CERT-TEST-02",
        root_hash="1" * 64,
        algorithm="sha256",
        total_evidences=1,
        evidence_ids=["id-1"],
        evidence_hashes=["2" * 64],
        signer_identity="Auth",
        signature="3" * 64,
    )
    storage.store_certificate(cert)

    with pytest.raises(sqlite3.DatabaseError, match="Custody certificate is immutable: DELETE prohibited"):
        with storage._conn:
            storage._conn.execute(
                "DELETE FROM certificates WHERE certificate_id = ?",
                ("CERT-TEST-02",),
            )


def test_sql_injection_defense_parameterization(storage: CustodyStorage) -> None:
    # Malicious payload trying to break out of quotes and drop table
    injection_payload = "'; DROP TABLE evidences; --"
    meta = EvidenceMetadata(
        source_path=injection_payload,
        file_size_bytes=100,
        custody_officer=injection_payload,
        case_id=injection_payload,
        notes=injection_payload,
    )
    item = EvidenceItem(
        evidence_id="EV-INJECTION-TEST",
        hash_value="9" * 64,
        metadata=meta,
    )

    storage.store_evidence(item)
    retrieved = storage.get_evidence_by_id("EV-INJECTION-TEST")
    assert retrieved is not None
    assert retrieved.metadata.source_path == injection_payload
    assert retrieved.metadata.case_id == injection_payload

    # Ensure table was NOT dropped and count works
    assert storage.count_evidences() == 1


def test_store_and_retrieve_merkle_roots(storage: CustodyStorage) -> None:
    r1 = storage.store_merkle_root("1" * 64, "sha256", 2, case_id="CASE-1")
    r2 = storage.store_merkle_root("2" * 64, "blake3", 4, case_id="CASE-1")
    r3 = storage.store_merkle_root("3" * 64, "sha256", 1, case_id="CASE-2")

    latest_case1 = storage.get_latest_merkle_root(case_id="CASE-1")
    assert latest_case1 is not None
    assert latest_case1["root_hash"] == "2" * 64

    latest_global = storage.get_latest_merkle_root()
    assert latest_global is not None
    assert latest_global["root_hash"] == "3" * 64


def test_store_and_retrieve_certificates(storage: CustodyStorage) -> None:
    cert = CustodyCertificateModel(
        certificate_id="CERT-X1",
        case_id="CASE-A",
        root_hash="1" * 64,
        algorithm="sha256",
        total_evidences=2,
        evidence_ids=["id-1", "id-2"],
        evidence_hashes=["2" * 64, "3" * 64],
        signer_identity="Officer-Lead",
        signature="4" * 64,
    )
    storage.store_certificate(cert)

    fetched = storage.get_certificate("CERT-X1")
    assert fetched is not None
    assert fetched.certificate_id == "CERT-X1"
    assert fetched.root_hash == "1" * 64
    assert fetched.evidence_ids == ["id-1", "id-2"]

    certs_a = storage.list_certificates(case_id="CASE-A")
    assert len(certs_a) == 1
    assert certs_a[0].certificate_id == "CERT-X1"

    certs_b = storage.list_certificates(case_id="CASE-B")
    assert len(certs_b) == 0
