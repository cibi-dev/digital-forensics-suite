"""
Tests for custody.evidence module: immutable Pydantic v2 forensic data models.
"""

import pytest
from pydantic import ValidationError

from custody.evidence import (
    AuditPathStep,
    CustodyCertificateModel,
    EvidenceItem,
    EvidenceMetadata,
    MerkleProofModel,
    VerificationResult,
    utcnow_iso,
)


def test_utcnow_iso_format() -> None:
    ts = utcnow_iso()
    assert ts.endswith("Z")
    assert "T" in ts
    assert len(ts) == 20


def test_evidence_metadata_valid() -> None:
    meta = EvidenceMetadata(
        source_path="/var/log/auth.log",
        file_size_bytes=1048576,
        custody_officer="Officer-Smith-42",
        case_id="CASE-2026-001",
    )
    assert meta.source_path == "/var/log/auth.log"
    assert meta.file_size_bytes == 1048576
    assert meta.custody_officer == "Officer-Smith-42"
    assert meta.acquisition_method == "logical_copy"
    assert meta.mime_type == "application/octet-stream"
    assert meta.case_id == "CASE-2026-001"


def test_evidence_metadata_validation_errors() -> None:
    with pytest.raises(ValidationError):
        EvidenceMetadata(source_path="", file_size_bytes=100, custody_officer="Officer")

    with pytest.raises(ValidationError):
        EvidenceMetadata(source_path="/safe/path", file_size_bytes=-10, custody_officer="Officer")

    with pytest.raises(ValidationError):
        EvidenceMetadata(source_path="/safe/path", file_size_bytes=10, custody_officer="")


def test_evidence_metadata_immutability() -> None:
    meta = EvidenceMetadata(
        source_path="/evidence.bin",
        file_size_bytes=512,
        custody_officer="Officer-1",
    )
    with pytest.raises(ValidationError):
        meta.source_path = "/modified.bin"  # type: ignore[misc]


def test_evidence_metadata_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EvidenceMetadata(
            source_path="/evidence.bin",
            file_size_bytes=512,
            custody_officer="Officer-1",
            unexpected_field="injected",  # type: ignore[call-arg]
        )


def test_evidence_item_valid() -> None:
    meta = EvidenceMetadata(
        source_path="/dev/sda1.img",
        file_size_bytes=2048,
        custody_officer="Agent-007",
    )
    valid_hash = "a" * 64
    item = EvidenceItem(
        algorithm="sha256",
        hash_value=valid_hash,
        metadata=meta,
    )
    assert len(item.evidence_id) > 0
    assert item.hash_value == valid_hash
    assert item.algorithm == "sha256"
    assert item.metadata == meta
    assert item.registered_at.endswith("Z")


def test_evidence_item_invalid_hash() -> None:
    meta = EvidenceMetadata(
        source_path="/path.bin",
        file_size_bytes=100,
        custody_officer="Officer-1",
    )
    # Too short
    with pytest.raises(ValidationError):
        EvidenceItem(hash_value="abc", metadata=meta)

    # Non-hex characters
    with pytest.raises(ValidationError):
        EvidenceItem(hash_value="z" * 64, metadata=meta)


def test_evidence_item_immutability() -> None:
    meta = EvidenceMetadata(
        source_path="/path.bin",
        file_size_bytes=100,
        custody_officer="Officer-1",
    )
    item = EvidenceItem(hash_value="b" * 64, metadata=meta)
    with pytest.raises(ValidationError):
        item.hash_value = "c" * 64  # type: ignore[misc]


def test_merkle_proof_model() -> None:
    step = AuditPathStep(hash="c" * 64, position="left")
    proof = MerkleProofModel(
        leaf_index=0,
        leaf_hash="d" * 64,
        audit_path=[step],
        root_hash="e" * 64,
        algorithm="sha256",
        total_leaves=2,
    )
    assert proof.leaf_index == 0
    assert len(proof.audit_path) == 1
    assert proof.audit_path[0].hash == "c" * 64

    # Test serialization round-trip
    dumped = proof.model_dump_json()
    reloaded = MerkleProofModel.model_validate_json(dumped)
    assert reloaded == proof


def test_verification_result_model() -> None:
    res = VerificationResult(
        is_valid=True,
        evidence_id="EV-1234",
        computed_hash="a" * 64,
        expected_hash="a" * 64,
        message="Valid evidence",
    )
    assert res.is_valid is True
    assert res.evidence_id == "EV-1234"
    assert res.verified_at.endswith("Z")


def test_custody_certificate_model() -> None:
    cert = CustodyCertificateModel(
        case_id="CASE-01",
        root_hash="1" * 64,
        algorithm="sha256",
        total_evidences=2,
        evidence_ids=["id-1", "id-2"],
        evidence_hashes=["2" * 64, "3" * 64],
        signer_identity="ForensicAuthority-01",
        signature="4" * 64,
    )
    assert cert.certificate_id.startswith("CERT-")
    assert cert.total_evidences == 2
    assert cert.signature_algorithm == "HMAC-SHA256"

    # Immutability check
    with pytest.raises(ValidationError):
        cert.signature = "5" * 64  # type: ignore[misc]
