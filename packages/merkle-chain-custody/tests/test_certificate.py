"""
Tests for custody.certificate module: HMAC-SHA256 non-repudiation signing,
canonical JSON determinism, and constant-time verification.
"""

import json
import pytest

from custody.certificate import (
    canonical_json_bytes,
    compute_hmac_signature,
    export_certificate_json,
    generate_certificate,
    import_certificate_json,
    verify_certificate,
)
from custody.evidence import EvidenceItem, EvidenceMetadata


def _flip_first_char(hex_str: str) -> str:
    """Flip first character to guarantee 1-char tamper."""
    c0 = hex_str[0]
    flipped = "1" if c0 != "1" else "2"
    return flipped + hex_str[1:]


@pytest.fixture
def sample_evidences() -> list[EvidenceItem]:
    meta1 = EvidenceMetadata(source_path="/e1.dd", file_size_bytes=1024, custody_officer="Officer-1")
    meta2 = EvidenceMetadata(source_path="/e2.dd", file_size_bytes=2048, custody_officer="Officer-2")
    return [
        EvidenceItem(evidence_id="EV-1", hash_value="1" * 64, metadata=meta1),
        EvidenceItem(evidence_id="EV-2", hash_value="2" * 64, metadata=meta2),
    ]


def test_canonical_json_bytes_determinism() -> None:
    # Different dictionary key insertion orders
    d1 = {"z": 100, "a": "hello", "m": [1, 2, 3]}
    d2 = {"a": "hello", "m": [1, 2, 3], "z": 100}

    b1 = canonical_json_bytes(d1)
    b2 = canonical_json_bytes(d2)

    assert b1 == b2
    assert b1 == b'{"a":"hello","m":[1,2,3],"z":100}'


def test_compute_hmac_signature() -> None:
    data = b"Forensic payload"
    key = "mock_secret_key_123"
    sig = compute_hmac_signature(data, key)
    assert len(sig) == 64

    # Empty key raises ValueError
    with pytest.raises(ValueError, match="Secret key cannot be empty"):
        compute_hmac_signature(data, "")


def test_generate_and_verify_valid_certificate(sample_evidences: list[EvidenceItem]) -> None:
    secret_key = "mock_secret_key_123"
    root_hash = "a" * 64

    cert = generate_certificate(
        root_hash=root_hash,
        evidence_items=sample_evidences,
        secret_key=secret_key,
        signer_identity="ForensicAuthority-HQ",
        case_id="CASE-2026-ALPHA",
    )

    assert cert.root_hash == root_hash
    assert cert.total_evidences == 2
    assert cert.signer_identity == "ForensicAuthority-HQ"
    assert len(cert.signature) == 64

    # Verification with matching key
    result = verify_certificate(cert, secret_key=secret_key)
    assert result.is_valid is True
    assert result.evidence_id == cert.certificate_id
    assert "verified successfully" in result.message.lower()


def test_generate_certificate_validation_errors(sample_evidences: list[EvidenceItem]) -> None:
    with pytest.raises(ValueError, match="Cannot issue certificate for an empty evidence set"):
        generate_certificate(root_hash="a" * 64, evidence_items=[], secret_key="k", signer_identity="s")

    with pytest.raises(ValueError, match="signer_identity cannot be empty"):
        generate_certificate(root_hash="a" * 64, evidence_items=sample_evidences, secret_key="k", signer_identity="")


def test_verify_certificate_tampered_payload(sample_evidences: list[EvidenceItem]) -> None:
    secret_key = "mock_secret_key_123"
    cert = generate_certificate(
        root_hash="a" * 64,
        evidence_items=sample_evidences,
        secret_key=secret_key,
        signer_identity="ForensicOfficer-01",
    )

    # Tamper root hash in dictionary representation
    cert_dict = cert.model_dump()
    cert_dict["root_hash"] = _flip_first_char(cert.root_hash)

    result = verify_certificate(cert_dict, secret_key=secret_key)
    assert result.is_valid is False
    assert "mismatch" in result.message.lower()


def test_verify_certificate_wrong_secret_key(sample_evidences: list[EvidenceItem]) -> None:
    correct_key = "mock_secret_key_123"
    wrong_key = "mock_wrong_key_999"

    cert = generate_certificate(
        root_hash="a" * 64,
        evidence_items=sample_evidences,
        secret_key=correct_key,
        signer_identity="ForensicOfficer-01",
    )

    result = verify_certificate(cert, secret_key=wrong_key)
    assert result.is_valid is False
    assert "mismatch" in result.message.lower()


def test_verify_certificate_tampered_signature(sample_evidences: list[EvidenceItem]) -> None:
    secret_key = "mock_secret_key_123"
    cert = generate_certificate(
        root_hash="a" * 64,
        evidence_items=sample_evidences,
        secret_key=secret_key,
        signer_identity="ForensicOfficer-01",
    )

    cert_dict = cert.model_dump()
    cert_dict["signature"] = _flip_first_char(cert.signature)

    result = verify_certificate(cert_dict, secret_key=secret_key)
    assert result.is_valid is False


def test_export_and_import_certificate_json(sample_evidences: list[EvidenceItem]) -> None:
    secret_key = "mock_secret_key_123"
    cert = generate_certificate(
        root_hash="f" * 64,
        evidence_items=sample_evidences,
        secret_key=secret_key,
        signer_identity="ForensicOfficer-01",
    )

    json_str = export_certificate_json(cert)
    assert isinstance(json_str, str)
    assert cert.certificate_id in json_str

    imported_cert = import_certificate_json(json_str)
    assert imported_cert == cert

    # Verify directly from JSON string
    res = verify_certificate(json_str, secret_key=secret_key)
    assert res.is_valid is True


def test_verify_certificate_malformed_inputs() -> None:
    secret_key = "mock_secret_key_123"

    # Malformed JSON string
    res_malformed = verify_certificate("{invalid_json: true}", secret_key=secret_key)
    assert res_malformed.is_valid is False
    assert "schema validation failed" in res_malformed.message.lower()

    # Unsupported type (integer)
    res_type = verify_certificate(12345, secret_key=secret_key)  # type: ignore[arg-type]
    assert res_type.is_valid is False
    assert "unsupported certificate input type" in res_type.message.lower()
