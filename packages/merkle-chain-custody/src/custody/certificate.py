"""
Forensic non-repudiation certificate generation and verification for ISO/IEC 27037.
Uses canonical JSON serialization and HMAC-SHA256 signatures with constant-time verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any, Dict, List, Optional, Union

from custody.evidence import CustodyCertificateModel, EvidenceItem, VerificationResult, utcnow_iso


def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """
    Serialize dictionary into deterministic canonical JSON bytes.
    Ensures sorted keys, compact separators, and ASCII encoding.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_hmac_signature(payload_bytes: bytes, secret_key: Union[str, bytes]) -> str:
    """
    Compute HMAC-SHA256 signature for payload bytes.
    """
    key_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    if not key_bytes:
        raise ValueError("Secret key cannot be empty")
    h = hmac.new(key_bytes, payload_bytes, hashlib.sha256)
    return h.hexdigest().lower()


def get_unsigned_payload(cert: Union[CustodyCertificateModel, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract the canonical unsigned dictionary structure from a certificate.
    """
    if isinstance(cert, CustodyCertificateModel):
        d = cert.model_dump()
    else:
        d = dict(cert)

    return {
        "certificate_id": d["certificate_id"],
        "case_id": d.get("case_id"),
        "root_hash": d["root_hash"].lower(),
        "algorithm": d["algorithm"].lower(),
        "total_evidences": int(d["total_evidences"]),
        "evidence_ids": list(d["evidence_ids"]),
        "evidence_hashes": [h.lower() for h in d["evidence_hashes"]],
        "generated_at": d["generated_at"],
        "signer_identity": d["signer_identity"],
        "signature_algorithm": "HMAC-SHA256",
    }


def generate_certificate(
    root_hash: str,
    evidence_items: List[EvidenceItem],
    secret_key: Union[str, bytes],
    signer_identity: str,
    case_id: Optional[str] = None,
    algorithm: str = "sha256",
    certificate_id: Optional[str] = None,
) -> CustodyCertificateModel:
    """
    Generate and sign an immutable forensic custody certificate.
    
    Args:
        root_hash: Verified Merkle root hash of the custody tree.
        evidence_items: List of evidence items included in the root.
        secret_key: Secret key used to generate the HMAC-SHA256 signature.
        signer_identity: Identity of investigator or custody officer.
        case_id: Optional case tracking ID.
        algorithm: Hash algorithm ('sha256' or 'blake3').
        certificate_id: Optional custom certificate ID.
        
    Returns:
        Signed CustodyCertificateModel.
    """
    if not evidence_items:
        raise ValueError("Cannot issue certificate for an empty evidence set")
    if not signer_identity.strip():
        raise ValueError("signer_identity cannot be empty")

    cert_id = certificate_id or f"CERT-{uuid.uuid4().hex[:12].upper()}"
    now_ts = utcnow_iso()
    ev_ids = [e.evidence_id for e in evidence_items]
    ev_hashes = [e.hash_value.lower() for e in evidence_items]

    unsigned_payload = {
        "certificate_id": cert_id,
        "case_id": case_id,
        "root_hash": root_hash.lower(),
        "algorithm": algorithm.lower(),
        "total_evidences": len(evidence_items),
        "evidence_ids": ev_ids,
        "evidence_hashes": ev_hashes,
        "generated_at": now_ts,
        "signer_identity": signer_identity.strip(),
        "signature_algorithm": "HMAC-SHA256",
    }

    payload_bytes = canonical_json_bytes(unsigned_payload)
    signature = compute_hmac_signature(payload_bytes, secret_key)

    return CustodyCertificateModel(
        certificate_id=cert_id,
        case_id=case_id,
        root_hash=root_hash.lower(),
        algorithm=algorithm.lower(),  # type: ignore[arg-type]
        total_evidences=len(evidence_items),
        evidence_ids=ev_ids,
        evidence_hashes=ev_hashes,
        generated_at=now_ts,
        signer_identity=signer_identity.strip(),
        signature_algorithm="HMAC-SHA256",
        signature=signature,
    )


def verify_certificate(
    certificate: Union[CustodyCertificateModel, Dict[str, Any], str],
    secret_key: Union[str, bytes],
) -> VerificationResult:
    """
    Cryptographically verify non-repudiation signature of a custody certificate.
    Uses constant-time comparison (CWE-208).
    
    Args:
        certificate: CustodyCertificateModel, dict, or JSON string.
        secret_key: Shared secret key for HMAC verification.
        
    Returns:
        VerificationResult detailing status and message.
    """
    try:
        if isinstance(certificate, str):
            cert_model = CustodyCertificateModel.model_validate_json(certificate)
        elif isinstance(certificate, dict):
            cert_model = CustodyCertificateModel.model_validate(certificate)
        elif isinstance(certificate, CustodyCertificateModel):
            cert_model = certificate
        else:
            return VerificationResult(
                is_valid=False,
                message=f"Unsupported certificate input type: {type(certificate).__name__}",
            )
    except Exception as exc:
        return VerificationResult(
            is_valid=False,
            message=f"Certificate schema validation failed: {exc}",
        )

    try:
        unsigned = get_unsigned_payload(cert_model)
        payload_bytes = canonical_json_bytes(unsigned)
        expected_sig = compute_hmac_signature(payload_bytes, secret_key)
        
        # Constant-time comparison
        is_match = hmac.compare_digest(expected_sig.lower(), cert_model.signature.lower())
        
        if is_match:
            return VerificationResult(
                is_valid=True,
                evidence_id=cert_model.certificate_id,
                computed_hash=expected_sig,
                expected_hash=cert_model.signature,
                computed_root=cert_model.root_hash,
                expected_root=cert_model.root_hash,
                message="Certificate cryptographic HMAC signature verified successfully.",
            )
        else:
            return VerificationResult(
                is_valid=False,
                evidence_id=cert_model.certificate_id,
                computed_hash=expected_sig,
                expected_hash=cert_model.signature,
                computed_root=cert_model.root_hash,
                expected_root=cert_model.root_hash,
                message="Cryptographic signature mismatch: certificate may have been tampered with or key is invalid.",
            )
    except Exception as exc:
        return VerificationResult(
            is_valid=False,
            evidence_id=getattr(cert_model, "certificate_id", None),
            message=f"Verification runtime exception: {exc}",
        )


def export_certificate_json(cert: CustodyCertificateModel, indent: int = 2) -> str:
    """Export certificate to formatted JSON string."""
    return json.dumps(cert.model_dump(), indent=indent, sort_keys=True)


def import_certificate_json(json_str: str) -> CustodyCertificateModel:
    """Import and validate certificate from JSON string."""
    return CustodyCertificateModel.model_validate_json(json_str)
