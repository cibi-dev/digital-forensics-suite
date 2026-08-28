"""
Pydantic v2 Immutable forensic data models for ISO/IEC 27037 chain of custody.
Enforces strict schema validation (extra='forbid') and immutability (frozen=True).
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format with Z suffix."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EvidenceMetadata(BaseModel):
    """
    Forensic metadata container according to ISO/IEC 27037 standards.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_path: str = Field(..., description="Original path or URI of collected evidence")
    file_size_bytes: int = Field(..., ge=0, description="Size of evidence in bytes")
    custody_officer: str = Field(..., min_length=1, description="Investigator ID or officer in custody")
    acquisition_timestamp: str = Field(default_factory=utcnow_iso, description="Acquisition ISO-8601 UTC timestamp")
    acquisition_method: str = Field(default="logical_copy", description="Forensic collection method")
    mime_type: Optional[str] = Field(default="application/octet-stream", description="Detected or declared MIME type")
    hardware_device: Optional[str] = Field(default=None, description="Host identifier or hardware SN")
    case_id: Optional[str] = Field(default=None, description="Forensic case tracking identifier")
    notes: Optional[str] = Field(default=None, description="Investigator custody notes")

    @field_validator("source_path")
    @classmethod
    def validate_source_path(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("source_path cannot be empty")
        return v.strip()


class EvidenceItem(BaseModel):
    """
    Immutable forensic evidence entry with cryptographic digest.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique forensic evidence UUID",
    )
    algorithm: Literal["sha256", "blake3"] = Field(
        default="sha256",
        description="Cryptographic hashing algorithm",
    )
    hash_value: str = Field(..., min_length=64, max_length=64, description="Hexadecimal hash digest")
    metadata: EvidenceMetadata = Field(..., description="ISO 27037 evidence acquisition metadata")
    registered_at: str = Field(default_factory=utcnow_iso, description="Registration UTC timestamp")
    leaf_index: Optional[int] = Field(default=None, ge=0, description="Index inside the custody Merkle tree")

    @field_validator("hash_value")
    @classmethod
    def validate_hash_value(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if len(v_clean) != 64 or not all(c in "0123456789abcdef" for c in v_clean):
            raise ValueError(f"Invalid 64-character hexadecimal digest: '{v}'")
        return v_clean


class AuditPathStep(BaseModel):
    """Single step in a Merkle inclusion proof."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    hash: str = Field(..., min_length=64, max_length=64, description="Sibling node hash")
    position: Literal["left", "right"] = Field(..., description="Sibling orientation relative to current node")


class MerkleProofModel(BaseModel):
    """
    Serializable Merkle inclusion proof model.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    leaf_index: int = Field(..., ge=0, description="Zero-based index of leaf in tree")
    leaf_hash: str = Field(..., min_length=64, max_length=64, description="Hexadecimal hash of leaf")
    audit_path: List[AuditPathStep] = Field(default_factory=list, description="Ordered sibling path to root")
    root_hash: str = Field(..., min_length=64, max_length=64, description="Target Merkle root hash")
    algorithm: Literal["sha256", "blake3"] = Field(default="sha256", description="Tree hash algorithm")
    total_leaves: int = Field(..., ge=1, description="Total number of leaves in tree")


class VerificationResult(BaseModel):
    """
    Forensic verification result report.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool = Field(..., description="Overall cryptographic verification status")
    evidence_id: Optional[str] = Field(default=None, description="ID of verified evidence item")
    computed_hash: Optional[str] = Field(default=None, description="Computed digest during verification")
    expected_hash: Optional[str] = Field(default=None, description="Expected digest from chain")
    computed_root: Optional[str] = Field(default=None, description="Computed Merkle root")
    expected_root: Optional[str] = Field(default=None, description="Expected Merkle root")
    message: str = Field(..., description="Detailed verification message or failure reason")
    verified_at: str = Field(default_factory=utcnow_iso, description="Verification execution timestamp")


class CustodyCertificateModel(BaseModel):
    """
    Cryptographically signed certificate of non-repudiation for a custody tree.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    certificate_id: str = Field(
        default_factory=lambda: f"CERT-{uuid.uuid4().hex[:12].upper()}",
        description="Unique custody certificate ID",
    )
    case_id: Optional[str] = Field(default=None, description="Associated forensic case identifier")
    root_hash: str = Field(..., min_length=64, max_length=64, description="Merkle root digest")
    algorithm: Literal["sha256", "blake3"] = Field(default="sha256", description="Underlying hash algorithm")
    total_evidences: int = Field(..., ge=1, description="Total number of registered evidences")
    evidence_ids: List[str] = Field(..., min_length=1, description="List of evidence IDs included")
    evidence_hashes: List[str] = Field(..., min_length=1, description="List of evidence hashes included")
    generated_at: str = Field(default_factory=utcnow_iso, description="Certificate generation timestamp")
    signer_identity: str = Field(..., min_length=1, description="Identity of signing officer / system")
    signature_algorithm: Literal["HMAC-SHA256"] = Field(
        default="HMAC-SHA256",
        description="Signature algorithm used for non-repudiation",
    )
    signature: str = Field(..., min_length=64, max_length=64, description="Hexadecimal HMAC signature")
