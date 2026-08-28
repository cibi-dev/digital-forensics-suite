"""
merkle-chain-custody
Forensic chain of custody cryptographic engine compliant with ISO/IEC 27037.
"""

from custody.certificate import (
    canonical_json_bytes,
    compute_hmac_signature,
    export_certificate_json,
    generate_certificate,
    import_certificate_json,
    verify_certificate,
)
from custody.evidence import (
    AuditPathStep,
    CustodyCertificateModel,
    EvidenceItem,
    EvidenceMetadata,
    MerkleProofModel,
    VerificationResult,
    utcnow_iso,
)
from custody.hasher import (
    DEFAULT_CHUNK_SIZE,
    HashAlgorithm,
    StreamingHasher,
    hash_bytes,
    hash_file,
    hash_stream,
    validate_safe_path,
    verify_digest,
    verify_file_hash,
)
from custody.merkle import (
    AuditPathNode,
    MerkleProof,
    MerkleTree,
    verify_merkle_proof,
)
from custody.storage import (
    CustodyStorage,
)

__version__ = "0.1.0"

__all__ = [
    # Hasher
    "DEFAULT_CHUNK_SIZE",
    "HashAlgorithm",
    "StreamingHasher",
    "hash_bytes",
    "hash_file",
    "hash_stream",
    "validate_safe_path",
    "verify_digest",
    "verify_file_hash",
    # Merkle
    "AuditPathNode",
    "MerkleProof",
    "MerkleTree",
    "verify_merkle_proof",
    # Evidence & Models
    "AuditPathStep",
    "CustodyCertificateModel",
    "EvidenceItem",
    "EvidenceMetadata",
    "MerkleProofModel",
    "VerificationResult",
    "utcnow_iso",
    # Storage
    "CustodyStorage",
    # Certificate
    "canonical_json_bytes",
    "compute_hmac_signature",
    "export_certificate_json",
    "generate_certificate",
    "import_certificate_json",
    "verify_certificate",
]
