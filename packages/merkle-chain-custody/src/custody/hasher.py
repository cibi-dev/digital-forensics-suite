"""
Forensic streaming hasher module for ISO/IEC 27037 chain of custody.
Supports SHA-256 and BLAKE3 algorithms with constant-time verification.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Optional, Union

try:
    import blake3
    _HAS_BLAKE3 = True
except ImportError:  # pragma: no cover
    _HAS_BLAKE3 = False

DEFAULT_CHUNK_SIZE: int = 65536  # 64 KB chunk size for bounded streaming I/O


class HashAlgorithm(str, Enum):
    """Supported cryptographic hash algorithms."""
    SHA256 = "sha256"
    BLAKE3 = "blake3"


def validate_safe_path(target_path: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> Path:
    """
    Validate path safety against Path Traversal vulnerabilities (CWE-22).
    
    Args:
        target_path: Path to validate.
        base_dir: Optional base directory to confine target path within.
        
    Returns:
        Resolved absolute Path.
        
    Raises:
        ValueError: If path escapes base_dir.
        FileNotFoundError: If target path does not exist.
    """
    resolved_target = Path(target_path).resolve()
    
    if base_dir is not None:
        resolved_base = Path(base_dir).resolve()
        try:
            # Check commonpath confinement
            common = Path(os.path.commonpath([str(resolved_base), str(resolved_target)]))
            if common != resolved_base:
                raise ValueError(f"Path Traversal detected: '{target_path}' escapes base directory '{base_dir}'")
        except ValueError as exc:
            if "Paths don't have the same drive" in str(exc) or "escapes base" in str(exc):
                raise
            raise ValueError(f"Path Traversal validation error: {exc}") from exc

    if not resolved_target.exists():
        raise FileNotFoundError(f"Target file not found: {resolved_target}")
        
    if not resolved_target.is_file():
        raise ValueError(f"Target path is not a regular file: {resolved_target}")

    return resolved_target


class StreamingHasher:
    """
    Streaming cryptographic hasher supporting SHA-256 and BLAKE3.
    Operates in O(1) memory space.
    """

    def __init__(self, algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256) -> None:
        algo_str = str(algorithm).lower()
        if isinstance(algorithm, HashAlgorithm):
            self.algorithm = algorithm
        elif algo_str in ("sha256", "sha-256"):
            self.algorithm = HashAlgorithm.SHA256
        elif algo_str in ("blake3", "blake-3"):
            self.algorithm = HashAlgorithm.BLAKE3
        else:
            raise ValueError(f"Unsupported hash algorithm: '{algorithm}'. Supported: sha256, blake3")

        self._hasher = self._init_hasher()

    def _init_hasher(self) -> Any:
        if self.algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256()
        elif self.algorithm == HashAlgorithm.BLAKE3:
            if not _HAS_BLAKE3:  # pragma: no cover
                raise RuntimeError("BLAKE3 is not installed in the current environment")
            return blake3.blake3()
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")  # pragma: no cover

    def update(self, data: bytes) -> StreamingHasher:
        """Update hash state with raw bytes."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"Expected bytes-like object, got {type(data).__name__}")
        self._hasher.update(data)
        return self

    def digest(self) -> bytes:
        """Return binary digest."""
        return self._hasher.digest()

    def hexdigest(self) -> str:
        """Return lowercase hexadecimal digest string."""
        return self._hasher.hexdigest().lower()

    def reset(self) -> None:
        """Reset internal hash state."""
        self._hasher = self._init_hasher()


def hash_bytes(data: bytes, algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256) -> str:
    """
    Compute cryptographic hash of in-memory byte buffer.
    
    Args:
        data: Input bytes.
        algorithm: 'sha256' or 'blake3'.
        
    Returns:
        Hexadecimal hash string.
    """
    hasher = StreamingHasher(algorithm=algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def hash_stream(
    stream: BinaryIO,
    algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Compute cryptographic hash of a binary stream in constant memory chunks.
    
    Args:
        stream: Readable binary stream.
        algorithm: 'sha256' or 'blake3'.
        chunk_size: Byte size per read iteration (must be > 0).
        
    Returns:
        Hexadecimal hash string.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive, got {chunk_size}")
        
    hasher = StreamingHasher(algorithm=algorithm)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def hash_file(
    file_path: Union[str, Path],
    algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    base_dir: Optional[Union[str, Path]] = None,
) -> str:
    """
    Compute cryptographic hash of a file safely using bounded chunk streaming.
    
    Args:
        file_path: Path to target file.
        algorithm: 'sha256' or 'blake3'.
        chunk_size: Byte size per read iteration.
        base_dir: Optional directory to confine file access (CWE-22 defense).
        
    Returns:
        Hexadecimal hash string.
    """
    safe_path = validate_safe_path(file_path, base_dir=base_dir)
    with safe_path.open("rb") as f:
        return hash_stream(f, algorithm=algorithm, chunk_size=chunk_size)


def verify_digest(computed_hash: str, expected_hash: str) -> bool:
    """
    Verify two hash strings in constant time (CWE-208 defense against timing attacks).
    
    Args:
        computed_hash: Hexadecimal hash computed from data.
        expected_hash: Reference hexadecimal hash to match against.
        
    Returns:
        True if hashes match exactly, False otherwise.
    """
    if not isinstance(computed_hash, str) or not isinstance(expected_hash, str):
        return False
    return hmac.compare_digest(computed_hash.strip().lower(), expected_hash.strip().lower())


def verify_file_hash(
    file_path: Union[str, Path],
    expected_hash: str,
    algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    base_dir: Optional[Union[str, Path]] = None,
) -> bool:
    """
    Compute file hash and verify against expected hash in constant time.
    """
    computed = hash_file(file_path, algorithm=algorithm, chunk_size=chunk_size, base_dir=base_dir)
    return verify_digest(computed, expected_hash)
