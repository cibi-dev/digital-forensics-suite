"""
Tests for custody.hasher module: streaming SHA-256 and BLAKE3, Path Traversal defense, and constant-time verification.
"""

import hashlib
import io
from pathlib import Path
import pytest
import blake3

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


def test_hash_bytes_sha256() -> None:
    data = b"Forensic Chain of Custody 2026"
    expected = hashlib.sha256(data).hexdigest()
    assert hash_bytes(data, algorithm=HashAlgorithm.SHA256) == expected
    assert hash_bytes(data, algorithm="sha256") == expected


def test_hash_bytes_blake3() -> None:
    data = b"Forensic Chain of Custody 2026"
    expected = blake3.blake3(data).hexdigest()
    assert hash_bytes(data, algorithm=HashAlgorithm.BLAKE3) == expected
    assert hash_bytes(data, algorithm="blake3") == expected


def test_streaming_hasher_matches_in_memory() -> None:
    data = b"A" * 100000 + b"B" * 50000
    expected_sha = hashlib.sha256(data).hexdigest()
    expected_b3 = blake3.blake3(data).hexdigest()

    hasher_sha = StreamingHasher("sha256")
    hasher_b3 = StreamingHasher("blake3")

    chunk_size = 1024
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        hasher_sha.update(chunk)
        hasher_b3.update(chunk)

    assert hasher_sha.hexdigest() == expected_sha
    assert hasher_b3.hexdigest() == expected_b3
    assert hasher_sha.digest() == hashlib.sha256(data).digest()
    assert hasher_b3.digest() == blake3.blake3(data).digest()


def test_streaming_hasher_reset() -> None:
    hasher = StreamingHasher("sha256")
    hasher.update(b"temporary data")
    hasher.reset()
    hasher.update(b"target data")
    expected = hashlib.sha256(b"target data").hexdigest()
    assert hasher.hexdigest() == expected


def test_streaming_hasher_invalid_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        StreamingHasher("md5")


def test_streaming_hasher_invalid_input_type() -> None:
    hasher = StreamingHasher("sha256")
    with pytest.raises(TypeError, match="Expected bytes-like object"):
        hasher.update("not bytes string")  # type: ignore[arg-type]


def test_hash_stream(tmp_path: Path) -> None:
    data = b"Evidence streaming content"
    stream = io.BytesIO(data)
    result = hash_stream(stream, algorithm="sha256", chunk_size=4)
    expected = hashlib.sha256(data).hexdigest()
    assert result == expected


def test_hash_stream_invalid_chunk_size() -> None:
    stream = io.BytesIO(b"abc")
    with pytest.raises(ValueError, match="chunk_size must be positive"):
        hash_stream(stream, chunk_size=0)


def test_hash_file(tmp_path: Path) -> None:
    test_file = tmp_path / "evidence_01.bin"
    test_file.write_bytes(b"Forensic disk image sample payload")
    
    sha_hash = hash_file(test_file, algorithm="sha256")
    b3_hash = hash_file(test_file, algorithm="blake3")
    
    expected_sha = hashlib.sha256(b"Forensic disk image sample payload").hexdigest()
    expected_b3 = blake3.blake3(b"Forensic disk image sample payload").hexdigest()
    
    assert sha_hash == expected_sha
    assert b3_hash == expected_b3


def test_validate_safe_path(tmp_path: Path) -> None:
    base = tmp_path / "sandbox"
    base.mkdir()
    target = base / "file.txt"
    target.write_text("safe content")

    # Safe inside base
    validated = validate_safe_path(target, base_dir=base)
    assert validated == target.resolve()

    # Missing file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        validate_safe_path(base / "nonexistent.txt")

    # Directory instead of file raises ValueError
    with pytest.raises(ValueError, match="not a regular file"):
        validate_safe_path(base)


def test_validate_safe_path_traversal_detection(tmp_path: Path) -> None:
    base = tmp_path / "sandbox"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("sensitive secret data")

    # Path traversal attempt pointing outside base_dir
    with pytest.raises(ValueError, match="Path Traversal detected"):
        validate_safe_path(outside, base_dir=base)


def test_verify_digest() -> None:
    h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h2 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    h3 = "0000000000000000000000000000000000000000000000000000000000000000"

    assert verify_digest(h1, h2) is True
    assert verify_digest(h1, h3) is False
    assert verify_digest(123, h1) is False  # type: ignore[arg-type]


def test_verify_file_hash(tmp_path: Path) -> None:
    test_file = tmp_path / "doc.txt"
    test_file.write_text("Integrity verification payload")
    correct_hash = hash_file(test_file, algorithm="sha256")
    tampered_hash = "f" * 64

    assert verify_file_hash(test_file, correct_hash, algorithm="sha256") is True
    assert verify_file_hash(test_file, tampered_hash, algorithm="sha256") is False
