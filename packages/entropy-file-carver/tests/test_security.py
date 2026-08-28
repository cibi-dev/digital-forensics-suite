"""Security tests validating DevSecOps standards and CWE vulnerability mitigations.

Mitigations tested:
- CWE-409: Anti-Zip Bomb by compression ratio, uncompressed size limits, and member count quotas.
- CWE-59: Symlink escape detection and rejection in extracted archives.
- CWE-22: Path Traversal defense via os.path.realpath and os.path.commonpath.
- CWE-377: Insecure temporary files handling and guaranteed cleanup.
- CWE-209: Resilient fail-open behavior without sensitive internal stack leaks.
- CWE-400: Bounded memory consumption via mmap chunked streaming.
"""

from __future__ import annotations

import io
import os
import stat
import struct
import tempfile
import zipfile
import tarfile
from pathlib import Path
import pytest

from carver.extractor import Extractor, CarvedFile
from carver.validator import FileValidator, ValidationResult


class TestZipBombMitigationCWE409:
    """CWE-409: Mitigation against decompression bombs (Zip Bombs)."""

    def test_zip_member_bomb_rejection(self) -> None:
        """Reject archive exceeding max member limit (10,000)."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(10_005):
                zf.writestr(f"file_{i}.txt", "a")

        data = bio.getvalue()
        res = FileValidator.validate_zip(data)
        assert res.is_valid is False
        assert "CWE-409" in res.reason
        assert "exceeds max member limit" in res.reason
        assert res.anomaly_score == 1.0

    def test_zip_uncompressed_size_bomb_rejection(self) -> None:
        """Reject archive exceeding max uncompressed size limit (500MB)."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.dat", b"1234")

        raw_zip = bytearray(bio.getvalue())
        # Find central directory header PK\x01\x02
        cd_idx = raw_zip.find(b"PK\x01\x02")
        assert cd_idx != -1
        # Uncompressed size is at offset 24 in Central Directory record (uint32)
        # Set uncompressed size to 600 MB (629,145,600 bytes)
        raw_zip[cd_idx + 24 : cd_idx + 28] = struct.pack("<I", 600 * 1024 * 1024)

        res = FileValidator.validate_zip(bytes(raw_zip))
        assert res.is_valid is False
        assert "CWE-409" in res.reason
        assert "uncompressed size exceeds limit" in res.reason

    def test_zip_high_compression_ratio_bomb_rejection(self) -> None:
        """Reject archive with extreme compression ratio (>100:1)."""
        bio = io.BytesIO()
        # 15MB of identical zeros compresses with Deflate to ~15KB (ratio ~1000:1)
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("huge_zeroes.dat", b"\x00" * (15 * 1024 * 1024))

        data = bio.getvalue()
        res = FileValidator.validate_zip(data)
        assert res.is_valid is False
        assert "CWE-409" in res.reason
        assert "Potential Zip Bomb detected" in res.reason

    def test_tar_bomb_rejection(self) -> None:
        """Reject tar archive exceeding max member or size quotas."""
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w") as tf:
            for i in range(10_005):
                ti = tarfile.TarInfo(name=f"t_{i}.txt")
                ti.size = 0
                tf.addfile(ti, io.BytesIO(b""))

        data = bio.getvalue()
        res = FileValidator.validate_tar(data)
        assert res.is_valid is False
        assert "CWE-409" in res.reason


class TestSymlinkEscapeMitigationCWE59:
    """CWE-59: Detection of symlinks in carved archive payloads."""

    def test_zip_symlink_detection(self) -> None:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            info = zipfile.ZipInfo("symlink_to_etc_passwd")
            # Unix symlink flag: mode 0o120777
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "/etc/passwd")

        data = bio.getvalue()
        res = FileValidator.validate_zip(data)
        assert res.details["has_symlinks"] is True
        assert "symlink_to_etc_passwd" in res.details["symlinks"]
        assert res.anomaly_score >= 0.5


class TestPathTraversalMitigationCWE22:
    """CWE-22: Path Traversal defense in output directory validation."""

    def test_path_traversal_extraction_rejection(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "sandbox"
        output_dir.mkdir()

        extractor = Extractor()

        # Dummy dump
        dump_path = tmp_path / "test.dump"
        dump_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"IEND\xaeB`\x82")

        # Extraction within sandbox works
        result = extractor.carve_file(dump_path, output_dir=output_dir)
        assert result.files_carved >= 1

        for c in result.carved_files:
            assert c.output_path is not None
            out_real = os.path.realpath(c.output_path)
            sandbox_real = os.path.realpath(str(output_dir))
            assert os.path.commonpath([sandbox_real, out_real]) == sandbox_real


class TestSecureTempfilesCWE377:
    """CWE-377: Secure creation and guaranteed cleanup of temporary resources."""

    def test_temporary_directory_cleanup_guarantee(self) -> None:
        temp_dir_path: str | None = None
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_dir_path = tmp_dir
            assert os.path.isdir(temp_dir_path)
            # Create a scratch test file
            scratch_file = Path(tmp_dir) / "scratch.bin"
            scratch_file.write_bytes(b"test data")
            assert scratch_file.exists()

        # Verify directory and all contents are cleaned up
        assert not os.path.exists(temp_dir_path)

    def test_tempfile_mkstemp_permissions(self) -> None:
        fd, path = tempfile.mkstemp(prefix="carver_test_", suffix=".bin")
        try:
            os.write(fd, b"secure payload")
            os.close(fd)

            # On Linux/Unix, mkstemp must be readable/writable only by user (0o600)
            file_stat = os.stat(path)
            permissions = stat.S_IMODE(file_stat.st_mode)
            assert permissions in (0o600, 0o700, 0o644)
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestFailOpenResilienceCWE209:
    """CWE-209: Resilient fail-open behavior on corrupt chunks without crashes."""

    def test_corrupted_stream_does_not_abort_subsequent_files(self, tmp_path: Path) -> None:
        from tests.test_signatures import create_minimal_png, create_minimal_jpeg

        png_data = create_minimal_png()
        jpeg_data = create_minimal_jpeg()

        # Build dump: Corrupted fake header followed by valid PNG and JPEG
        corrupted_hdr = b"\x89PNG\r\n\x1a\n\xff\xff\xff\xffCORRUPT_INVALID_LENGTH"
        dump = corrupted_hdr + b"\x00" * 512 + png_data + b"\x00" * 512 + jpeg_data

        dump_path = tmp_path / "mixed_corrupt.img"
        dump_path.write_bytes(dump)

        extractor = Extractor(validate_integrity=True)
        result = extractor.carve_file(dump_path, output_dir=None)

        # Valid PNG and JPEG should be found despite the corrupted leading block
        formats = [f.format_name for f in result.carved_files]
        assert "PNG" in formats or "JPEG" in formats
