"""Tests for format integrity validation and steganography/encryption detection."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path
import pytest

from carver.validator import (
    FileValidator,
    detect_steganography_or_hidden_payload,
    validate_carved_file,
)
from tests.test_signatures import (
    create_minimal_elf32,
    create_minimal_elf64,
    create_minimal_jpeg,
    create_minimal_pdf,
    create_minimal_pe,
    create_minimal_png,
    create_minimal_tar,
    create_minimal_zip,
)


def create_sample_zip() -> bytes:
    """Create a valid zip with 2 sample files."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("test1.txt", "Sample contents for test 1")
        zf.writestr("test2.txt", "Sample contents for test 2")
    return bio.getvalue()


def create_sample_tar_with_symlink() -> bytes:
    """Create a tar archive with a symlink."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        ti_file = tarfile.TarInfo(name="file.txt")
        ti_file.size = 5
        tf.addfile(ti_file, io.BytesIO(b"hello"))

        ti_link = tarfile.TarInfo(name="symlink.txt")
        ti_link.type = tarfile.SYMTYPE
        ti_link.linkname = "file.txt"
        tf.addfile(ti_link)
    return bio.getvalue()


def create_sample_gzip() -> bytes:
    """Create a valid gzip compressed payload."""
    bio = io.BytesIO()
    with gzip.GzipFile(fileobj=bio, mode="wb") as gz:
        gz.write(b"Hello world uncompressed string for gzip validation.")
    return bio.getvalue()


class TestFileValidatorIntegrity:
    """Tests for format integrity verification."""

    def test_validate_valid_png(self) -> None:
        png_data = create_minimal_png()
        res = FileValidator.validate_png(png_data)
        assert res.is_valid is True
        assert res.format_name == "PNG"
        assert res.has_stego_or_encryption is False
        assert res.overlay_bytes == 0

    def test_validate_corrupt_png(self) -> None:
        corrupted = b"\x89PNG\r\n\x1a\nTRUNCATED"
        res = FileValidator.validate_png(corrupted)
        assert res.is_valid is False
        assert "missing standard 8-byte magic header" in res.reason or "Corrupt PNG" in res.reason

        res_short = FileValidator.validate_png(b"\x89PNG")
        assert res_short.is_valid is False

    def test_validate_valid_jpeg(self) -> None:
        jpg_data = create_minimal_jpeg()
        res = FileValidator.validate_jpeg(jpg_data)
        assert res.is_valid is True
        assert res.format_name == "JPEG"

    def test_validate_corrupt_jpeg(self) -> None:
        corrupted = b"\xff\xd8\xff\xe0MISSING_EOI_MARKER"
        res = FileValidator.validate_jpeg(corrupted)
        assert res.is_valid is False
        assert "missing EOI marker" in res.reason

        res_short = FileValidator.validate_jpeg(b"\xff\xd8")
        assert res_short.is_valid is False

    def test_validate_valid_zip(self) -> None:
        zip_data = create_sample_zip()
        res = FileValidator.validate_zip(zip_data)
        assert res.is_valid is True
        assert res.format_name == "ZIP"
        assert res.details["member_count"] == 2

    def test_validate_corrupt_zip(self) -> None:
        corrupted = b"PK\x03\x04CORRUPTED_ZIP_STREAM_LONG_ENOUGH_TO_PASS_LEN_CHECK"
        res = FileValidator.validate_zip(corrupted)
        assert res.is_valid is False

        res_short = FileValidator.validate_zip(b"PK\x03\x04")
        assert res_short.is_valid is False
        assert "smaller than minimum EOCD" in res_short.reason

    def test_validate_valid_pdf(self) -> None:
        pdf_data = create_minimal_pdf()
        res = FileValidator.validate_pdf(pdf_data)
        assert res.is_valid is True
        assert res.format_name == "PDF"

    def test_validate_corrupt_pdf(self) -> None:
        corrupted = b"%PDF-1.4\nNo trailer here in this text"
        res = FileValidator.validate_pdf(corrupted)
        assert res.is_valid is False

        res_short = FileValidator.validate_pdf(b"%PDF-")
        assert res_short.is_valid is False

    def test_validate_valid_elf64(self) -> None:
        elf_data = create_minimal_elf64()
        res = FileValidator.validate_elf(elf_data)
        assert res.is_valid is True
        assert res.details["bitness"] == 64

    def test_validate_valid_elf32(self) -> None:
        elf_data = create_minimal_elf32()
        res = FileValidator.validate_elf(elf_data)
        assert res.is_valid is True
        assert res.details["bitness"] == 32

    def test_validate_corrupt_elf(self) -> None:
        corrupted = b"\x7fELF" + b"\x00" * 20
        res = FileValidator.validate_elf(corrupted)
        assert res.is_valid is False
        assert "Invalid ELF" in res.reason

        res_bad_magic = FileValidator.validate_elf(b"NOT_AN_ELF_FILE" + b"\x00" * 60)
        assert res_bad_magic.is_valid is False

    def test_validate_valid_pe(self) -> None:
        pe_data = create_minimal_pe()
        res = FileValidator.validate_pe(pe_data)
        assert res.is_valid is True
        assert res.details["number_of_sections"] == 2

    def test_validate_corrupt_pe(self) -> None:
        res_short = FileValidator.validate_pe(b"MZ")
        assert res_short.is_valid is False

        # PE with e_lfanew out of range
        dos_hdr = bytearray(b"MZ" + b"\x00" * 126)
        import struct
        dos_hdr[0x3C:0x40] = struct.pack("<I", 0x1000)
        res_bad_ptr = FileValidator.validate_pe(bytes(dos_hdr))
        assert res_bad_ptr.is_valid is False
        assert "points outside file boundaries" in res_bad_ptr.reason

        # PE with missing PE\0\0 signature
        dos_hdr[0x3C:0x40] = struct.pack("<I", 0x40)
        res_bad_sig = FileValidator.validate_pe(bytes(dos_hdr))
        assert res_bad_sig.is_valid is False
        assert "missing PE\\0\\0 signature" in res_bad_sig.reason

    def test_validate_valid_tar(self) -> None:
        tar_data = create_minimal_tar()
        res = FileValidator.validate_tar(tar_data)
        assert res.is_valid is True
        assert res.details["member_count"] == 1

    def test_validate_tar_with_symlink(self) -> None:
        tar_data = create_sample_tar_with_symlink()
        res = FileValidator.validate_tar(tar_data)
        assert res.is_valid is True
        assert res.details["has_symlinks"] is True
        assert res.anomaly_score >= 0.4

    def test_validate_corrupt_tar(self) -> None:
        res_short = FileValidator.validate_tar(b"ustar")
        assert res_short.is_valid is False

        corrupted = b"ustar" + b"\xff" * 600
        res = FileValidator.validate_tar(corrupted)
        assert res.is_valid is False

    def test_validate_valid_gzip(self) -> None:
        gz_data = create_sample_gzip()
        res = FileValidator.validate_gzip(gz_data)
        assert res.is_valid is True
        assert res.format_name == "GZIP"

    def test_validate_corrupt_gzip(self) -> None:
        res_short = FileValidator.validate_gzip(b"\x1f\x8b")
        assert res_short.is_valid is False

        corrupted = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03CORRUPTED_STREAM_DATA"
        res = FileValidator.validate_gzip(corrupted)
        assert res.is_valid is False
        assert "Corrupt GZIP stream" in res.reason

    def test_validate_generic_fallback(self) -> None:
        res = FileValidator.validate("UNKNOWN_EXT", b"some binary data")
        assert res.is_valid is True
        assert res.format_name == "UNKNOWN_EXT"


class TestSteganographyAndHiddenPayloadDetection:
    """Tests for detecting hidden encrypted payloads and trailing overlay anomalies."""

    def test_png_high_entropy_overlay_detection(self) -> None:
        png_data = create_minimal_png()
        encrypted_payload = bytes(range(256)) * 2
        stego_png = png_data + encrypted_payload

        res = FileValidator.validate_png(stego_png)
        assert res.is_valid is True
        assert res.has_stego_or_encryption is True
        assert res.overlay_bytes == 512
        assert res.overlay_entropy >= 7.5
        assert res.anomaly_score >= 0.8
        assert "Potential Stego/Payload" in res.reason

    def test_png_low_entropy_null_padding_not_flagged_as_stego(self) -> None:
        png_data = create_minimal_png()
        padding = b"\x00" * 128
        padded_png = png_data + padding

        res = FileValidator.validate_png(padded_png)
        assert res.is_valid is True
        assert res.has_stego_or_encryption is False
        assert res.overlay_bytes == 128
        assert res.overlay_entropy == 0.0

    def test_jpeg_high_entropy_overlay_detection(self) -> None:
        jpg_data = create_minimal_jpeg()
        encrypted_payload = bytes(range(256)) * 2
        stego_jpg = jpg_data + encrypted_payload

        res = FileValidator.validate_jpeg(stego_jpg)
        assert res.is_valid is True
        assert res.has_stego_or_encryption is True
        assert res.overlay_bytes == 512

    def test_pdf_high_entropy_overlay_detection(self) -> None:
        pdf_data = create_minimal_pdf()
        encrypted_payload = bytes(range(256)) * 2
        stego_pdf = pdf_data + encrypted_payload

        res = FileValidator.validate_pdf(stego_pdf)
        assert res.is_valid is True
        assert res.has_stego_or_encryption is True
        assert res.overlay_bytes == 512

    def test_elf_high_entropy_overlay_detection(self) -> None:
        elf_data = create_minimal_elf64()
        encrypted_payload = bytes(range(256)) * 2
        stego_elf = elf_data + encrypted_payload

        res = FileValidator.validate_elf(stego_elf)
        assert res.is_valid is True
        assert res.has_stego_or_encryption is True
        assert res.overlay_bytes >= 256

    def test_pe_high_entropy_overlay_detection(self) -> None:
        pe_data = create_minimal_pe()
        encrypted_payload = bytes(range(256)) * 2
        stego_pe = pe_data + encrypted_payload

        res = FileValidator.validate_pe(stego_pe)
        assert res.is_valid is True
        assert res.has_stego_or_encryption is True

    def test_detect_steganography_convenience_wrapper(self) -> None:
        png_data = create_minimal_png()
        encrypted_payload = bytes(range(256)) * 2
        has_stego, score, overlay_len, overlay_ent = detect_steganography_or_hidden_payload(
            png_data + encrypted_payload, "PNG"
        )
        assert has_stego is True
        assert score >= 0.8
        assert overlay_len == 512
        assert overlay_ent >= 7.5

    def test_validate_carved_file_from_path(self, tmp_path: Path) -> None:
        test_file = tmp_path / "valid.png"
        test_file.write_bytes(create_minimal_png())

        res = validate_carved_file("PNG", test_file)
        assert res.is_valid is True

        missing_res = validate_carved_file("PNG", tmp_path / "missing.png")
        assert missing_res.is_valid is False
        assert "File not found" in missing_res.reason
