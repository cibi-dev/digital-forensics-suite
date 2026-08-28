"""Tests for binary signature catalogue, magic bytes recognition, and boundary parsers."""

from __future__ import annotations

import io
import struct
import tarfile
import zlib
import pytest

from carver.signatures import (
    FILE_SIGNATURES,
    FileSignature,
    calculate_file_end,
    detect_signature_at,
    find_elf_end,
    find_gzip_end,
    find_jpeg_end,
    find_pdf_end,
    find_pe_end,
    find_png_end,
    find_tar_end,
    find_zip_end,
)


def create_minimal_png() -> bytes:
    """Helper to generate a structurally valid minimal PNG."""
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND"))
    iend_chunk = struct.pack(">I", 0) + b"IEND" + iend_crc
    return magic + ihdr_chunk + iend_chunk


def create_minimal_jpeg() -> bytes:
    """Helper to generate a minimal JPEG buffer."""
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xff\xd9"


def create_minimal_zip() -> bytes:
    """Helper to generate a minimal empty ZIP buffer."""
    eocd = b"PK\x05\x06" + b"\x00" * 18
    local_hdr = b"PK\x03\x04" + b"\x00" * 26
    return local_hdr + eocd


def create_minimal_pdf() -> bytes:
    """Helper to generate a minimal PDF document buffer."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n60\n%%EOF\n"
    )


def create_minimal_elf64() -> bytes:
    """Helper to generate a minimal 64-bit ELF header buffer."""
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    hdr = (
        e_ident
        + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, 128, 0, 64, 56, 1, 64, 2, 1)
    )
    sec1 = struct.pack("<IIQQQQIIQQ", 0, 1, 6, 0x400000, 256, 128, 0, 0, 16, 0)
    sec2 = struct.pack("<IIQQQQIIQQ", 0, 1, 6, 0x400000, 384, 128, 0, 0, 16, 0)
    data = hdr + (b"\x00" * (128 - len(hdr))) + sec1 + sec2
    return data + b"\x00" * (512 - len(data))


def create_minimal_elf32() -> bytes:
    """Helper to generate a minimal 32-bit ELF header buffer."""
    e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    hdr = (
        e_ident
        + struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0x8048000, 52, 104, 0, 52, 32, 1, 40, 2, 1)
    )
    return hdr + b"\x00" * (256 - len(hdr))


def create_minimal_pe() -> bytes:
    """Helper to generate a minimal PE executable header."""
    dos_hdr = bytearray(b"MZ" + b"\x00" * 126)
    dos_hdr[0x3C:0x40] = struct.pack("<I", 0x80)

    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 112, 0x0002)
    opt_hdr = b"\x00" * 112
    sec_hdr1 = b".text\x00\x00\x00" + struct.pack("<IIII", 0x200, 0x1000, 0x200, 0x200) + b"\x00" * 16
    sec_hdr2 = b".data\x00\x00\x00" + struct.pack("<IIII", 0x200, 0x2000, 0x200, 0x400) + b"\x00" * 16
    content = bytes(dos_hdr) + pe_sig + coff + opt_hdr + sec_hdr1 + sec_hdr2
    pad = b"\x90" * (0x600 - len(content))
    return content + pad


def create_minimal_tar() -> bytes:
    """Helper to create a minimal TAR buffer."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        data = b"Hello from minimal TAR!"
        ti = tarfile.TarInfo(name="hello.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return bio.getvalue()


class TestSignatureDetection:
    """Tests for recognizing signatures at varying offsets."""

    def test_detect_png(self) -> None:
        raw = b"\x00" * 32 + create_minimal_png() + b"\x00" * 32
        sig = detect_signature_at(raw, offset=32)
        assert sig is not None
        assert sig.name == "PNG"
        assert sig.extension == "png"

    def test_detect_jpeg(self) -> None:
        raw = b"JUNK" * 10 + create_minimal_jpeg()
        sig = detect_signature_at(raw, offset=40)
        assert sig is not None
        assert sig.name == "JPEG"

    def test_detect_zip(self) -> None:
        raw = create_minimal_zip()
        sig = detect_signature_at(raw, offset=0)
        assert sig is not None
        assert sig.name == "ZIP"

    def test_detect_pdf(self) -> None:
        raw = b"PREFIX" + create_minimal_pdf()
        sig = detect_signature_at(raw, offset=6)
        assert sig is not None
        assert sig.name == "PDF"

    def test_detect_elf(self) -> None:
        raw = create_minimal_elf64()
        sig = detect_signature_at(raw, offset=0)
        assert sig is not None
        assert sig.name == "ELF"

    def test_detect_pe(self) -> None:
        raw = create_minimal_pe()
        sig = detect_signature_at(raw, offset=0)
        assert sig is not None
        assert sig.name == "PE"

    def test_detect_tar(self) -> None:
        raw = create_minimal_tar()
        sig = detect_signature_at(raw, offset=0)
        assert sig is not None
        assert sig.name == "TAR"

    def test_detect_gzip(self) -> None:
        raw = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00"
        sig = detect_signature_at(raw, offset=0)
        assert sig is not None
        assert sig.name == "GZIP"

    def test_detect_pe_invalid_e_lfanew(self) -> None:
        dos_hdr = bytearray(b"MZ" + b"\x00" * 126)
        dos_hdr[0x3C:0x40] = struct.pack("<I", 0x10)  # Too small (< 0x40)
        assert detect_signature_at(bytes(dos_hdr), offset=0) is None

        dos_hdr[0x3C:0x40] = struct.pack("<I", 0x80)
        # Missing PE signature at 0x80
        assert detect_signature_at(bytes(dos_hdr), offset=0) is None

    def test_no_signature_found(self) -> None:
        raw = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 10
        assert detect_signature_at(raw, offset=0) is None
        assert detect_signature_at(raw, offset=15) is None


class TestBoundaryParsers:
    """Tests for calculating exact end boundaries for all supported formats."""

    def test_png_boundary_parser(self) -> None:
        png_data = create_minimal_png()
        padded = b"PADDING" + png_data + b"EXTRA_TRAILING_BYTES"
        end = find_png_end(padded, start_offset=7)
        assert end is not None
        assert end == 7 + len(png_data)

    def test_png_corrupt_chunk_returns_none(self) -> None:
        assert find_png_end(b"\x89PNG\r\n\x1a\n", 0) is None
        assert find_png_end(b"\x89PNG", 0) is None
        corrupted = b"\x89PNG\r\n\x1a\n" + b"\xff\xff\xff\xffCORRUPT"
        assert find_png_end(corrupted, 0) is None
        huge_chunk = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 200 * 1024 * 1024) + b"IHDR"
        assert find_png_end(huge_chunk, 0) is None
        assert find_png_end(b"NOT_PNG_AT_ALL_TEST", 0) is None

    def test_jpeg_boundary_parser(self) -> None:
        jpg_data = create_minimal_jpeg()
        padded = jpg_data + b"OVERLAY_BYTES"
        end = find_jpeg_end(padded, start_offset=0)
        assert end == len(jpg_data)

        assert find_jpeg_end(b"\xff\xd8", 0) is None
        assert find_jpeg_end(b"NOT_JPEG", 0) is None
        assert find_jpeg_end(b"\xff\xd8\xffNO_EOI_HERE", 0) is None

    def test_zip_boundary_parser(self) -> None:
        zip_data = create_minimal_zip()
        padded = b"HEADER" + zip_data + b"TRAILING"
        end = find_zip_end(padded, start_offset=6)
        assert end is not None
        assert end == 6 + len(zip_data)

        assert find_zip_end(b"PK", 0) is None
        assert find_zip_end(b"NOT_ZIP", 0) is None
        assert find_zip_end(b"PK\x03\x04NO_EOCD_HERE", 0) is None
        assert find_zip_end(b"PK\x03\x04" + b"PK\x05\x06" + b"\x00" * 5, 0) is None

    def test_pdf_boundary_parser(self) -> None:
        pdf_data = create_minimal_pdf()
        padded = pdf_data + b"\n\n\nTRAILING"
        end = find_pdf_end(padded, start_offset=0)
        assert end is not None
        assert end >= len(pdf_data)

        assert find_pdf_end(b"%PDF", 0) is None
        assert find_pdf_end(b"NOT_PDF", 0) is None
        assert find_pdf_end(b"%PDF-1.4\nNo trailer here", 0) is None

    def test_elf_boundary_parser(self) -> None:
        elf64_data = create_minimal_elf64()
        end64 = find_elf_end(elf64_data, start_offset=0)
        assert end64 is not None
        assert end64 >= 128

        elf32_data = create_minimal_elf32()
        end32 = find_elf_end(elf32_data, start_offset=0)
        assert end32 is not None
        assert end32 >= 52

        assert find_elf_end(b"\x7fELF", 0) is None
        assert find_elf_end(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20, 0) is None
        assert find_elf_end(b"NOT_ELF_FILE_BINARY", 0) is None

    def test_pe_boundary_parser(self) -> None:
        pe_data = create_minimal_pe()
        end = find_pe_end(pe_data, start_offset=0)
        assert end is not None
        assert end >= 0x400

        assert find_pe_end(b"MZ", 0) is None
        assert find_pe_end(b"MZ" + b"\x00" * 70, 0) is None
        assert find_pe_end(b"NOT_PE_FILE_SAMPLE", 0) is None

    def test_tar_boundary_parser(self) -> None:
        tar_data = create_minimal_tar()
        end = find_tar_end(tar_data, start_offset=0)
        assert end is not None
        assert end >= 512

        assert find_tar_end(b"ustar", 0) is None
        assert find_tar_end(b"\x00" * 512, 0) is None
        assert find_tar_end(b"\x00" * 257 + b"ustar" + b"\x00" * 10, 0) is None

    def test_gzip_boundary_parser(self) -> None:
        gz_data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00"
        end = find_gzip_end(gz_data, start_offset=0)
        assert end is not None
        assert end == len(gz_data)

        assert find_gzip_end(b"\x1f\x8b", 0) is None
        assert find_gzip_end(b"NOT_GZIP", 0) is None

    def test_calculate_file_end_fallback(self) -> None:
        dummy_sig = FileSignature(
            name="TEST_SIG",
            extension="dat",
            magic=b"TEST",
            trailer=b"END!",
            min_size=8,
            max_size=1024,
        )
        data = b"TEST_PAYLOAD_HERE_END!EXTRA"
        end = calculate_file_end(dummy_sig, data, start_offset=0)
        assert end == len(b"TEST_PAYLOAD_HERE_END!")

        dummy_no_trailer = FileSignature(
            name="NO_TRAILER",
            extension="dat",
            magic=b"RAW",
            trailer=None,
            min_size=4,
            max_size=50,
        )
        data2 = b"RAW_SOME_DATA_WITHOUT_TRAILER_1234567890"
        end2 = calculate_file_end(dummy_no_trailer, data2, start_offset=0)
        assert end2 == len(data2)
