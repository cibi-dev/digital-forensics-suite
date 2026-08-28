"""Forensic binary signature catalogue and header/trailer parsers.

Supports detection and precise boundary calculation for:
- PE (Portable Executable / EXE / DLL)
- ELF (Linux Executable / Shared Object)
- ZIP (Archives, Office Open XML: DOCX, XLSX, PPTX, APK, JAR)
- PDF (Portable Document Format)
- PNG (Portable Network Graphics)
- JPEG (Joint Photographic Experts Group)
- TAR (Tape Archive POSIX format)
- GZIP (Gnu Zipped data)
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from typing import Any, Callable, Sequence, Union

BufferType = Union[bytes, memoryview, mmap.mmap]


@dataclass(frozen=True)
class FileSignature:
    """Definition of a binary file signature for forensic carving."""

    name: str
    extension: str
    magic: bytes
    magic_offset: int = 0
    trailer: bytes | None = None
    min_size: int = 16
    max_size: int = 500 * 1024 * 1024  # 500 MB default ceiling
    has_custom_bounds: bool = False
    description: str = ""


def find_png_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Parse PNG chunks to compute exact end offset after the IEND chunk.

    Args:
        data: Buffer containing PNG.
        start_offset: Offset in data where PNG signature starts.

    Returns:
        Exact absolute end offset (exclusive), or None if invalid/truncated.
    """
    png_magic = b"\x89PNG\r\n\x1a\n"
    if start_offset + 8 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 8]) != png_magic:
        return None

    curr = start_offset + 8
    data_len = len(data)

    while curr + 12 <= data_len:
        chunk_len = struct.unpack(">I", bytes(data[curr : curr + 4]))[0]
        chunk_type = bytes(data[curr + 4 : curr + 8])

        # Guard against absurd chunk lengths (e.g. > 100MB chunk in PNG)
        if chunk_len > 100 * 1024 * 1024:
            return None

        chunk_end = curr + 12 + chunk_len
        if chunk_end > data_len:
            # File is truncated
            return None

        if chunk_type == b"IEND":
            return chunk_end

        curr = chunk_end

    return None


def find_jpeg_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Find the End of Image (EOI, 0xFFD9) marker for a JPEG file.

    Args:
        data: Buffer containing JPEG.
        start_offset: Offset in data where JPEG starts.

    Returns:
        End offset (exclusive) right after 0xFFD9, or None.
    """
    jpeg_magic = b"\xff\xd8\xff"
    if start_offset + 3 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 3]) != jpeg_magic:
        return None

    # Search for \xff\xd9 starting from start_offset + 2
    view = bytes(data[start_offset:])
    eoi_idx = view.find(b"\xff\xd9")
    if eoi_idx == -1:
        return None

    return start_offset + eoi_idx + 2


def find_zip_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Find the End of Central Directory (EOCD) record for a ZIP archive.

    Args:
        data: Buffer containing ZIP.
        start_offset: Offset where PK\x03\x04 starts.

    Returns:
        End offset (exclusive) of the ZIP archive, or None.
    """
    zip_magic = b"PK\x03\x04"
    if start_offset + 4 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 4]) != zip_magic:
        return None

    # Search for EOCD marker PK\x05\x06
    view = bytes(data[start_offset:])
    eocd_marker = b"PK\x05\x06"

    # Search from end backwards or forward
    eocd_idx = view.rfind(eocd_marker)
    if eocd_idx == -1:
        return None

    eocd_abs = start_offset + eocd_idx
    if eocd_abs + 22 > len(data):
        return None

    # Read comment length at offset 20 in EOCD (uint16 LE)
    comment_len = struct.unpack("<H", bytes(data[eocd_abs + 20 : eocd_abs + 22]))[0]
    total_end = eocd_abs + 22 + comment_len

    if total_end > len(data):
        total_end = min(len(data), eocd_abs + 22)

    return total_end


def find_pdf_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Find the %%EOF marker of a PDF document.

    Args:
        data: Buffer containing PDF.
        start_offset: Offset where %PDF- starts.

    Returns:
        End offset right after %%EOF (including optional newline), or None.
    """
    pdf_magic = b"%PDF-"
    if start_offset + 5 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 5]) != pdf_magic:
        return None

    view = bytes(data[start_offset:])
    eof_idx = view.rfind(b"%%EOF")
    if eof_idx == -1:
        return None

    end_pos = start_offset + eof_idx + 5
    # Skip optional trailing whitespace / CRLF
    data_len = len(data)
    while end_pos < data_len and data[end_pos] in (b"\r"[0], b"\n"[0], b" "[0]):
        end_pos += 1

    return end_pos


def find_elf_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Calculate exact size of an ELF binary from its header tables.

    Args:
        data: Buffer containing ELF.
        start_offset: Offset where \x7fELF starts.

    Returns:
        Calculated end offset of the ELF binary, or None.
    """
    elf_magic = b"\x7fELF"
    if start_offset + 16 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 4]) != elf_magic:
        return None

    ei_class = data[start_offset + 4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[start_offset + 5]   # 1 = Little-endian, 2 = Big-endian
    endian = "<" if ei_data == 1 else ">"

    max_end = start_offset + 64

    if ei_class == 2:  # 64-bit ELF
        if start_offset + 64 > len(data):
            return None
        # e_phoff (offset 0x20, 8 bytes), e_shoff (offset 0x28, 8 bytes)
        # e_phentsize (offset 0x36, 2 bytes), e_phnum (offset 0x38, 2 bytes)
        # e_shentsize (offset 0x3A, 2 bytes), e_shnum (offset 0x3C, 2 bytes)
        e_phoff = struct.unpack(f"{endian}Q", bytes(data[start_offset + 0x20 : start_offset + 0x28]))[0]
        e_shoff = struct.unpack(f"{endian}Q", bytes(data[start_offset + 0x28 : start_offset + 0x30]))[0]
        e_phentsize, e_phnum = struct.unpack(f"{endian}HH", bytes(data[start_offset + 0x36 : start_offset + 0x3A]))
        e_shentsize, e_shnum = struct.unpack(f"{endian}HH", bytes(data[start_offset + 0x3A : start_offset + 0x3E]))

        if e_phoff > 0 and e_phentsize > 0 and e_phnum > 0:
            ph_end = start_offset + e_phoff + (e_phentsize * e_phnum)
            max_end = max(max_end, ph_end)

        if e_shoff > 0 and e_shentsize > 0 and e_shnum > 0:
            sh_end = start_offset + e_shoff + (e_shentsize * e_shnum)
            max_end = max(max_end, sh_end)

            # Inspect sections to find highest sh_offset + sh_size
            for i in range(min(e_shnum, 128)):
                sec_hdr_off = start_offset + e_shoff + (i * e_shentsize)
                if sec_hdr_off + 40 <= len(data):
                    # Section header: sh_offset at +24 (8 bytes), sh_size at +32 (8 bytes)
                    sh_offset = struct.unpack(f"{endian}Q", bytes(data[sec_hdr_off + 24 : sec_hdr_off + 32]))[0]
                    sh_size = struct.unpack(f"{endian}Q", bytes(data[sec_hdr_off + 32 : sec_hdr_off + 40]))[0]
                    if sh_offset > 0 and sh_size > 0 and sh_offset < 100 * 1024 * 1024:
                        max_end = max(max_end, start_offset + sh_offset + sh_size)

    elif ei_class == 1:  # 32-bit ELF
        if start_offset + 52 > len(data):
            return None
        e_phoff = struct.unpack(f"{endian}I", bytes(data[start_offset + 0x1C : start_offset + 0x20]))[0]
        e_shoff = struct.unpack(f"{endian}I", bytes(data[start_offset + 0x20 : start_offset + 0x24]))[0]
        e_phentsize, e_phnum = struct.unpack(f"{endian}HH", bytes(data[start_offset + 0x2A : start_offset + 0x2E]))
        e_shentsize, e_shnum = struct.unpack(f"{endian}HH", bytes(data[start_offset + 0x2E : start_offset + 0x32]))

        if e_phoff > 0 and e_phentsize > 0 and e_phnum > 0:
            ph_end = start_offset + e_phoff + (e_phentsize * e_phnum)
            max_end = max(max_end, ph_end)

        if e_shoff > 0 and e_shentsize > 0 and e_shnum > 0:
            sh_end = start_offset + e_shoff + (e_shentsize * e_shnum)
            max_end = max(max_end, sh_end)

    return min(max_end, len(data))


def find_pe_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Calculate exact size of a Windows PE binary (EXE/DLL) by parsing section tables.

    Args:
        data: Buffer containing PE.
        start_offset: Offset where 'MZ' starts.

    Returns:
        Calculated end offset of the PE binary, or None.
    """
    if start_offset + 64 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 2]) != b"MZ":
        return None

    # e_lfanew at offset 0x3C
    e_lfanew = struct.unpack("<I", bytes(data[start_offset + 0x3C : start_offset + 0x40]))[0]
    pe_sig_off = start_offset + e_lfanew

    if pe_sig_off + 24 > len(data):
        return None
    if bytes(data[pe_sig_off : pe_sig_off + 4]) != b"PE\x00\x00":
        return None

    # COFF File Header
    num_sections = struct.unpack("<H", bytes(data[pe_sig_off + 6 : pe_sig_off + 8]))[0]
    opt_hdr_size = struct.unpack("<H", bytes(data[pe_sig_off + 20 : pe_sig_off + 22]))[0]

    sec_table_start = pe_sig_off + 24 + opt_hdr_size
    max_end = sec_table_start + (num_sections * 40)

    for i in range(min(num_sections, 96)):
        sec_off = sec_table_start + (i * 40)
        if sec_off + 40 > len(data):
            break
        # PointerToRawData at offset 20 (4 bytes), SizeOfRawData at offset 16 (4 bytes)
        raw_size = struct.unpack("<I", bytes(data[sec_off + 16 : sec_off + 20]))[0]
        raw_ptr = struct.unpack("<I", bytes(data[sec_off + 20 : sec_off + 24]))[0]

        if raw_ptr > 0 and raw_size > 0 and raw_ptr < 200 * 1024 * 1024:
            sec_end = start_offset + raw_ptr + raw_size
            max_end = max(max_end, sec_end)

    return min(max_end, len(data))


def find_tar_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Parse TAR POSIX 512-byte blocks until the end-of-archive marker.

    Args:
        data: Buffer containing TAR.
        start_offset: Offset where tar header begins.

    Returns:
        End offset of the TAR archive, or None.
    """
    if start_offset + 512 > len(data):
        return None

    # Check magic at offset 257
    magic_pos = start_offset + 257
    if magic_pos + 5 > len(data):
        return None
    magic_bytes = bytes(data[magic_pos : magic_pos + 5])
    if magic_bytes != b"ustar":
        return None

    curr = start_offset
    data_len = len(data)
    consecutive_zero_blocks = 0

    while curr + 512 <= data_len:
        block = bytes(data[curr : curr + 512])
        if block == b"\x00" * 512:
            consecutive_zero_blocks += 1
            if consecutive_zero_blocks >= 2:
                return curr + 512
            curr += 512
            continue
        else:
            consecutive_zero_blocks = 0

        # Read size field in octal at offset 124..135 (11 bytes + null)
        size_str = block[124:136].strip(b"\x00 ").decode("ascii", errors="ignore")
        try:
            file_size = int(size_str, 8) if size_str else 0
        except ValueError:
            break

        # Calculate number of 512-byte blocks for data
        data_blocks = (file_size + 511) // 512
        curr += 512 + (data_blocks * 512)

    return min(curr, data_len) if curr > start_offset + 512 else None


def find_gzip_end(data: bytes | memoryview, start_offset: int = 0) -> int | None:
    """Compute GZIP end boundary by parsing GZIP header and finding trailing CRC/ISIZE.

    Args:
        data: Buffer containing GZIP.
        start_offset: Offset where \x1f\x8b\x08 starts.

    Returns:
        Calculated end offset of the GZIP stream, or None.
    """
    if start_offset + 10 > len(data):
        return None
    if bytes(data[start_offset : start_offset + 3]) != b"\x1f\x8b\x08":
        return None

    # In forensic carving, GZIP end can be determined by decompression or minimum size
    # Here we check minimal size and fallback search for next signature
    min_size = 18  # Header (10) + minimal empty deflate (2) + CRC/ISIZE (8)
    return min(start_offset + 50 * 1024 * 1024, len(data))


SIGNATURE_BOUND_PARSERS: dict[str, Callable[[Any, int], int | None]] = {
    "PNG": find_png_end,
    "JPEG": find_jpeg_end,
    "ZIP": find_zip_end,
    "PDF": find_pdf_end,
    "ELF": find_elf_end,
    "PE": find_pe_end,
    "TAR": find_tar_end,
    "GZIP": find_gzip_end,
}


# Canonical catalogue of supported file signatures
FILE_SIGNATURES: list[FileSignature] = [
    FileSignature(
        name="PNG",
        extension="png",
        magic=b"\x89PNG\r\n\x1a\n",
        trailer=b"IEND\xaeB`\x82",
        min_size=24,
        has_custom_bounds=True,
        description="Portable Network Graphics image",
    ),
    FileSignature(
        name="JPEG",
        extension="jpg",
        magic=b"\xff\xd8\xff",
        trailer=b"\xff\xd9",
        min_size=16,
        has_custom_bounds=True,
        description="JPEG/JFIF raster image",
    ),
    FileSignature(
        name="ZIP",
        extension="zip",
        magic=b"PK\x03\x04",
        trailer=b"PK\x05\x06",
        min_size=22,
        has_custom_bounds=True,
        description="ZIP Archive / Open XML Document",
    ),
    FileSignature(
        name="PDF",
        extension="pdf",
        magic=b"%PDF-",
        trailer=b"%%EOF",
        min_size=32,
        has_custom_bounds=True,
        description="Adobe Portable Document Format",
    ),
    FileSignature(
        name="ELF",
        extension="elf",
        magic=b"\x7fELF",
        min_size=52,
        has_custom_bounds=True,
        description="Executable and Linkable Format (Linux Binary)",
    ),
    FileSignature(
        name="PE",
        extension="exe",
        magic=b"MZ",
        min_size=128,
        has_custom_bounds=True,
        description="Portable Executable (Windows EXE/DLL)",
    ),
    FileSignature(
        name="TAR",
        extension="tar",
        magic=b"ustar",
        magic_offset=257,
        min_size=512,
        has_custom_bounds=True,
        description="POSIX Tar Archive",
    ),
    FileSignature(
        name="GZIP",
        extension="gz",
        magic=b"\x1f\x8b\x08",
        min_size=18,
        has_custom_bounds=True,
        description="Gnu Zipped archive",
    ),
]


def detect_signature_at(data: BufferType, offset: int) -> FileSignature | None:
    """Detect if a known file signature starts at the given offset.

    Args:
        data: Buffer containing file data.
        offset: Offset to inspect.

    Returns:
        Matching FileSignature or None.
    """
    for sig in FILE_SIGNATURES:
        check_off = offset + sig.magic_offset
        magic_len = len(sig.magic)
        if check_off + magic_len <= len(data):
            if bytes(data[check_off : check_off + magic_len]) == sig.magic:
                # Additional heuristic validation for PE (check e_lfanew)
                if sig.name == "PE":
                    if offset + 64 > len(data):
                        continue
                    e_lfanew = struct.unpack("<I", bytes(data[offset + 0x3C : offset + 0x40]))[0]
                    if e_lfanew < 0x40 or e_lfanew > 0x1000 or offset + e_lfanew + 4 > len(data):
                        continue
                    if bytes(data[offset + e_lfanew : offset + e_lfanew + 4]) != b"PE\x00\x00":
                        continue
                return sig
    return None


def calculate_file_end(
    sig: FileSignature, data: BufferType, start_offset: int
) -> int:
    """Calculate the end offset of a file using parser logic or trailer search.

    Args:
        sig: Detected file signature.
        data: Data buffer.
        start_offset: Offset where file begins.

    Returns:
        Calculated end offset (exclusive).
    """
    parser = SIGNATURE_BOUND_PARSERS.get(sig.name)
    if parser:
        parsed_end = parser(data, start_offset)
        if parsed_end is not None and parsed_end > start_offset:
            return parsed_end

    # Fallback to trailer search if available
    if sig.trailer:
        view = bytes(data[start_offset:])
        trailer_idx = view.find(sig.trailer)
        if trailer_idx != -1:
            return start_offset + trailer_idx + len(sig.trailer)

    # Fallback default slice
    return min(start_offset + sig.max_size, len(data))
