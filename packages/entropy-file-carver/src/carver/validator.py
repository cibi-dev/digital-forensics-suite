"""Integrity validation and hidden steganography/encryption detection for carved files.

Enforces strict security checks:
- CWE-409: Zip Bomb mitigation via decompression ratio (<100:1), size (<500MB), and member quotas.
- CWE-59: Symlink escape detection within carved archives.
- Forensic overlay analysis: Detection of encrypted payloads and steganography appended after file trailers.
"""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from carver.entropy import calculate_entropy
from carver.signatures import (
    find_png_end,
    find_jpeg_end,
    find_zip_end,
    find_pdf_end,
    find_elf_end,
    find_pe_end,
)


class ValidationResult(BaseModel):
    """Forensic validation report for a carved file."""

    is_valid: bool = Field(..., description="Whether the file structure is valid for its format")
    format_name: str = Field(..., description="Detected file format name")
    reason: str = Field(..., description="Validation summary or failure explanation")
    details: dict[str, Any] = Field(default_factory=dict, description="Detailed format metadata")
    has_stego_or_encryption: bool = Field(
        default=False, description="Flag indicating detected hidden encrypted or steganographic payload"
    )
    anomaly_score: float = Field(
        default=0.0, description="Risk anomaly score (0.0 normal, 1.0 critical)", ge=0.0, le=1.0
    )
    overlay_bytes: int = Field(default=0, description="Number of trailing bytes after canonical trailer", ge=0)
    overlay_entropy: float = Field(default=0.0, description="Shannon entropy of trailing overlay bytes", ge=0.0, le=8.0)


class FileValidator:
    """Enterprise-grade forensic file validator and steganography detector."""

    MAX_UNCOMPRESSED_ARCHIVE_BYTES = 500 * 1024 * 1024  # 500 MB (CWE-409)
    MAX_ARCHIVE_MEMBERS = 10_000                       # Max 10,000 files in archive
    MAX_COMPRESSION_RATIO = 100.0                      # Max 100:1 ratio before flagging bomb
    STEGO_ENTROPY_THRESHOLD = 7.0                      # Entropy threshold for encrypted/stego payloads

    @classmethod
    def validate_zip(cls, data: bytes) -> ValidationResult:
        """Validate ZIP archive structure and test for CWE-409 (Zip Bomb) and CWE-59 (Symlinks)."""
        if len(data) < 22:
            return ValidationResult(
                is_valid=False,
                format_name="ZIP",
                reason="Corrupt ZIP: file smaller than minimum EOCD record (22 bytes)",
            )

        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                infolist = zf.infolist()
                total_uncompressed = sum(info.file_size for info in infolist)
                total_compressed = sum(info.compress_size for info in infolist)
                member_count = len(infolist)

                # CWE-409: Guard against member bomb
                if member_count > cls.MAX_ARCHIVE_MEMBERS:
                    return ValidationResult(
                        is_valid=False,
                        format_name="ZIP",
                        reason=f"Security Violation (CWE-409): Archive exceeds max member limit ({member_count} > {cls.MAX_ARCHIVE_MEMBERS})",
                        anomaly_score=1.0,
                    )

                # CWE-409: Guard against uncompressed size bomb
                if total_uncompressed > cls.MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                    return ValidationResult(
                        is_valid=False,
                        format_name="ZIP",
                        reason=f"Security Violation (CWE-409): Archive uncompressed size exceeds limit ({total_uncompressed:,} bytes > {cls.MAX_UNCOMPRESSED_ARCHIVE_BYTES:,} bytes)",
                        anomaly_score=1.0,
                    )

                # CWE-409: Guard against anomalous compression ratio
                ratio = (total_uncompressed / max(1, total_compressed)) if total_compressed > 0 else 1.0
                if ratio > cls.MAX_COMPRESSION_RATIO and total_uncompressed > 10 * 1024 * 1024:
                    return ValidationResult(
                        is_valid=False,
                        format_name="ZIP",
                        reason=f"Security Violation (CWE-409): Potential Zip Bomb detected (Compression ratio {ratio:.1f}:1 > {cls.MAX_COMPRESSION_RATIO}:1)",
                        anomaly_score=1.0,
                    )

                # CWE-59: Detect symlink members
                symlinks = []
                for info in infolist:
                    # Unix symlink flag: mode 0o120000
                    mode = info.external_attr >> 16
                    if (mode & 0o170000) == 0o120000:
                        symlinks.append(info.filename)

                details = {
                    "member_count": member_count,
                    "total_uncompressed": total_uncompressed,
                    "total_compressed": total_compressed,
                    "compression_ratio": round(ratio, 2),
                    "symlinks": symlinks,
                    "has_symlinks": len(symlinks) > 0,
                }

                if symlinks:
                    return ValidationResult(
                        is_valid=True,
                        format_name="ZIP",
                        reason=f"Valid ZIP with {len(symlinks)} symlinks detected (CWE-59 warning)",
                        details=details,
                        anomaly_score=0.6,
                    )

                return ValidationResult(
                    is_valid=True,
                    format_name="ZIP",
                    reason="Valid ZIP archive",
                    details=details,
                )

        except zipfile.BadZipFile as e:
            return ValidationResult(
                is_valid=False,
                format_name="ZIP",
                reason=f"Corrupt ZIP structure: {str(e)}",
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                format_name="ZIP",
                reason=f"ZIP validation error: {str(e)}",
            )

    @classmethod
    def validate_tar(cls, data: bytes) -> ValidationResult:
        """Validate TAR archive structure and test for symlinks and bombs."""
        if len(data) < 512:
            return ValidationResult(
                is_valid=False,
                format_name="TAR",
                reason="Corrupt TAR: file smaller than single 512-byte block",
            )

        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                members = tf.getmembers()
                total_size = sum(m.size for m in members)
                member_count = len(members)

                if member_count > cls.MAX_ARCHIVE_MEMBERS:
                    return ValidationResult(
                        is_valid=False,
                        format_name="TAR",
                        reason=f"Security Violation (CWE-409): Tar exceeds member limit ({member_count} > {cls.MAX_ARCHIVE_MEMBERS})",
                        anomaly_score=1.0,
                    )

                if total_size > cls.MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                    return ValidationResult(
                        is_valid=False,
                        format_name="TAR",
                        reason=f"Security Violation (CWE-409): Tar uncompressed size exceeds limit ({total_size:,} bytes)",
                        anomaly_score=1.0,
                    )

                symlinks = [m.name for m in members if m.issym() or m.islnk()]
                details = {
                    "member_count": member_count,
                    "total_uncompressed": total_size,
                    "symlinks": symlinks,
                    "has_symlinks": len(symlinks) > 0,
                }

                return ValidationResult(
                    is_valid=True,
                    format_name="TAR",
                    reason=f"Valid TAR archive with {member_count} members",
                    details=details,
                    anomaly_score=0.4 if symlinks else 0.0,
                )
        except tarfile.TarError as e:
            return ValidationResult(
                is_valid=False,
                format_name="TAR",
                reason=f"Corrupt TAR: {str(e)}",
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                format_name="TAR",
                reason=f"TAR validation error: {str(e)}",
            )

    @classmethod
    def validate_png(cls, data: bytes) -> ValidationResult:
        """Validate PNG structure and check for trailing overlay data."""
        png_magic = b"\x89PNG\r\n\x1a\n"
        if len(data) < 24 or not data.startswith(png_magic):
            return ValidationResult(
                is_valid=False,
                format_name="PNG",
                reason="Invalid PNG: missing standard 8-byte magic header",
            )

        canonical_end = find_png_end(data, 0)
        if canonical_end is None:
            return ValidationResult(
                is_valid=False,
                format_name="PNG",
                reason="Corrupt PNG: truncated chunks or missing IEND terminator",
            )

        # Inspect IHDR
        width, height, bit_depth, color_type = struct.unpack(">IIBB", data[16:26])

        # Analyze trailing overlay (strip trailing sector null padding to avoid entropy dilution)
        overlay = data[canonical_end:]
        overlay_len = len(overlay)
        overlay_payload = overlay.rstrip(b"\x00")
        overlay_ent = calculate_entropy(overlay_payload) if len(overlay_payload) > 0 else 0.0

        has_stego = len(overlay_payload) >= 16 and overlay_ent >= cls.STEGO_ENTROPY_THRESHOLD
        anomaly_score = 0.9 if has_stego else (0.3 if overlay_len > 0 else 0.0)

        details = {
            "width": width,
            "height": height,
            "bit_depth": bit_depth,
            "color_type": color_type,
            "canonical_size": canonical_end,
            "total_size": len(data),
            "overlay_bytes": overlay_len,
        }

        reason = "Valid PNG image"
        if has_stego:
            reason = f"Valid PNG with High-Entropy Overlay ({overlay_len} bytes, H={overlay_ent:.2f} bits) - Potential Stego/Payload"
        elif overlay_len > 0:
            reason = f"Valid PNG with {overlay_len} trailing overlay bytes"

        return ValidationResult(
            is_valid=True,
            format_name="PNG",
            reason=reason,
            details=details,
            has_stego_or_encryption=has_stego,
            anomaly_score=anomaly_score,
            overlay_bytes=overlay_len,
            overlay_entropy=round(overlay_ent, 4),
        )

    @classmethod
    def validate_jpeg(cls, data: bytes) -> ValidationResult:
        """Validate JPEG structure (SOI, markers, EOI) and detect trailing overlay."""
        if len(data) < 4 or not data.startswith(b"\xff\xd8\xff"):
            return ValidationResult(
                is_valid=False,
                format_name="JPEG",
                reason="Invalid JPEG: missing SOI marker (\xFF\xD8\xFF)",
            )

        eoi_idx = data.find(b"\xff\xd9")
        if eoi_idx == -1:
            return ValidationResult(
                is_valid=False,
                format_name="JPEG",
                reason="Corrupt JPEG: missing EOI marker (\xFF\xD9)",
            )

        canonical_end = eoi_idx + 2
        overlay = data[canonical_end:]
        overlay_len = len(overlay)
        overlay_payload = overlay.rstrip(b"\x00")
        overlay_ent = calculate_entropy(overlay_payload) if len(overlay_payload) > 0 else 0.0

        has_stego = len(overlay_payload) >= 16 and overlay_ent >= cls.STEGO_ENTROPY_THRESHOLD
        anomaly_score = 0.9 if has_stego else (0.2 if overlay_len > 0 else 0.0)

        details = {
            "canonical_size": canonical_end,
            "total_size": len(data),
            "overlay_bytes": overlay_len,
        }

        reason = "Valid JPEG image"
        if has_stego:
            reason = f"Valid JPEG with High-Entropy Overlay ({len(overlay_payload)} bytes, H={overlay_ent:.2f} bits) - Potential Stego/Payload"

        return ValidationResult(
            is_valid=True,
            format_name="JPEG",
            reason=reason,
            details=details,
            has_stego_or_encryption=has_stego,
            anomaly_score=anomaly_score,
            overlay_bytes=overlay_len,
            overlay_entropy=round(overlay_ent, 4),
        )

    @classmethod
    def validate_pdf(cls, data: bytes) -> ValidationResult:
        """Validate PDF document structure and check for EOF trailers."""
        if len(data) < 16 or not data.startswith(b"%PDF-"):
            return ValidationResult(
                is_valid=False,
                format_name="PDF",
                reason="Invalid PDF: missing %PDF- header",
            )

        eof_idx = data.rfind(b"%%EOF")
        if eof_idx == -1:
            return ValidationResult(
                is_valid=False,
                format_name="PDF",
                reason="Corrupt PDF: missing %%EOF trailer",
            )

        version = data[:8].decode("ascii", errors="ignore").strip()
        canonical_end = find_pdf_end(data, 0) or (eof_idx + 5)
        overlay = data[canonical_end:]
        overlay_len = len(overlay)
        overlay_payload = overlay.rstrip(b"\x00")
        overlay_ent = calculate_entropy(overlay_payload) if len(overlay_payload) > 0 else 0.0

        has_stego = len(overlay_payload) >= 32 and overlay_ent >= cls.STEGO_ENTROPY_THRESHOLD
        anomaly_score = 0.85 if has_stego else 0.0

        return ValidationResult(
            is_valid=True,
            format_name="PDF",
            reason="Valid PDF document" if not has_stego else "Valid PDF with suspicious high-entropy trailing data",
            details={"version": version, "canonical_size": canonical_end, "total_size": len(data)},
            has_stego_or_encryption=has_stego,
            anomaly_score=anomaly_score,
            overlay_bytes=overlay_len,
            overlay_entropy=round(overlay_ent, 4),
        )

    @classmethod
    def validate_elf(cls, data: bytes) -> ValidationResult:
        """Validate Linux ELF binary headers and verify section table bounds."""
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return ValidationResult(
                is_valid=False,
                format_name="ELF",
                reason="Invalid ELF: missing \\x7fELF magic",
            )

        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = LE, 2 = BE
        endian = "<" if ei_data == 1 else ">"

        bitness = 64 if ei_class == 2 else 32
        details = {
            "bitness": bitness,
            "endian": "little" if ei_data == 1 else "big",
            "elf_version": data[6],
            "os_abi": data[7],
        }

        canonical_end = find_elf_end(data, 0) or len(data)
        overlay = data[canonical_end:]
        overlay_len = len(overlay)
        overlay_payload = overlay.rstrip(b"\x00")
        overlay_ent = calculate_entropy(overlay_payload) if len(overlay_payload) > 0 else 0.0
        has_stego = len(overlay_payload) >= 64 and overlay_ent >= cls.STEGO_ENTROPY_THRESHOLD

        return ValidationResult(
            is_valid=True,
            format_name="ELF",
            reason=f"Valid ELF {bitness}-bit binary",
            details=details,
            has_stego_or_encryption=has_stego,
            anomaly_score=0.8 if has_stego else 0.0,
            overlay_bytes=overlay_len,
            overlay_entropy=round(overlay_ent, 4),
        )

    @classmethod
    def validate_pe(cls, data: bytes) -> ValidationResult:
        """Validate Windows PE executable and inspect section table."""
        if len(data) < 64 or not data.startswith(b"MZ"):
            return ValidationResult(
                is_valid=False,
                format_name="PE",
                reason="Invalid PE: missing 'MZ' DOS header",
            )

        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if e_lfanew + 24 > len(data):
            return ValidationResult(
                is_valid=False,
                format_name="PE",
                reason="Corrupt PE: e_lfanew points outside file boundaries",
            )

        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return ValidationResult(
                is_valid=False,
                format_name="PE",
                reason="Invalid PE: missing PE\\0\\0 signature at e_lfanew",
            )

        machine, num_sections = struct.unpack("<HH", data[e_lfanew + 4 : e_lfanew + 8])
        details = {
            "machine": hex(machine),
            "number_of_sections": num_sections,
            "e_lfanew": e_lfanew,
        }

        canonical_end = find_pe_end(data, 0) or len(data)
        overlay = data[canonical_end:]
        overlay_len = len(overlay)
        overlay_payload = overlay.rstrip(b"\x00")
        overlay_ent = calculate_entropy(overlay_payload) if len(overlay_payload) > 0 else 0.0
        has_stego = len(overlay_payload) >= 64 and overlay_ent >= cls.STEGO_ENTROPY_THRESHOLD

        return ValidationResult(
            is_valid=True,
            format_name="PE",
            reason=f"Valid PE executable with {num_sections} sections",
            details=details,
            has_stego_or_encryption=has_stego,
            anomaly_score=0.85 if has_stego else 0.0,
            overlay_bytes=overlay_len,
            overlay_entropy=round(overlay_ent, 4),
        )

    @classmethod
    def validate_gzip(cls, data: bytes) -> ValidationResult:
        """Validate GZIP header and stream integrity."""
        if len(data) < 10 or not data.startswith(b"\x1f\x8b\x08"):
            return ValidationResult(
                is_valid=False,
                format_name="GZIP",
                reason="Invalid GZIP: missing \\x1f\\x8b\\x08 header",
            )

        import gzip
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
                # Read first 1MB to verify stream validity
                decompressed = gz.read(1024 * 1024)
                return ValidationResult(
                    is_valid=True,
                    format_name="GZIP",
                    reason="Valid GZIP compressed stream",
                    details={"sample_decompressed_bytes": len(decompressed)},
                )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                format_name="GZIP",
                reason=f"Corrupt GZIP stream: {str(e)}",
            )

    @classmethod
    def validate(cls, format_name: str, data: bytes) -> ValidationResult:
        """Dispatcher to validate data for the specified format."""
        validators = {
            "ZIP": cls.validate_zip,
            "TAR": cls.validate_tar,
            "PNG": cls.validate_png,
            "JPEG": cls.validate_jpeg,
            "PDF": cls.validate_pdf,
            "ELF": cls.validate_elf,
            "PE": cls.validate_pe,
            "GZIP": cls.validate_gzip,
        }

        validator_func = validators.get(format_name.upper())
        if validator_func:
            return validator_func(data)

        # Fallback generic validation
        return ValidationResult(
            is_valid=len(data) > 0,
            format_name=format_name,
            reason=f"Generic buffer validation ({len(data)} bytes)",
            details={"size": len(data)},
        )


def validate_carved_file(format_name: str, file_path_or_bytes: str | Path | bytes) -> ValidationResult:
    """Validate a carved file from a path or raw bytes.

    Args:
        format_name: Target format (PNG, ZIP, PDF, etc.).
        file_path_or_bytes: Path to file or raw bytes.

    Returns:
        ValidationResult with structural integrity and security analysis.
    """
    if isinstance(file_path_or_bytes, (str, Path)):
        path = Path(file_path_or_bytes).resolve()
        if not path.is_file():
            return ValidationResult(
                is_valid=False,
                format_name=format_name,
                reason=f"File not found: {path}",
            )
        data = path.read_bytes()
    else:
        data = file_path_or_bytes

    return FileValidator.validate(format_name, data)


def detect_steganography_or_hidden_payload(data: bytes, format_name: str) -> tuple[bool, float, int, float]:
    """Inspect trailing bytes of a carved file for hidden encrypted or steganographic payloads.

    Args:
        data: Carved file byte buffer.
        format_name: Format name.

    Returns:
        Tuple of (has_hidden_payload, anomaly_score, overlay_bytes, overlay_entropy).
    """
    result = FileValidator.validate(format_name, data)
    return (
        result.has_stego_or_encryption,
        result.anomaly_score,
        result.overlay_bytes,
        result.overlay_entropy,
    )
