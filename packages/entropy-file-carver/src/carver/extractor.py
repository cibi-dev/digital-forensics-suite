"""Secure embedded file extractor using memory-mapped I/O (mmap).

Provides zero-copy / chunked slicing, path traversal defense (CWE-22),
and stream quota protections (CWE-400).
"""

from __future__ import annotations

import hashlib
import logging
import mmap
import os
from pathlib import Path
from typing import Generator, Sequence
from pydantic import BaseModel, Field

from carver.entropy import calculate_entropy
from carver.signatures import (
    FILE_SIGNATURES,
    FileSignature,
    calculate_file_end,
    detect_signature_at,
)
from carver.validator import FileValidator, ValidationResult

logger = logging.getLogger("carver.extractor")


class CarvedFile(BaseModel):
    """Metadata record representing a carved file artifact."""

    offset: int = Field(..., description="Starting byte offset in source binary", ge=0)
    end_offset: int = Field(..., description="Ending byte offset in source binary", ge=0)
    size: int = Field(..., description="Carved file size in bytes", ge=0)
    format_name: str = Field(..., description="File format name (PNG, ZIP, etc.)")
    extension: str = Field(..., description="File extension")
    sha256: str = Field(..., description="SHA-256 checksum of extracted file")
    entropy: float = Field(..., description="Shannon entropy of the carved file", ge=0.0, le=8.0)
    is_valid: bool = Field(default=True, description="Whether structural validation succeeded")
    validation_reason: str = Field(default="", description="Summary of format validation")
    has_stego: bool = Field(default=False, description="Flag for detected steganography or encrypted overlay")
    anomaly_score: float = Field(default=0.0, description="Risk anomaly score", ge=0.0, le=1.0)
    output_path: str | None = Field(default=None, description="Absolute path to carved file on disk")
    error: str | None = Field(default=None, description="Error message if extraction failed")


class ExtractionResult(BaseModel):
    """Aggregate statistics and artifacts from an extraction run."""

    source_file: str = Field(..., description="Path to source file analyzed")
    total_scanned_bytes: int = Field(..., description="Total bytes scanned in source binary", ge=0)
    files_found: int = Field(..., description="Total candidate signatures found", ge=0)
    files_carved: int = Field(..., description="Total successfully extracted files", ge=0)
    carved_files: list[CarvedFile] = Field(default_factory=list, description="List of carved file objects")
    errors: list[str] = Field(default_factory=list, description="Non-fatal warnings and errors encountered")


class Extractor:
    """Enterprise-grade forensic file carver operating via memory-mapped streaming."""

    def __init__(
        self,
        min_size: int = 16,
        max_file_size: int = 200 * 1024 * 1024,  # 200 MB max per file
        max_total_files: int = 5000,
        validate_integrity: bool = True,
        signatures: Sequence[FileSignature] | None = None,
    ) -> None:
        self.min_size = min_size
        self.max_file_size = max_file_size
        self.max_total_files = max_total_files
        self.validate_integrity = validate_integrity
        self.signatures = list(signatures) if signatures is not None else FILE_SIGNATURES

    def scan_mmap(self, mm: mmap.mmap, file_size: int) -> Generator[tuple[int, int, FileSignature], None, None]:
        """Scan memory map and yield (start_offset, end_offset, signature) for detected files."""
        curr_offset = 0

        while curr_offset < file_size:
            sig = detect_signature_at(mm, curr_offset)
            if sig is None:
                curr_offset += 1
                continue

            # Calculate prospective end offset
            end_offset = calculate_file_end(sig, mm, curr_offset)
            file_len = end_offset - curr_offset

            if file_len < self.min_size or file_len < sig.min_size:
                curr_offset += 1
                continue

            # Guard against extreme sizes
            if file_len > self.max_file_size:
                end_offset = min(curr_offset + self.max_file_size, file_size)

            yield (curr_offset, end_offset, sig)

            # Advance offset to avoid duplicate nested detections of the same signature
            curr_offset = max(curr_offset + 1, end_offset)

    def carve_file(
        self,
        source_path: str | Path,
        output_dir: str | Path | None = None,
    ) -> ExtractionResult:
        """Scan and carve embedded files from a binary file.

        Args:
            source_path: Path to target disk image or dump.
            output_dir: Directory where carved files will be saved (optional).

        Returns:
            ExtractionResult with metadata for all carved files.
        """
        source_resolved = Path(source_path).resolve()
        if not source_resolved.is_file():
            raise FileNotFoundError(f"Source file not found: {source_resolved}")

        file_size = source_resolved.stat().st_size
        if file_size == 0:
            return ExtractionResult(
                source_file=str(source_resolved),
                total_scanned_bytes=0,
                files_found=0,
                files_carved=0,
                carved_files=[],
                errors=[],
            )

        out_dir_resolved: Path | None = None
        if output_dir is not None:
            out_dir_resolved = Path(output_dir).resolve()
            out_dir_resolved.mkdir(parents=True, exist_ok=True)

        carved_list: list[CarvedFile] = []
        errors: list[str] = []

        with open(source_resolved, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for start_offset, end_offset, sig in self.scan_mmap(mm, file_size):
                    if len(carved_list) >= self.max_total_files:
                        errors.append(f"Reached maximum extraction limit of {self.max_total_files} files.")
                        break

                    try:
                        carved = self._extract_slice(
                            mm=mm,
                            start_offset=start_offset,
                            end_offset=end_offset,
                            sig=sig,
                            output_dir=out_dir_resolved,
                        )
                        carved_list.append(carved)
                    except Exception as exc:
                        # Fail-open / resilient error handling (CWE-209)
                        err_msg = f"Failed to carve {sig.name} at 0x{start_offset:08X}: {str(exc)}"
                        logger.warning(err_msg)
                        errors.append(err_msg)

        return ExtractionResult(
            source_file=str(source_resolved),
            total_scanned_bytes=file_size,
            files_found=len(carved_list),
            files_carved=len([c for c in carved_list if c.output_path is not None or not output_dir]),
            carved_files=carved_list,
            errors=errors,
        )

    def _extract_slice(
        self,
        mm: mmap.mmap,
        start_offset: int,
        end_offset: int,
        sig: FileSignature,
        output_dir: Path | None,
    ) -> CarvedFile:
        """Securely stream a slice from mmap, calculate hash and entropy, and write to disk."""
        file_len = end_offset - start_offset
        hasher = hashlib.sha256()

        # For entropy and validation, inspect chunk buffer
        # If file is reasonable size (<10MB), read for validation
        sample_size = min(file_len, 10 * 1024 * 1024)
        sample_bytes = bytes(mm[start_offset : start_offset + sample_size])
        entropy = calculate_entropy(sample_bytes)

        # Validate format integrity if requested
        is_valid = True
        validation_reason = "Not validated"
        has_stego = False
        anomaly_score = 0.0

        if self.validate_integrity:
            # Include trailing lookahead window to inspect for appended overlay/steganography
            lookahead_end = min(start_offset + file_len + 4096, mm.size())
            val_slice = bytes(mm[start_offset:lookahead_end])
            val_res: ValidationResult = FileValidator.validate(sig.name, val_slice)
            is_valid = val_res.is_valid
            validation_reason = val_res.reason
            has_stego = val_res.has_stego_or_encryption
            anomaly_score = val_res.anomaly_score

        out_path_str: str | None = None

        if output_dir is not None:
            # Construct safe filename
            filename = f"carved_0x{start_offset:08x}_{sig.name.lower()}.{sig.extension}"
            target_path = (output_dir / filename).resolve()

            # CWE-22 Defense: Path Traversal check
            output_dir_real = os.path.realpath(str(output_dir))
            target_path_real = os.path.realpath(str(target_path))
            if os.path.commonpath([output_dir_real, target_path_real]) != output_dir_real:
                raise PermissionError(f"Security Violation (CWE-22): Path traversal detected -> {target_path}")

            # Stream slice out in 64KB blocks without loading whole file in RAM
            with open(target_path_real, "wb") as out_f:
                curr = start_offset
                while curr < end_offset:
                    chunk_len = min(65536, end_offset - curr)
                    chunk = mm[curr : curr + chunk_len]
                    out_f.write(chunk)
                    hasher.update(chunk)
                    curr += chunk_len

            out_path_str = target_path_real
        else:
            # If no output dir, compute hash over slice
            curr = start_offset
            while curr < end_offset:
                chunk_len = min(65536, end_offset - curr)
                chunk = mm[curr : curr + chunk_len]
                hasher.update(chunk)
                curr += chunk_len

        return CarvedFile(
            offset=start_offset,
            end_offset=end_offset,
            size=file_len,
            format_name=sig.name,
            extension=sig.extension,
            sha256=hasher.hexdigest(),
            entropy=entropy,
            is_valid=is_valid,
            validation_reason=validation_reason,
            has_stego=has_stego,
            anomaly_score=anomaly_score,
            output_path=out_path_str,
        )


def carve_files_from_mmap(
    source_path: str | Path,
    output_dir: str | Path | None = None,
    validate: bool = True,
) -> ExtractionResult:
    """Convenience functional wrapper to carve files from a binary resource."""
    extractor = Extractor(validate_integrity=validate)
    return extractor.carve_file(source_path=source_path, output_dir=output_dir)
