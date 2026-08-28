"""Tests for secure mmap-based embedded file extraction."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pytest

from carver.extractor import Extractor, carve_files_from_mmap
from tests.test_signatures import (
    create_minimal_jpeg,
    create_minimal_pdf,
    create_minimal_png,
    create_minimal_zip,
)


class TestExtractorSuite:
    """Extraction tests with synthetic disk dumps containing embedded artifacts."""

    @pytest.fixture
    def synthetic_dump(self, tmp_path: Path) -> Path:
        """Create a synthetic 1MB disk image containing multiple embedded files."""
        png_data = create_minimal_png()
        jpeg_data = create_minimal_jpeg()
        zip_data = create_minimal_zip()
        pdf_data = create_minimal_pdf()

        # Construct disk image with padding between files
        dump = (
            b"\x00" * 4096  # Boot sector / zero pad
            + png_data
            + b"\xaa" * 2048
            + jpeg_data
            + b"\x55" * 1024
            + zip_data
            + b"\x00" * 4096
            + pdf_data
            + b"\xff" * 4096
        )

        dump_path = tmp_path / "synthetic_disk.img"
        dump_path.write_bytes(dump)
        return dump_path

    def test_extract_without_writing_to_disk(self, synthetic_dump: Path) -> None:
        extractor = Extractor(validate_integrity=True)
        result = extractor.carve_file(synthetic_dump, output_dir=None)

        assert result.files_found >= 4
        formats = [f.format_name for f in result.carved_files]
        assert "PNG" in formats
        assert "JPEG" in formats
        assert "ZIP" in formats
        assert "PDF" in formats

        # No files written when output_dir is None
        for f in result.carved_files:
            assert f.output_path is None
            assert f.sha256 != ""
            assert 0.0 <= f.entropy <= 8.0

    def test_carve_to_output_directory(self, synthetic_dump: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "carved_output"
        result = carve_files_from_mmap(synthetic_dump, output_dir=out_dir, validate=True)

        assert result.files_carved >= 4
        assert out_dir.exists()

        for carved in result.carved_files:
            assert carved.output_path is not None
            carved_path = Path(carved.output_path)
            assert carved_path.exists()
            assert carved_path.stat().st_size == carved.size

            # Check SHA-256 verification
            actual_sha256 = hashlib.sha256(carved_path.read_bytes()).hexdigest()
            assert actual_sha256 == carved.sha256

    def test_extraction_limits_max_files(self, synthetic_dump: Path) -> None:
        # Limit max total files to 2
        extractor = Extractor(max_total_files=2)
        result = extractor.carve_file(synthetic_dump)
        assert len(result.carved_files) == 2
        assert any("Reached maximum extraction limit" in err for err in result.errors)

    def test_extraction_min_size_filter(self, synthetic_dump: Path) -> None:
        # Filter files smaller than 1MB
        extractor = Extractor(min_size=1024 * 1024)
        result = extractor.carve_file(synthetic_dump)
        # All minimal files are smaller than 1MB
        assert len(result.carved_files) == 0

    def test_carve_nonexistent_file_raises_error(self, tmp_path: Path) -> None:
        extractor = Extractor()
        with pytest.raises(FileNotFoundError):
            extractor.carve_file(tmp_path / "non_existent_file.bin")

    def test_carve_empty_file_returns_empty_result(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        extractor = Extractor()
        result = extractor.carve_file(empty_file)
        assert result.files_found == 0
        assert result.files_carved == 0
        assert result.carved_files == []

    def test_carve_corrupt_offset_resilience(self, tmp_path: Path) -> None:
        # A file with MZ magic but truncated DOS header
        corrupt_dump = tmp_path / "corrupt.img"
        corrupt_dump.write_bytes(b"MZ\x00\x00")

        extractor = Extractor()
        result = extractor.carve_file(corrupt_dump)
        assert result.files_found == 0
