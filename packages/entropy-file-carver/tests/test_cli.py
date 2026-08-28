"""Tests for entropy-file-carver CLI subcommands and options."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from carver.cli import main
from tests.test_signatures import create_minimal_jpeg, create_minimal_png


@pytest.fixture
def sample_image_path(tmp_path: Path) -> Path:
    """Create a sample binary image containing a PNG, JPEG, and random high-entropy noise."""
    img = tmp_path / "sample_forensic.bin"
    png_data = create_minimal_png()
    jpeg_data = create_minimal_jpeg()
    noise = bytes(range(256)) * 4  # 1024 bytes of max entropy (8.0)
    img.write_bytes(b"\x00" * 512 + png_data + b"\x55" * 512 + jpeg_data + noise + b"\xff" * 512)
    return img


@pytest.fixture
def sample_image_with_stego(tmp_path: Path) -> Path:
    """Create an image containing a PNG with high-entropy stego payload."""
    img = tmp_path / "sample_stego.bin"
    png_data = create_minimal_png() + (bytes(range(256)) * 2)
    img.write_bytes(b"\x00" * 256 + png_data + b"\x00" * 256)
    return img


class TestCLISubcommands:
    """Tests for all CLI subcommands and formatting flags."""

    def test_cli_scan_text_output(self, sample_image_path: Path, capsys) -> None:
        exit_code = main(["-v", "scan", str(sample_image_path)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Entropy File Carver - Binary Scan Report" in captured.out
        assert "PNG" in captured.out
        assert "JPEG" in captured.out

    def test_cli_scan_json_output(self, sample_image_path: Path, capsys) -> None:
        exit_code = main(["scan", str(sample_image_path), "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["files_found"] >= 2
        assert len(data["carved_files"]) >= 2

    def test_cli_scan_stego_status_output(self, sample_image_with_stego: Path, capsys) -> None:
        exit_code = main(["scan", str(sample_image_with_stego)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "STEGO/ENCRYPTED OVERLAY" in captured.out

    def test_cli_scan_nonexistent_file(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["scan", str(tmp_path / "missing.bin")])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error: Target file not found" in captured.err

    def test_cli_carve_command(self, sample_image_path: Path, tmp_path: Path, capsys) -> None:
        out_dir = tmp_path / "carved_dest"
        exit_code = main(["carve", str(sample_image_path), "-o", str(out_dir)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Extraction Complete" in captured.out
        assert out_dir.exists()
        assert (out_dir / "manifest.json").exists()

    def test_cli_carve_json_output(self, sample_image_path: Path, tmp_path: Path, capsys) -> None:
        out_dir = tmp_path / "carved_json_dest"
        exit_code = main(["carve", str(sample_image_path), "-o", str(out_dir), "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["files_carved"] >= 2

    def test_cli_carve_nonexistent_file(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["carve", str(tmp_path / "missing.bin"), "-o", str(tmp_path / "out")])
        assert exit_code == 1

    def test_cli_entropy_map_command(self, sample_image_path: Path, capsys) -> None:
        exit_code = main(["entropy-map", str(sample_image_path), "-b", "512", "--high-threshold", "7.0"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Entropy Map" in captured.out
        assert "High-Entropy Regions Detected" in captured.out

    def test_cli_entropy_map_json_output(self, sample_image_path: Path, capsys) -> None:
        exit_code = main(["entropy-map", str(sample_image_path), "-b", "512", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "mean_entropy" in data
        assert len(data["blocks"]) > 0

    def test_cli_entropy_map_nonexistent_file(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["entropy-map", str(tmp_path / "missing.bin")])
        assert exit_code == 1

    def test_cli_report_markdown_stdout(self, sample_image_path: Path, capsys) -> None:
        exit_code = main(["report", str(sample_image_path)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "# Forensic Analysis Report" in captured.out
        assert "Embedded Files Detected" in captured.out

    def test_cli_report_markdown_with_stego_alert(self, sample_image_with_stego: Path, capsys) -> None:
        exit_code = main(["report", str(sample_image_with_stego)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Steganography & Encrypted Overlay Alerts" in captured.out
        assert "Potential Stego/Payload" in captured.out

    def test_cli_report_json_file_output(self, sample_image_path: Path, tmp_path: Path, capsys) -> None:
        report_path = tmp_path / "report.json"
        exit_code = main(["report", str(sample_image_path), "--format", "json", "-o", str(report_path)])
        assert exit_code == 0
        assert report_path.exists()
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert "entropy_statistics" in data
        assert "carved_files" in data

    def test_cli_report_nonexistent_file(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["report", str(tmp_path / "missing.bin")])
        assert exit_code == 1
