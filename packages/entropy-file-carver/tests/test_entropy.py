"""Tests for Shannon entropy mathematical precision and sliding window mapping."""

from __future__ import annotations

import math
import os
import tempfile
import pytest

from carver.entropy import (
    EntropyBlock,
    EntropyMap,
    byte_histogram,
    calculate_entropy,
    calculate_entropy_blocks,
    calculate_entropy_sliding_window,
    generate_file_entropy_map,
    scan_file_entropy,
)


class TestShannonEntropyCalculations:
    """Mathematical precision tests for Shannon entropy."""

    def test_empty_buffer_entropy(self) -> None:
        """Entropy of empty buffer should be strictly 0.0."""
        assert calculate_entropy(b"") == 0.0

    def test_uniform_single_byte_entropy(self) -> None:
        """Buffers with identical repeated bytes must yield 0.0 entropy."""
        assert calculate_entropy(b"\x00" * 4096) == 0.0
        assert calculate_entropy(b"\xff" * 1024) == 0.0
        assert calculate_entropy(b"A" * 512) == 0.0

    def test_two_equal_symbols_entropy(self) -> None:
        """Buffer with 2 equally frequent symbols must yield exactly 1.0 bit/byte."""
        data = b"\x00" * 500 + b"\x01" * 500
        entropy = calculate_entropy(data)
        assert pytest.approx(entropy, rel=1e-5) == 1.0

    def test_four_equal_symbols_entropy(self) -> None:
        """Buffer with 4 equally frequent symbols must yield exactly 2.0 bits/byte."""
        data = b"A" * 250 + b"B" * 250 + b"C" * 250 + b"D" * 250
        entropy = calculate_entropy(data)
        assert pytest.approx(entropy, rel=1e-5) == 2.0

    def test_max_entropy_256_unique_bytes(self) -> None:
        """Buffer with all 256 byte values uniformly distributed must yield 8.0 bits/byte."""
        data = bytes(range(256)) * 10  # 2560 bytes, exactly 10 of each byte
        entropy = calculate_entropy(data)
        assert pytest.approx(entropy, rel=1e-5) == 8.0

    def test_english_text_entropy_range(self) -> None:
        """Standard English ASCII text typically has entropy between 3.5 and 5.0 bits/byte."""
        sample_text = (
            b"The Shannon entropy is a measure of the average information content "
            b"missing when the value of the random variable is not known. "
            b"In binary digital forensics, entropy mapping is essential for detecting "
            b"embedded compressed payloads, encrypted containers, and obfuscated shellcode."
        )
        entropy = calculate_entropy(sample_text)
        assert 3.5 <= entropy <= 5.0

    def test_bytearray_and_memoryview_support(self) -> None:
        """calculate_entropy should seamlessly accept bytes, bytearray, and memoryview."""
        raw = b"\x00\x01\x02\x03" * 100
        assert calculate_entropy(raw) == calculate_entropy(bytearray(raw))
        assert calculate_entropy(raw) == calculate_entropy(memoryview(raw))

    def test_byte_histogram(self) -> None:
        """Histogram should correctly report counts for each byte 0..255."""
        data = b"ABC" * 10 + b"\x00" * 5
        hist = byte_histogram(data)
        assert len(hist) == 256
        assert hist[ord("A")] == 10
        assert hist[ord("B")] == 10
        assert hist[ord("C")] == 10
        assert hist[0] == 5
        assert hist[255] == 0


class TestSlidingWindowEntropy:
    """Tests for sliding window entropy scanning."""

    def test_sliding_window_empty_data(self) -> None:
        assert calculate_entropy_sliding_window(b"") == []

    def test_sliding_window_smaller_than_window(self) -> None:
        data = b"HelloWorld"
        results = calculate_entropy_sliding_window(data, window_size=64, step_size=16)
        assert len(results) == 1
        assert results[0][0] == 0
        assert pytest.approx(results[0][1], rel=1e-4) == calculate_entropy(data)

    def test_sliding_window_steps_and_tail(self) -> None:
        # 1024 zero bytes followed by 1024 high-entropy bytes + 100 extra tail bytes
        low_part = b"\x00" * 1024
        high_part = bytes(range(256)) * 4
        tail = b"\x55" * 100
        data = low_part + high_part + tail

        results = calculate_entropy_sliding_window(data, window_size=512, step_size=256)
        assert len(results) >= 8
        assert results[0][1] == 0.0
        assert pytest.approx(results[4][1], rel=1e-3) == 8.0

    def test_sliding_window_invalid_args(self) -> None:
        with pytest.raises(ValueError, match="window_size must be >= 1"):
            calculate_entropy_sliding_window(b"abc", window_size=0)

        with pytest.raises(ValueError, match="step_size must be >= 1"):
            calculate_entropy_sliding_window(b"abc", step_size=0)


class TestEntropyBlocksAndMapping:
    """Tests for block mapping, classification, and visualizations."""

    def test_calculate_entropy_blocks_empty(self) -> None:
        emap = calculate_entropy_blocks(b"", block_size=512)
        assert emap.total_size == 0
        assert emap.blocks == []
        assert emap.mean_entropy == 0.0

    def test_calculate_entropy_blocks_invalid_size(self) -> None:
        with pytest.raises(ValueError, match="block_size must be >= 1"):
            calculate_entropy_blocks(b"abc", block_size=0)

    def test_entropy_block_classifications(self) -> None:
        b1 = EntropyBlock.create(offset=0, size=512, entropy=0.05)
        assert b1.classification == "NULL_OR_UNIFORM"

        b2 = EntropyBlock.create(offset=512, size=512, entropy=3.2)
        assert b2.classification == "LOW_TEXT_OR_CODE"

        b3 = EntropyBlock.create(offset=1024, size=512, entropy=6.5)
        assert b3.classification == "MEDIUM_STRUCTURED"

        b4 = EntropyBlock.create(offset=1536, size=512, entropy=7.8)
        assert b4.classification == "HIGH_COMPRESSED_OR_ENCRYPTED"

    def test_find_high_entropy_regions(self) -> None:
        # Construct blocks: 2 low, 3 high, 1 low, 2 high
        blocks = [
            EntropyBlock.create(0, 100, 1.0),
            EntropyBlock.create(100, 100, 2.0),
            EntropyBlock.create(200, 100, 7.5),
            EntropyBlock.create(300, 100, 7.9),
            EntropyBlock.create(400, 100, 7.8),
            EntropyBlock.create(500, 100, 4.0),
            EntropyBlock.create(600, 100, 7.6),
            EntropyBlock.create(700, 100, 7.7),
        ]
        emap = EntropyMap(
            total_size=800,
            block_size=100,
            blocks=blocks,
            mean_entropy=5.7,
            min_entropy=1.0,
            max_entropy=7.9,
        )
        regions = emap.find_high_entropy_regions(threshold=7.2, min_contiguous_blocks=2)
        assert regions == [(200, 500), (600, 800)]

    def test_to_ascii_graph_rendering_and_downsampling(self) -> None:
        # Generate 100 blocks to test terminal downsampling branch (>40 blocks)
        blocks = [EntropyBlock.create(i * 100, 100, (i % 8)) for i in range(100)]
        emap = EntropyMap(
            total_size=10000,
            block_size=100,
            blocks=blocks,
            mean_entropy=4.0,
            min_entropy=0.0,
            max_entropy=7.0,
        )
        graph = emap.to_ascii_graph(width=30)
        assert "Entropy Map" in graph
        assert len(graph.splitlines()) >= 40

        # Empty blocks graph
        empty_map = EntropyMap(
            total_size=0,
            block_size=512,
            blocks=[],
            mean_entropy=0.0,
            min_entropy=0.0,
            max_entropy=0.0,
        )
        assert "No blocks to visualize" in empty_map.to_ascii_graph()


class TestStreamingFileEntropy:
    """Tests for mmap-based streaming file entropy scan."""

    def test_scan_file_entropy_stream(self, tmp_path) -> None:
        test_file = tmp_path / "sample.bin"
        test_file.write_bytes(b"\x00" * 4096 + bytes(range(256)) * 16)

        blocks = list(scan_file_entropy(test_file, block_size=4096))
        assert len(blocks) == 2
        assert blocks[0].entropy == 0.0
        assert pytest.approx(blocks[1].entropy, rel=1e-4) == 8.0

        emap = generate_file_entropy_map(test_file, block_size=4096)
        assert emap.total_size == 8192
        assert len(emap.blocks) == 2
        assert emap.mean_entropy == 4.0

    def test_scan_empty_file_entropy(self, tmp_path) -> None:
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        blocks = list(scan_file_entropy(empty_file))
        assert blocks == []

        emap = generate_file_entropy_map(empty_file)
        assert emap.total_size == 0
        assert emap.blocks == []
