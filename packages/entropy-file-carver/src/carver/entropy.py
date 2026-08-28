"""Shannon Entropy calculation module for binary forensics.

Provides exact Shannon entropy calculation:
    H(X) = -sum(p(x) * log2(p(x)))
for byte streams (range 0.0 to 8.0 bits per byte).
Includes sliding window generators, histogram computations, and block-based entropy mapping.
"""

from __future__ import annotations

import collections
import math
import mmap
from pathlib import Path
from typing import Generator, Sequence
from pydantic import BaseModel, Field


def calculate_entropy(data: bytes | bytearray | memoryview) -> float:
    """Calculate exact Shannon entropy in bits per byte for a given byte buffer.

    Formula:
        H(X) = - sum_{i=0}^{255} p(i) * log2(p(i))
    where p(i) is the probability of occurrence of byte value i.

    Args:
        data: Byte buffer to analyze.

    Returns:
        Entropy in bits per byte, strictly in the range [0.0, 8.0].
    """
    if not data:
        return 0.0

    length = len(data)
    # Using collections.Counter for C-accelerated byte counting in Python 3.10+
    counts = collections.Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    # Bound to [0.0, 8.0] to guard against floating-point precision artifacts
    return max(0.0, min(8.0, entropy))


def byte_histogram(data: bytes | bytearray | memoryview) -> dict[int, int]:
    """Compute exact frequency distribution of byte values (0-255).

    Args:
        data: Byte buffer to analyze.

    Returns:
        Dictionary mapping byte value (0-255) to its occurrence count.
    """
    counts = collections.Counter(data)
    return {byte_val: counts.get(byte_val, 0) for byte_val in range(256)}


def calculate_entropy_sliding_window(
    data: bytes | bytearray | memoryview,
    window_size: int = 1024,
    step_size: int = 256,
) -> list[tuple[int, float]]:
    """Compute Shannon entropy across a sliding window over binary data.

    Args:
        data: Binary buffer to scan.
        window_size: Size of each analysis window in bytes (>= 1).
        step_size: Stride/step between consecutive windows (>= 1).

    Returns:
        List of (offset, entropy) pairs.
    """
    if window_size < 1:
        raise ValueError(f"window_size must be >= 1, got {window_size}")
    if step_size < 1:
        raise ValueError(f"step_size must be >= 1, got {step_size}")

    data_len = len(data)
    if data_len == 0:
        return []

    if data_len <= window_size:
        return [(0, calculate_entropy(data))]

    results: list[tuple[int, float]] = []
    for offset in range(0, data_len - window_size + 1, step_size):
        window = data[offset : offset + window_size]
        results.append((offset, calculate_entropy(window)))

    # Handle tail if last window didn't cover the exact end
    last_processed_end = results[-1][0] + window_size if results else 0
    if last_processed_end < data_len:
        tail_offset = max(0, data_len - window_size)
        if not results or results[-1][0] != tail_offset:
            results.append((tail_offset, calculate_entropy(data[tail_offset:])))

    return results


class EntropyBlock(BaseModel):
    """Represents an entropy measurement for a discrete block in a binary file."""

    offset: int = Field(..., description="Byte offset in file", ge=0)
    size: int = Field(..., description="Block size in bytes", gt=0)
    entropy: float = Field(..., description="Shannon entropy (0.0 - 8.0)", ge=0.0, le=8.0)
    classification: str = Field(..., description="Forensic categorization of the block")

    @classmethod
    def create(cls, offset: int, size: int, entropy: float) -> EntropyBlock:
        """Factory method determining the classification based on entropy."""
        if entropy < 0.2:
            classification = "NULL_OR_UNIFORM"
        elif entropy < 4.5:
            classification = "LOW_TEXT_OR_CODE"
        elif entropy < 7.2:
            classification = "MEDIUM_STRUCTURED"
        else:
            classification = "HIGH_COMPRESSED_OR_ENCRYPTED"

        return cls(
            offset=offset,
            size=size,
            entropy=round(entropy, 4),
            classification=classification,
        )


class EntropyMap(BaseModel):
    """Complete entropy profile and statistical breakdown of a binary resource."""

    total_size: int = Field(..., description="Total size in bytes", ge=0)
    block_size: int = Field(..., description="Block size used for mapping", gt=0)
    blocks: list[EntropyBlock] = Field(default_factory=list, description="List of mapped blocks")
    mean_entropy: float = Field(..., description="Mean entropy across all blocks", ge=0.0, le=8.0)
    min_entropy: float = Field(..., description="Minimum block entropy", ge=0.0, le=8.0)
    max_entropy: float = Field(..., description="Maximum block entropy", ge=0.0, le=8.0)

    def find_high_entropy_regions(
        self, threshold: float = 7.2, min_contiguous_blocks: int = 1
    ) -> list[tuple[int, int]]:
        """Find contiguous byte ranges exceeding the given entropy threshold.

        Args:
            threshold: Minimum entropy threshold (0.0-8.0).
            min_contiguous_blocks: Minimum number of consecutive high-entropy blocks.

        Returns:
            List of (start_offset, end_offset) tuples.
        """
        regions: list[tuple[int, int]] = []
        current_start: int | None = None
        current_count = 0
        current_end = 0

        for block in self.blocks:
            if block.entropy >= threshold:
                if current_start is None:
                    current_start = block.offset
                    current_count = 0
                current_count += 1
                current_end = block.offset + block.size
            else:
                if current_start is not None:
                    if current_count >= min_contiguous_blocks:
                        regions.append((current_start, current_end))
                    current_start = None
                    current_count = 0

        if current_start is not None and current_count >= min_contiguous_blocks:
            regions.append((current_start, current_end))

        return regions

    def to_ascii_graph(self, width: int = 60) -> str:
        """Render a terminal-friendly ASCII visualization of the entropy distribution."""
        if not self.blocks:
            return "No blocks to visualize."

        lines: list[str] = [
            f"Entropy Map (Total: {self.total_size:,} bytes, Block Size: {self.block_size:,} bytes)",
            f"Mean: {self.mean_entropy:.4f} | Min: {self.min_entropy:.4f} | Max: {self.max_entropy:.4f}",
            "-" * (width + 24),
            "Offset      Entropy  Visualization (0.0 -> 8.0)",
            "-" * (width + 24),
        ]

        # Sample blocks if there are too many for a terminal display
        display_blocks = self.blocks
        if len(self.blocks) > 40:
            step = len(self.blocks) / 40
            display_blocks = [self.blocks[int(i * step)] for i in range(40)]

        for b in display_blocks:
            bar_len = int((b.entropy / 8.0) * width)
            bar = "█" * bar_len + "░" * (width - bar_len)
            lines.append(f"0x{b.offset:08X}  {b.entropy:6.4f}  [{bar}] {b.classification[:4]}")

        lines.append("-" * (width + 24))
        return "\n".join(lines)


def calculate_entropy_blocks(
    data: bytes | bytearray | memoryview, block_size: int = 4096
) -> EntropyMap:
    """Divide binary data into sequential fixed blocks and compute an EntropyMap.

    Args:
        data: Binary buffer to analyze.
        block_size: Size in bytes of each discrete block.

    Returns:
        EntropyMap containing detailed block-by-block statistics.
    """
    if block_size < 1:
        raise ValueError(f"block_size must be >= 1, got {block_size}")

    data_len = len(data)
    if data_len == 0:
        return EntropyMap(
            total_size=0,
            block_size=block_size,
            blocks=[],
            mean_entropy=0.0,
            min_entropy=0.0,
            max_entropy=0.0,
        )

    blocks: list[EntropyBlock] = []
    entropies: list[float] = []

    for offset in range(0, data_len, block_size):
        chunk = data[offset : min(offset + block_size, data_len)]
        ent = calculate_entropy(chunk)
        entropies.append(ent)
        blocks.append(EntropyBlock.create(offset=offset, size=len(chunk), entropy=ent))

    mean_ent = sum(entropies) / len(entropies)
    return EntropyMap(
        total_size=data_len,
        block_size=block_size,
        blocks=blocks,
        mean_entropy=round(mean_ent, 4),
        min_entropy=round(min(entropies), 4),
        max_entropy=round(max(entropies), 4),
    )


def scan_file_entropy(
    file_path: str | Path, block_size: int = 4096
) -> Generator[EntropyBlock, None, None]:
    """Streamingly scan a file using memory mapping without loading entire file in RAM.

    Args:
        file_path: Path to the target file.
        block_size: Block size in bytes.

    Yields:
        EntropyBlock for each processed slice.
    """
    path = Path(file_path).resolve()
    file_size = path.stat().st_size
    if file_size == 0:
        return

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for offset in range(0, file_size, block_size):
                chunk_len = min(block_size, file_size - offset)
                chunk = mm[offset : offset + chunk_len]
                ent = calculate_entropy(chunk)
                yield EntropyBlock.create(offset=offset, size=chunk_len, entropy=ent)


def generate_file_entropy_map(
    file_path: str | Path, block_size: int = 4096
) -> EntropyMap:
    """Generate a complete EntropyMap from a file using mmap streaming.

    Args:
        file_path: Path to the target file.
        block_size: Block size in bytes.

    Returns:
        EntropyMap instance.
    """
    path = Path(file_path).resolve()
    file_size = path.stat().st_size
    if file_size == 0:
        return EntropyMap(
            total_size=0,
            block_size=block_size,
            blocks=[],
            mean_entropy=0.0,
            min_entropy=0.0,
            max_entropy=0.0,
        )

    blocks: list[EntropyBlock] = list(scan_file_entropy(path, block_size=block_size))
    entropies = [b.entropy for b in blocks]

    return EntropyMap(
        total_size=file_size,
        block_size=block_size,
        blocks=blocks,
        mean_entropy=round(sum(entropies) / len(entropies), 4),
        min_entropy=round(min(entropies), 4),
        max_entropy=round(max(entropies), 4),
    )
