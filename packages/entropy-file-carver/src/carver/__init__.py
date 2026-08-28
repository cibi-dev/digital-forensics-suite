"""Entropy File Carver - Forensic Binary Scanner and Embedded File Carver.

Enterprise-grade package for exact Shannon entropy calculation, sliding window mapping,
magic bytes signature carving, and security validation.
"""

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
from carver.extractor import (
    CarvedFile,
    ExtractionResult,
    Extractor,
    carve_files_from_mmap,
)
from carver.signatures import (
    FILE_SIGNATURES,
    FileSignature,
    calculate_file_end,
    detect_signature_at,
)
from carver.validator import (
    FileValidator,
    ValidationResult,
    detect_steganography_or_hidden_payload,
    validate_carved_file,
)

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "calculate_entropy",
    "byte_histogram",
    "calculate_entropy_sliding_window",
    "calculate_entropy_blocks",
    "scan_file_entropy",
    "generate_file_entropy_map",
    "EntropyBlock",
    "EntropyMap",
    "FileSignature",
    "FILE_SIGNATURES",
    "detect_signature_at",
    "calculate_file_end",
    "Extractor",
    "CarvedFile",
    "ExtractionResult",
    "carve_files_from_mmap",
    "FileValidator",
    "ValidationResult",
    "validate_carved_file",
    "detect_steganography_or_hidden_payload",
]
