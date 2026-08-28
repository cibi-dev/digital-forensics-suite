# 🔬 Entropy File Carver (`entropy-file-carver`)

[![CI / Security Scan](https://img.shields.io/badge/CI-Passing-brightgreen?logo=github-actions)](.github/workflows/security-scan.yml)
[![Coverage](https://img.shields.io/badge/Coverage-94%25-brightgreen)](tests/)
[![Security: Bandit](https://img.shields.io/badge/SAST-Bandit%200%20Issues-brightgreen)](https://github.com/PyCQA/bandit)
[![Security: Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks%200%20Leaks-brightgreen)](https://github.com/gitleaks/gitleaks)
[![Supply Chain: CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%20JSON-blue)](sbom.json)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade binary forensic scanner and embedded file carver. Computes exact **Shannon entropy** $H(X) = -\sum p(x)\log_2 p(x)$ (0.0–8.0 bits/byte) across sliding windows and discrete blocks, identifies embedded file signatures (PE, ELF, ZIP, PDF, PNG, JPEG, TAR, GZIP), and streams safe extractions via memory-mapped I/O (`mmap`) without exhausting host RAM.

---

## 🎯 Key Architectural Capabilities

1. **Exact Shannon Entropy Engine**:
   - Computes mathematical Shannon entropy $H(X) \in [0.0, 8.0]$ bits/byte.
   - Zero-copy sliding window analysis and configurable block mapping.
   - Automatic classification: `NULL_OR_UNIFORM` ($<0.2$), `LOW_TEXT_OR_CODE` ($0.2\text{--}4.5$), `MEDIUM_STRUCTURED` ($4.5\text{--}7.2$), `HIGH_COMPRESSED_OR_ENCRYPTED` ($\ge 7.2$).
2. **Zero-Copy `mmap` File Carving**:
   - Processes gigabyte-scale memory dumps and raw disk images with zero full-buffer loading.
   - Slices and writes extracted files in 64KB bounded streams directly to disk.
3. **Forensic Boundary Parsers**:
   - **PNG**: Chunk sequence parser calculating exact offsets after the `IEND` CRC.
   - **JPEG**: Start-of-Image (`0xFFD8`) to End-of-Image (`0xFFD9`) marker resolution.
   - **ZIP**: Local file headers to End of Central Directory (`PK\x05\x06` + comment).
   - **PDF**: `%PDF-` version headers to final `%%EOF` trailer.
   - **ELF**: 32-bit & 64-bit section header and program header table boundary parser.
   - **PE**: DOS `MZ` header, `e_lfanew`, and COFF Section Header table boundary calculation.
   - **TAR**: POSIX 512-byte block parser scanning to end-of-archive consecutive nulls.
   - **GZIP**: `\x1f\x8b\x08` Deflate stream validation.
4. **Steganography & Encrypted Payload Detection**:
   - Analyzes trailing overlay data appended beyond canonical format trailers.
   - Strips sector alignment nulls and flags high-entropy overlays ($H \ge 7.0$) as potential steganography, encrypted shellcode, or hidden archives.
5. **DevSecOps Hardening**:
   - **CWE-409 (Anti-Zip Bomb)**: Decompression ratio limits ($<100:1$), uncompressed size limits ($<500\text{MB}$), and member count quotas ($<10,000$).
   - **CWE-59 (Symlink Escape)**: Inspects archive member attributes and flags symlink targets.
   - **CWE-22 (Path Traversal)**: Realpath and commonpath sandbox verification.
   - **CWE-377 (Insecure Tempfiles)**: Safe temporary creation with guaranteed context manager cleanup.
   - **CWE-209 (Controlled Fail-Open)**: Resilient to corrupt blocks with sanitized warning telemetry.

---

## 🚀 Quickstart & Installation

```bash
git clone https://github.com/cibi-dev/entropy-file-carver.git
cd entropy-file-carver
pip install -e .[dev]
```

---

## 💻 CLI Usage

### 1. Scan a Binary Dump (Dry Run)
Scans for embedded file signatures, offsets, sizes, and local Shannon entropy:
```bash
entropy-file-carver scan disk_dump.raw
```
JSON output:
```bash
entropy-file-carver scan disk_dump.raw --json
```

### 2. Carve Embedded Files to Output Directory
Safely extracts all embedded artifacts and creates `manifest.json`:
```bash
entropy-file-carver carve disk_dump.raw -o ./carved_output/
```

### 3. Generate Entropy Map & Terminal ASCII Graph
Visualizes the Shannon entropy curve across 4KB blocks:
```bash
entropy-file-carver entropy-map memory_dump.bin -b 4096 --high-threshold 7.2
```

### 4. Generate Comprehensive Forensic Report
Outputs Markdown or JSON forensic audits:
```bash
entropy-file-carver report memory_dump.bin -o forensic_report.md
```

---

## 🐍 Programmatic Python API

```python
from pathlib import Path
from carver import (
    calculate_entropy,
    calculate_entropy_blocks,
    carve_files_from_mmap,
    validate_carved_file,
    detect_steganography_or_hidden_payload,
)

# 1. Exact Shannon Entropy
data = b"Some ASCII plaintext followed by high entropy data..."
entropy = calculate_entropy(data)
print(f"Shannon Entropy: {entropy:.4f} bits/byte")

# 2. Carve Files from Disk Dump via mmap
result = carve_files_from_mmap(
    source_path="evidence.raw",
    output_dir="./extracted/",
    validate=True,
)

for file in result.carved_files:
    print(f"Carved [{file.format_name}] at 0x{file.offset:08X} (Size: {file.size:,} B, H={file.entropy:.4f})")
    if file.has_stego:
        print(f"  🚨 Stego Alert: Anomaly Score {file.anomaly_score}")
```

---

## 📊 Performance Benchmarks

Measured on Linux `x86_64` (Python 3.14):

| Benchmark Task | Throughput | Metric |
|---|:---:|:---:|
| **Raw Shannon Entropy (4KB)** | **12.75 MB/s** | 5,120 blocks / 1.57s |
| **Block Entropy Mapping (4KB)** | **12.04 MB/s** | 20 MB scanned / 1.66s |
| **mmap Signature Scanning & Carving** | **10.82 MB/s** | 3.8 files/sec |
| **Forensic Format Validation** | **148,990 validations/sec** | 1,000 files / 6.7ms |

---

## 🛡️ DevSecOps & Security Verification

Execute the canonical verification pipeline:

```bash
# 1. Run unit & integration tests with coverage check (>=90%)
pytest -v --cov=carver --cov-report=term-missing --cov-fail-under=90

# 2. Static Application Security Testing (Bandit)
bandit -r src/ -ll

# 3. Secret Detection (Gitleaks)
gitleaks detect --no-git --verbose

# 4. Generate CycloneDX SBOM
cyclonedx-py environment --output-file sbom.json
```

---

## 📜 Security Policy & SLA

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting guidelines and response SLAs.
