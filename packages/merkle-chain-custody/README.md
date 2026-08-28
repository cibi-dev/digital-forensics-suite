# merkle-chain-custody

[![CI](https://github.com/cibi-dev/merkle-chain-custody/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/merkle-chain-custody/actions)
[![Security Scan](https://img.shields.io/badge/Security-Bandit%20Pass-brightgreen.svg)](SECURITY.md)
[![Gitleaks](https://img.shields.io/badge/Secrets-0%20Leaks-brightgreen.svg)](SECURITY.md)
[![Coverage](https://img.shields.io/badge/Coverage-96%25-brightgreen.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](pyproject.toml)
[![ISO/IEC 27037](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027037-navy.svg)](#isoiec-27037-forensic-architecture)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Forensic chain of custody cryptographic engine compliant with **ISO/IEC 27037** (*Guidelines for identification, collection, acquisition and preservation of digital evidence*). 

Provides high-throughput dual-engine streaming hashing (**SHA-256 + BLAKE3**), a balanced binary **Merkle tree** with $O(\log N)$ inclusion proofs and domain separation, **immutable SQLite storage** enforced by native database DDL triggers, and cryptographically signed **JSON non-repudiation certificates** (HMAC-SHA256) with constant-time verification.

---

## 🏛️ Architecture & Forensic Compliance (ISO/IEC 27037)

```
                       +-------------------------------------------------+
                       |             Forensic Evidence Ingest            |
                       |       (Disk Dumps, Memory, Log Streams)         |
                       +-------------------------------------------------+
                                                |
                                                v
                       +-------------------------------------------------+
                       |         Streaming Hasher (SHA-256 / BLAKE3)     |
                       |          O(1) Memory Chunked Ingestion          |
                       +-------------------------------------------------+
                                                |
                       +------------------------+------------------------+
                       |                                                 |
                       v                                                 v
        +-----------------------------+                   +-----------------------------+
        |   Immutable SQLite Engine   |                   |     Balanced Merkle Tree    |
        |  - Write-Once DDL Triggers  |                   |  - Domain Separation        |
        |  - Anti-UPDATE / DELETE     |                   |  - Promotion Balancing      |
        |  - 100% Parameterized (CWE) |                   |  - O(log N) Audit Paths     |
        +-----------------------------+                   +-----------------------------+
                       |                                                 |
                       +------------------------+------------------------+
                                                |
                                                v
                       +-------------------------------------------------+
                       |      Non-Repudiation Custody Certificate        |
                       |        Canonical JSON + HMAC-SHA256 Sig         |
                       |    Constant-Time Compare (CWE-208 Defense)      |
                       +-------------------------------------------------+
```

### ISO/IEC 27037 Lifecycle Mapping

| Forensic Phase | Module | Control & Assurance Mechanism |
|---|---|---|
| **1. Identification** | `custody.evidence` | Immutable `EvidenceMetadata` & `EvidenceItem` Pydantic v2 schemas (`frozen=True`, `extra='forbid'`). |
| **2. Collection & Acquisition** | `custody.hasher` | Bounded chunk streaming (64 KB) prevents memory exhaustion (CWE-400); Path Traversal sanitization (CWE-22). |
| **3. Preservation & Chain Tracking** | `custody.storage` | SQLite DDL triggers block any `UPDATE` or `DELETE` at database engine level. |
| **4. Integrity & Proof of Inclusion** | `custody.merkle` | Balanced binary Merkle tree with RFC 6962 domain separation prefixes (`0x00` leaves, `0x01` internal nodes). |
| **5. Non-Repudiation & Court Report** | `custody.certificate` | Canonical deterministic JSON serialization + HMAC-SHA256 signature verified via `hmac.compare_digest`. |

---

## 🚀 Key Features

- **Dual-Engine Streaming Hashing:** Up to **1,924 MB/s** throughput with BLAKE3 and **870 MB/s** with SHA-256 with constant memory usage.
- **Balanced Binary Merkle Tree:**
  - Deterministic leaf ordering and promotion-based balancing.
  - Generates compact $O(\log N)$ inclusion proofs for forensic chain audit.
  - Immune to second-preimage and duplicate-leaf malleability attacks.
  - Instant 1-byte tamper detection across leaf data, sibling paths, and root hashes.
- **Tamper-Proof SQLite Storage:**
  - Native `BEFORE UPDATE` and `BEFORE DELETE` triggers abort unauthorized mutations.
  - 100% parameterized SQL queries preventing SQL Injection (CWE-89).
  - WAL journal mode with write speeds exceeding **35,000 items/sec**.
- **HMAC-SHA256 Custody Certificates:**
  - Generates verifiable non-repudiation certificates linking all case evidences to the Merkle root.
  - Constant-time verification (`hmac.compare_digest`) eliminating timing attack vectors (CWE-208).
- **Comprehensive CLI Tool:** Subcommands `add`, `verify`, `proof`, `audit`, and `cert` for seamless operational integration.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/cibi-dev/merkle-chain-custody.git
cd merkle-chain-custody

# Install with pip
pip install .

# For development and testing tools
pip install .[dev]
```

---

## 💻 Python SDK Quickstart

### 1. Ingest Evidence and Compute Streaming Digest

```python
from custody.hasher import hash_file, verify_file_hash

# Compute 64 KB streaming digest
file_hash = hash_file("disk_dump.raw", algorithm="sha256")
print(f"Computed SHA-256: {file_hash}")

# Verify file integrity in constant time
is_intact = verify_file_hash("disk_dump.raw", expected_hash=file_hash, algorithm="sha256")
assert is_intact is True
```

### 2. Store Evidence in Immutable SQLite

```python
from custody.evidence import EvidenceItem, EvidenceMetadata
from custody.storage import CustodyStorage

metadata = EvidenceMetadata(
    source_path="/forensics/cases/2026/disk_dump.raw",
    file_size_bytes=1073741824,
    custody_officer="Lead-Investigator-01",
    acquisition_method="physical_block_stream",
    case_id="CASE-2026-ALPHA",
)

evidence = EvidenceItem(
    algorithm="sha256",
    hash_value=file_hash,
    metadata=metadata,
)

with CustodyStorage("custody.db") as storage:
    storage.store_evidence(evidence)
    print(f"Evidence registered: {evidence.evidence_id}")
```

### 3. Build Merkle Tree & Generate Inclusion Proof

```python
from custody.merkle import MerkleTree

leaves = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
]

tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
print(f"Merkle Root: {tree.root}")

# Generate proof for leaf index 1
proof = tree.get_proof(1)
assert proof.verify() is True
print(f"Inclusion Proof Verified: {proof.root_hash}")
```

### 4. Issue and Verify Non-Repudiation Certificate

```python
from custody.certificate import generate_certificate, verify_certificate

# Generate HMAC-SHA256 signed certificate
cert = generate_certificate(
    root_hash=tree.root,
    evidence_items=[evidence],
    secret_key="court_authorized_custody_key",
    signer_identity="ForensicAuthority-Lead",
    case_id="CASE-2026-ALPHA",
)

# Verify certificate non-repudiation
result = verify_certificate(cert, secret_key="court_authorized_custody_key")
assert result.is_valid is True
print(f"Certificate Status: {result.message}")
```

---

## 🛠️ Command Line Interface (CLI)

The package provides the `custody` CLI:

### Register Evidence (`add`)
```bash
custody add /path/to/evidence.raw \
    --db custody.db \
    --officer "Officer-Smith" \
    --case "CASE-2026-001" \
    --algo sha256 \
    --notes "Primary forensic copy"
```

### Verify File Integrity (`verify`)
```bash
# Verify against SQLite record
custody verify /path/to/evidence.raw --db custody.db

# Or verify against explicit reference hash
custody verify /path/to/evidence.raw --expected-hash <64_HEX_CHARS>
```

### Generate Merkle Inclusion Proof (`proof`)
```bash
custody proof --db custody.db --case "CASE-2026-001" --evidence-id <EVIDENCE_UUID> --json
```

### Full Chain Integrity Audit (`audit`)
```bash
# Audits all registered evidences against disk state and verifies Merkle root
custody audit --db custody.db --case "CASE-2026-001"
```

### Generate & Verify Non-Repudiation Certificates (`cert`)
```bash
# Generate signed certificate
custody cert generate \
    --db custody.db \
    --case "CASE-2026-001" \
    --key "court_secret_key" \
    --signer "ForensicAuthority-Lead" \
    --out certificate.json

# Verify signed certificate
custody cert verify certificate.json --key "court_secret_key"
```

---

## 🛡️ DevSecOps & Security Controls Applied

| Guardrail | CWE / Standard | Implementation & Defense Mechanism |
|---|---|---|
| **Constant-Time Crypto** | CWE-208 | All digest and signature comparisons execute via `hmac.compare_digest`. |
| **Secure PRNG & Keys** | CWE-321 / CWE-330 | Keys and nonces generated with `secrets` and `os.urandom` (zero `random`). |
| **SQL Injection Defense** | CWE-89 | 100% parameterized queries (`?`, zero string formatting or f-strings in SQL). |
| **Database Immutability** | OWASP Database | SQLite DDL triggers enforce write-once guarantee across all tables. |
| **Path Traversal Defense** | CWE-22 | Safe path resolution with `os.path.realpath` and `os.path.commonpath`. |
| **Resource Quotas & Anti-DoS** | CWE-400 | Chunked bounded streaming ($64\text{ KB}$) prevents memory spikes during massive file ingestion. |
| **Safe Deserialization** | CWE-502 | Strict Pydantic v2 schemas (`extra='forbid'`, `frozen=True`) and canonical JSON. |
| **Static Analysis & SAST** | Bandit | 0 vulnerabilities of Medium or High severity (`bandit -r src/ -ll`). |
| **Secrets Sanitation** | CWE-798 | Gitleaks secret scanner validation in CI/CD pipeline (0 leaks). |

---

## ⚡ Performance Benchmarks

*Measurements executed on Linux x86_64, Python 3.14 (see `benchmarks/resultados.json` for reproducible raw output).*

| Benchmark Metric | Throughput / Latency |
|---|---|
| **BLAKE3 Streaming Throughput** | **1,924.90 MB/s** |
| **SHA-256 Streaming Throughput** | **870.69 MB/s** |
| **Merkle Tree Construction (1,000 leaves)** | **3.28 ms** |
| **Merkle Tree Construction (10,000 leaves)** | **86.95 ms** |
| **Inclusion Proof Generation Latency** | **17.02 µs** / proof |
| **Inclusion Proof Verification Latency** | **26.69 µs** / proof |
| **HMAC-SHA256 Certificate Signing (500 items)** | **1.43 ms** |
| **HMAC-SHA256 Certificate Verification** | **1.14 ms** |
| **SQLite Write Ingestion (with Triggers)** | **35,191 items/sec** |

To reproduce the benchmark suite:
```bash
python benchmarks/run.py
```

---

## 🧪 Running the Test Suite

```bash
# Run pytest with full coverage report (>=90% gate)
pytest -v --cov=custody --cov-report=term-missing --cov-fail-under=90

# Run Bandit SAST scan
bandit -r src/ -ll

# Run Gitleaks secret detection
gitleaks detect --no-git --source . --verbose
```

---

## 📜 License & Security Contact

Distributed under the **Apache-2.0 License**.

To report security vulnerabilities, please refer to [SECURITY.md](SECURITY.md) or contact **cibi-dev@users.noreply.github.com** privately.
