# 🛡️ Forensic Timeline Reconstructor

[![CI Security Scan](https://github.com/cibi-dev/forensic-timeline-reconstructor/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/forensic-timeline-reconstructor/actions)
[![Security Policy](https://img.shields.io/badge/Security-SECURITY.md-blue.svg)](SECURITY.md)
[![SAST Bandit](https://img.shields.io/badge/SAST-Bandit%20Clean-success.svg)](https://github.com/PyCQA/bandit)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-brightgreen.svg)](sbom.json)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An enterprise-grade, high-throughput Incident Response (IR) forensic correlation engine that reconstructs canonical UTC timelines with microsecond resolution from heterogeneous log sources, featuring deterministic timestomping and clock tampering detection.

---

## 🎯 Key Features

- **Microsecond UTC Resolution:** Canonical timezone normalizer guaranteeing UTC awareness (`datetime.timezone.utc`) with full microsecond precision across all log formats.
- **Heterogeneous Ingestion:** Native, bounded-memory streaming parsers for:
  - **Syslog RFC 5424** (PRI calculation, structured data extraction, msg-id).
  - **Syslog RFC 3164** (BSD legacy headers, tags, PIDs).
  - **Linux Auth.log** (SSH publickey/password logins, failed brute-force, sudo execution, PAM sessions, user creations).
  - **Nginx Access & Error Logs** (Combined format, HTTP status codes, method/URL extraction, error worker PIDs).
  - **JSON-Lines Structured Streams** (Auto-discovery of timestamps, severities, hosts, actors, client IPs, and payload metadata).
- **Streaming Multi-Source Correlation ($O(K)$ Memory):** K-way merge using `heapq.merge` over active streams, sustaining $<50\text{ MB}$ RAM consumption regardless of input dataset size (CWE-400 mitigation).
- **Exact Timestomping & Integrity Detection:**
  - 🚨 **Negative Clock Jumps ($t_{i+1} < t_i$):** Pinpoints attacker clock rollback or out-of-sequence log injections.
  - 🔍 **Anomalous Deletion Gaps:** Identifies service interruptions, log wiper activities, or rotation gaps.
  - ⚡ **High-Frequency Burst Inconsistencies:** Detects scripted bulk injection.
  - 🔮 **Future Timestamps:** Detects timestamps ahead of current reference time.
- **Multi-Stage Attack Chain Correlation:** Automatic correlation of brute-force authentication attacks followed by successful compromise and subsequent privilege escalation (`sudo`).
- **Executive Reporting & Exporting:** Streaming JSON-Lines (`.jsonl`) export and executive GitHub Flavored Markdown (`.md`) investigation reports.

---

## 🏗️ Architecture

```
Heterogeneous Log Sources (Disk / Streams)
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Syslog RFC 5424 │  │ Linux Auth.log  │  │  Nginx Access   │  │   JSON-Lines    │
│  & RFC 3164     │  │  (SSH / Sudo)   │  │   & Error Logs  │  │ Structured Logs │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │                    │
         ▼                    ▼                    ▼                    ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│             Bounded Streaming Parsers & Canonical UTC Normalizer               │
│           (Microsecond Precision, Sanitization & Fail-Open CWE-209)            │
└───────────────────────────────────────┬────────────────────────────────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│               Streaming K-Way Merge Correlator (heapq.merge)                   │
│              O(K) RAM Consumption (<50 MB) + Query Filtering                   │
└───────────────────────┬───────────────────────────────┬────────────────────────┘
                        │                               │
                        ▼                               ▼
┌────────────────────────────────────────┐ ┌────────────────────────────────────┐
│      Timestomping Integrity Engine     │ │   Attack Chain Correlation Engine  │
│  (Negative Jumps, Gaps, Skew & Bursts) │ │ (Brute Force -> Login -> PrivEsc)  │
└───────────────────────┬────────────────┘ └────────────┬───────────────────────┘
                        │                               │
                        └───────────────┬───────────────┘
                                        ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│               Exporters: Streaming JSONL & Executive Markdown Report           │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### Installation

```bash
# Clone and install with development dependencies
git clone https://github.com/cibi-dev/forensic-timeline-reconstructor.git
cd forensic-timeline-reconstructor
pip install .[dev]
```

---

## 💻 CLI Usage Guide

The package provides the `forensic-timeline` command-line tool.

### 1. Parse a Log File

```bash
# Print summary
forensic-timeline parse /var/log/auth.log --format summary

# Stream to canonical JSON-Lines
forensic-timeline parse /var/log/nginx/access.log --format jsonl --output parsed_access.jsonl
```

### 2. Correlate Multiple Log Sources into a Unified Timeline

```bash
# Correlate files into a canonical chronological JSONL timeline
forensic-timeline correlate \
  --files /var/log/syslog /var/log/auth.log /var/log/nginx/access.log \
  --format jsonl \
  --output correlated_timeline.jsonl

# Filter by time window and minimum severity
forensic-timeline correlate \
  --dir /var/log/incident_logs \
  --start "2023-10-11T00:00:00Z" \
  --end "2023-10-11T23:59:59Z" \
  --min-severity "WARNING" \
  --format markdown \
  --output timeline_report.md
```

### 3. Detect Timestomping and Tampering

```bash
# Run integrity scan (returns exit code 1 if anomalies found, 0 if clean)
forensic-timeline detect-tamper --files /var/log/syslog /var/log/auth.log

# Export structured integrity audit in JSON
forensic-timeline detect-tamper --files /var/log/auth.log --format json --output audit.json
```

### 4. Export Executive Incident Report

```bash
forensic-timeline export \
  --files /var/log/syslog /var/log/auth.log /var/log/nginx/access.log \
  --format markdown \
  --output incident_investigation_report.md \
  --detect-chains \
  --report-title "Production Incident IR Timeline Investigation"
```

---

## 🐍 Python API Example

```python
from timeline.correlator import TimelineCorrelator
from timeline.integrity import IntegrityAnalyzer
from timeline.exporters.jsonl import export_jsonl
from timeline.exporters.markdown import export_markdown_report

# 1. Correlate log streams
correlator = TimelineCorrelator()
files = ["/var/log/syslog", "/var/log/auth.log", "/var/log/nginx/access.log"]
events_stream = correlator.merge_files(files)

# 2. Analyze integrity for timestomping
analyzer = IntegrityAnalyzer(max_allowed_gap_seconds=3600.0)
anomalies = analyzer.analyze_multi_file(files)

# 3. Detect multi-stage attack chains
events_list = list(events_stream)
chains = correlator.find_attack_chains(events_list)

# 4. Generate executive investigation report
report_md = export_markdown_report(
    events=events_list,
    anomalies=anomalies,
    attack_chains=chains,
    output_file="investigation_report.md",
)
```

---

## 🛡️ DevSecOps & Security Hardening (CWE Mitigations)

| CWE ID | Vulnerability Vector | Defense & Implementation Applied |
|---|---|---|
| **CWE-1333** | ReDoS / Catastrophic Backtracking | Bounded input length ($\le 65,536\text{ chars}$), linear and possessive regex patterns. |
| **CWE-400** | Uncontrolled Resource Consumption | Generator-based streaming pipelines ($O(K)$ memory via `heapq.merge`), $<50\text{ MB}$ peak RAM. |
| **CWE-209** | Information Exposure via Error | Fail-open design catching malformed lines, logging sanitized diagnostics without halting the pipeline. |
| **CWE-22** | Path Traversal | Rigorous path validation with `os.path.realpath` and `os.path.commonpath`. |
| **CWE-502** | Insecure Deserialization | Strict Pydantic v2 data models with `model_config = {"extra": "forbid"}`. |
| **CWE-798** | Hardcoded Credentials | Zero credentials; verified with automated Gitleaks scan in CI/CD. |

---

## 📊 Benchmark Metrics

Validated via `python benchmarks/run.py` on 100,000 heterogeneous log events:

- **Throughput:** $>50\text{ MB/s}$ / $>100,000\text{ events/s}$.
- **Peak RAM:** $<15\text{ MB}$ (Well within the $<50\text{ MB}$ DevSecOps threshold).
- **Integrity Scan Overhead:** $<0.1\text{ s}$.

See [benchmarks/resultados.json](benchmarks/resultados.json) for real test run outputs.

---

## 🧪 Testing & Continuous Validation

```bash
# Run pytest with 90%+ code coverage gate
pytest -v

# Run Bandit SAST security audit
bandit -r src/ -ll

# Run Gitleaks secret detection
gitleaks detect --source . --verbose

# Run Performance & Memory Benchmark
python benchmarks/run.py

# Generate CycloneDX SBOM
cyclonedx-py environment --output-file sbom.json
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
