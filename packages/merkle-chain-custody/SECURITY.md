# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via email to:
**cibi-dev@users.noreply.github.com**

Do NOT open public GitHub issues for security vulnerabilities or secret leaks.

### Response SLA
- **Acknowledgement:** Within 48 hours.
- **Triage & Remediation Plan:** Within 7 business days.
- **Patch Release:** Prioritized based on CVSS severity (HIGH/CRITICAL within 7 days).

---

## Security Hardening Applied

This project adheres to the strict **cibi-dev DevSecOps & Security Standard** and forensic integrity principles aligned with **ISO/IEC 27037**:

| Security Control | Reference / Standard | Verification |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI (`gitleaks detect`) |
| Constant-Time Comparisons | CWE-208 (`hmac.compare_digest`) | Cryptographic unit tests |
| Cryptographic PRNG & Keys | CWE-321 / CWE-330 (`secrets`, `os.urandom`) | Crypto hygiene audit |
| SQL Injection Prevention | CWE-89 (100% Parameterized queries `?`) | SQLite trigger & query tests |
| Storage Immutability | Anti-UPDATE / Anti-DELETE Triggers | SQLite DDL integrity tests |
| Path Traversal Defense | CWE-22 (`os.path.realpath`, `os.path.commonpath`) | Pytest suite |
| Static Application Security Testing | Bandit (`bandit -r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Subprocess Execution | CWE-78 (`shell=False`, argument list) | Code review & Bandit |
| Bounded Memory & Streaming DoS Defense | CWE-400 (Anti-DoS chunked streaming) | Benchmark & memory tests |
| Safe Deserialization | CWE-502 (Pydantic v2 `extra='forbid'`, canonical JSON) | Schema validation tests |
| Non-Repudiation Certificate Signatures | HMAC-SHA256 with constant-time verification | Forensic verification tests |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
