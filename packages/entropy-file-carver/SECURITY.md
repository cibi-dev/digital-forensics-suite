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

This project adheres to the strict **cibi-dev DevSecOps & Security Standard**:

| Security Control | Reference / Standard | Verification |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI |
| Anti-Zip Bomb & Decompression Guard | CWE-409 | Ratio < 100:1, Size < 500MB, Count < 10,000 |
| Symlink Escape Prevention | CWE-59 | Canonical path & symlink rejection |
| Path Traversal Defense | CWE-22 (`os.path.commonpath`, `os.path.realpath`) | Pytest suite (`test_security.py`) |
| Secure Temporary Files | CWE-377 (`tempfile.mkstemp`, `mkdtemp` + cleanup) | Pytest & atexit cleanup handlers |
| Controlled Fail-Open Error Handling | CWE-209 | Sanitized log warnings, resilient scanner |
| Bounded Memory & Resource Quotas | CWE-400 (Anti-DoS) | `mmap` zero-copy chunking & stream limits |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Deserialization | CWE-502 (Pydantic v2 strict models) | Strict schema validation |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
