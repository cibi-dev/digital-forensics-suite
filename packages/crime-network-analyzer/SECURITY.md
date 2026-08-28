# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via email to:
**cibi-dev@users.noreply.github.com**

Do NOT open public GitHub issues for security vulnerabilities, PII exposure, or secret leaks.

### Response SLA
- **Acknowledgement:** Within 48 hours.
- **Triage & Remediation Plan:** Within 7 business days.
- **Patch Release:** Prioritized based on CVSS severity (HIGH/CRITICAL within 7 days).

---

## Security Hardening & CWE Mitigations Applied

This project adheres to the strict **cibi-dev DevSecOps & Security Standard**:

| Security Control | Reference / Standard | Verification & Mitigation Details |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI; zero credentials in repository |
| PII Exposure Mitigation | CWE-209 | Automated PII masking for names, phone numbers, IBANs, and IPs in exports & logs |
| XML Injection & XXE Defense | CWE-91, CWE-611 | Safe XML generation & strict entity escaping (`&`, `<`, `>`, `"`, `'`) in GEXF and GraphML exporters |
| Resource Quotas & Anti-DoS | CWE-400 | Bounded k-cycle search with depth limits (`max_depth`, `max_cycles`) preventing combinatorial explosion |
| Path Traversal Defense | CWE-22 | Strict path resolution and sanitization for export file destinations |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings across all application modules |
| Safe Deserialization | CWE-502 | Strict schema validation with Pydantic v2 for graph ingestion |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to each release; automated dependency scanning |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
