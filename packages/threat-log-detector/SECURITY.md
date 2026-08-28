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

| Security Control | Reference / Standard | Verification & Mitigation |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks scan in CI / Pre-push hook |
| Path Traversal Defense | CWE-22 (`commonpath` / strict resolution) | Pytest suite & input validation |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 known CVEs |
| Safe Subprocess Execution | CWE-78 (`shell=False`, argument list) | Code review & Bandit AST checks |
| Constant-Time Crypto Comparisons | CWE-208 (`hmac.compare_digest`) | Applied where cryptographic tokens are checked |
| Bounded Memory & Resource Quotas | CWE-400 (Anti-DoS) | Chunked log processing, max line size 64KB, bounded sliding windows |
| Safe Deserialization | CWE-502 (`json` & `.npz` arrays only) | **Strict prohibition of `pickle` and `joblib.load`** |
| Log Data Sanitization | CWE-209 (Sensitive Information Leakage) | Automatic redaction of credentials, API tokens, and private keys to `[REDACTED]` |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release and verified via CI |

---

## Threat Model & Invariant Protections

1. **CWE-502 (Deserialization of Untrusted Data):**
   - ML model parameters (IsolationForest trees, decision matrices, scaler means/variances, and Mahalanobis covariance matrices) are stored exclusively in JSON or NumPy arrays (`.npz` with `allow_pickle=False`).
   - The engine explicitly disallows Python `pickle.load` / `pickle.loads` to prevent arbitrary code execution attacks via poisoned model artifacts.

2. **CWE-209 / CWE-532 (Information Exposure Through Log Data):**
   - The `AlertGenerator` implements regex sanitizers to mask passwords, SSH tokens, API keys, private keys, and authorization headers before constructing alerts or writing audit logs.

3. **CWE-400 (Uncontrolled Resource Consumption / ReDoS / Log Bomb):**
   - Line length upper bound (65,536 characters) to reject log-bomb payloads.
   - Non-backtracking, linear-time regular expressions for log parsing.
   - Sliding window aggregation with maximum queue sizes and memory safeguards.

4. **Pure Local Execution:**
   - 100% offline, local CPU algorithmic inference without external cloud AI endpoints or telemetry leakage.

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
