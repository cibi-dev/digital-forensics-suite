# Security Policy — `digital-forensics-suite`

## Standards Applied (SECURITY.md Canonical #1–17)

### Base Controls (#1–5)
- **#1 Secrets:** Zero hardcoded credentials (CWE-798). Gitleaks automated secret scanning.
- **#2 Input Validation:** All evidence metadata and forensic schemas validated via Pydantic v2 `extra='forbid'`.
- **#3 Output Sanitization:** Expert reports and forensic timeline outputs sanitized against log forging and XSS.
- **#4 Dependency Pinning:** Dependencies pinned in `pyproject.toml`; CycloneDX SBOM generated.
- **#5 Forensic Audit Logging:** Cryptographic timestamps (ISO 8601 UTC) and PII masking.

### Phase 2 Controls (#6–13)
- **#6 Safe File Carving:** Embedded artifact extraction bounded by max carve size, signature verification, and memory mapping.
- **#7 Schema Validation:** SQL queries execute against parameterized SQLite schema with read-only guards.
- **#8 Temporary Evidence Isolation:** Isolated memory storage for sensitive carving operations.
- **#9 Chain of Custody Cryptography:** ISO/IEC 27037 compliant Merkle Tree root hashing and HMAC-SHA256 signatures (`hmac.compare_digest()`).
- **#10 Query Timeout:** Text-to-SQL executor enforces 5000ms query timeouts to block Cartesian product DoS.
- **#11 Immutability Triggers:** SQLite DDL triggers block `UPDATE` and `DELETE` on evidence and certificate tables.
- **#12 Deterministic Verification:** Self-contained Merkle audit proofs verifiable offline without cloud dependencies.
- **#13 Strict Parameterization:** AST-based SQL guard prevents SQL injection (CWE-89) and query tampering.

### AI & Forensic Agent Controls (#14–17)
- **#14 Anti-SSRF:** Forensic enrichment endpoints validated against RFC 1918 private ranges.
- **#15 Guardrails Engine:** Self-healing SQL generator with schema-bounded AST grammar.
- **#16 Human Approval:** Forensic evidence destruction or invalidation strictly prohibited; human approval for timeline export.
- **#17 Graph & Search Bounding:** Graph traversal in `crime-network-analyzer` bounded to depth $k \le 5$ and node limit 10,000.

## Reporting Vulnerabilities
Open a private security advisory via GitHub Security Advisories or contact `cibi-dev@users.noreply.github.com`.
