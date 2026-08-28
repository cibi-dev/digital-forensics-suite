"""
Immutable SQLite storage backend for ISO/IEC 27037 chain of custody.
Enforces write-once immutability via SQLite DDL triggers and strictly parameterized queries (CWE-89).
"""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from custody.evidence import CustodyCertificateModel, EvidenceItem, EvidenceMetadata, utcnow_iso

SQL_SCHEMA = """
-- Table for immutable evidence entries
CREATE TABLE IF NOT EXISTS evidences (
    id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    source_path TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    custody_officer TEXT NOT NULL,
    acquisition_timestamp TEXT NOT NULL,
    acquisition_method TEXT NOT NULL,
    mime_type TEXT,
    hardware_device TEXT,
    case_id TEXT,
    notes TEXT,
    registered_at TEXT NOT NULL,
    leaf_index INTEGER
);

CREATE INDEX IF NOT EXISTS idx_evidences_hash ON evidences(hash_value);
CREATE INDEX IF NOT EXISTS idx_evidences_case ON evidences(case_id);

-- Table for Merkle tree roots
CREATE TABLE IF NOT EXISTS merkle_roots (
    id TEXT PRIMARY KEY,
    root_hash TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    total_leaves INTEGER NOT NULL,
    case_id TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_merkle_roots_case ON merkle_roots(case_id);

-- Table for signed non-repudiation certificates
CREATE TABLE IF NOT EXISTS certificates (
    certificate_id TEXT PRIMARY KEY,
    case_id TEXT,
    root_hash TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    total_evidences INTEGER NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    evidence_hashes_json TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    signer_identity TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signature TEXT NOT NULL,
    certificate_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_case ON certificates(case_id);

-- Anti-UPDATE / Anti-DELETE triggers for forensic immutability
CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_update
BEFORE UPDATE ON evidences
BEGIN
    SELECT RAISE(ABORT, 'Custody evidence is immutable: UPDATE prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_evidence_delete
BEFORE DELETE ON evidences
BEGIN
    SELECT RAISE(ABORT, 'Custody evidence is immutable: DELETE prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_merkle_roots_update
BEFORE UPDATE ON merkle_roots
BEGIN
    SELECT RAISE(ABORT, 'Merkle root record is immutable: UPDATE prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_merkle_roots_delete
BEFORE DELETE ON merkle_roots
BEGIN
    SELECT RAISE(ABORT, 'Merkle root record is immutable: DELETE prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_certificates_update
BEFORE UPDATE ON certificates
BEGIN
    SELECT RAISE(ABORT, 'Custody certificate is immutable: UPDATE prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_certificates_delete
BEFORE DELETE ON certificates
BEGIN
    SELECT RAISE(ABORT, 'Custody certificate is immutable: DELETE prohibited');
END;
"""


class CustodyStorage:
    """
    SQLite persistence layer with immutable triggers and parameterized SQL queries.
    """

    def __init__(self, db_path: Union[str, Path] = ":memory:") -> None:
        self.db_path: str = str(db_path)
        if self.db_path != ":memory:":
            target = Path(self.db_path).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(target)

        conn_kwargs: Dict[str, Any] = {"check_same_thread": False}
        if sys.version_info >= (3, 12):
            conn_kwargs["autocommit"] = True
        self._conn: sqlite3.Connection = sqlite3.connect(
            self.db_path,
            **conn_kwargs,
        )
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = NORMAL;")
        with self._conn:
            self._conn.executescript(SQL_SCHEMA)

    def close(self) -> None:
        """Close SQLite connection cleanly."""
        if hasattr(self, "_conn") and self._conn:
            self._conn.close()

    def __enter__(self) -> CustodyStorage:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def store_evidence(self, evidence: EvidenceItem) -> None:
        """
        Store a new evidence item. Fails if ID already exists or update is attempted.
        """
        sql = """
        INSERT INTO evidences (
            id, algorithm, hash_value, source_path, file_size_bytes,
            custody_officer, acquisition_timestamp, acquisition_method,
            mime_type, hardware_device, case_id, notes, registered_at, leaf_index
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._conn:
            self._conn.execute(
                sql,
                (
                    evidence.evidence_id,
                    evidence.algorithm,
                    evidence.hash_value,
                    evidence.metadata.source_path,
                    evidence.metadata.file_size_bytes,
                    evidence.metadata.custody_officer,
                    evidence.metadata.acquisition_timestamp,
                    evidence.metadata.acquisition_method,
                    evidence.metadata.mime_type,
                    evidence.metadata.hardware_device,
                    evidence.metadata.case_id,
                    evidence.metadata.notes,
                    evidence.registered_at,
                    evidence.leaf_index,
                ),
            )

    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceItem:
        meta = EvidenceMetadata(
            source_path=row["source_path"],
            file_size_bytes=row["file_size_bytes"],
            custody_officer=row["custody_officer"],
            acquisition_timestamp=row["acquisition_timestamp"],
            acquisition_method=row["acquisition_method"],
            mime_type=row["mime_type"],
            hardware_device=row["hardware_device"],
            case_id=row["case_id"],
            notes=row["notes"],
        )
        return EvidenceItem(
            evidence_id=row["id"],
            algorithm=row["algorithm"],
            hash_value=row["hash_value"],
            metadata=meta,
            registered_at=row["registered_at"],
            leaf_index=row["leaf_index"],
        )

    def get_evidence_by_id(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Fetch evidence item by its unique ID."""
        sql = "SELECT * FROM evidences WHERE id = ?"
        cursor = self._conn.execute(sql, (evidence_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_evidence(row)

    def get_evidence_by_hash(self, hash_value: str) -> Optional[EvidenceItem]:
        """Fetch evidence item by its cryptographic hash."""
        sql = "SELECT * FROM evidences WHERE hash_value = ?"
        cursor = self._conn.execute(sql, (hash_value.lower(),))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_evidence(row)

    def list_evidences(self, case_id: Optional[str] = None) -> List[EvidenceItem]:
        """List all evidence items, optionally filtered by case_id, ordered by registration."""
        if case_id is not None:
            sql = "SELECT * FROM evidences WHERE case_id = ? ORDER BY rowid ASC"
            cursor = self._conn.execute(sql, (case_id,))
        else:
            sql = "SELECT * FROM evidences ORDER BY rowid ASC"
            cursor = self._conn.execute(sql)
        return [self._row_to_evidence(row) for row in cursor.fetchall()]

    def count_evidences(self, case_id: Optional[str] = None) -> int:
        """Count evidence items."""
        if case_id is not None:
            sql = "SELECT COUNT(*) FROM evidences WHERE case_id = ?"
            cursor = self._conn.execute(sql, (case_id,))
        else:
            sql = "SELECT COUNT(*) FROM evidences"
            cursor = self._conn.execute(sql)
        return int(cursor.fetchone()[0])

    def store_merkle_root(
        self,
        root_hash: str,
        algorithm: str,
        total_leaves: int,
        case_id: Optional[str] = None,
    ) -> str:
        """Store a computed Merkle root record."""
        root_id = str(uuid.uuid4())
        now_ts = utcnow_iso()
        sql = """
        INSERT INTO merkle_roots (id, root_hash, algorithm, total_leaves, case_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        with self._conn:
            self._conn.execute(
                sql,
                (root_id, root_hash.lower(), algorithm.lower(), total_leaves, case_id, now_ts),
            )
        return root_id

    def get_latest_merkle_root(self, case_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Fetch the most recent Merkle root."""
        if case_id is not None:
            sql = "SELECT * FROM merkle_roots WHERE case_id = ? ORDER BY rowid DESC LIMIT 1"
            cursor = self._conn.execute(sql, (case_id,))
        else:
            sql = "SELECT * FROM merkle_roots ORDER BY rowid DESC LIMIT 1"
            cursor = self._conn.execute(sql)
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def store_certificate(self, cert: CustodyCertificateModel) -> None:
        """Store a signed non-repudiation certificate."""
        sql = """
        INSERT INTO certificates (
            certificate_id, case_id, root_hash, algorithm, total_evidences,
            evidence_ids_json, evidence_hashes_json, generated_at, signer_identity,
            signature_algorithm, signature, certificate_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        raw_json = cert.model_dump_json()
        with self._conn:
            self._conn.execute(
                sql,
                (
                    cert.certificate_id,
                    cert.case_id,
                    cert.root_hash,
                    cert.algorithm,
                    cert.total_evidences,
                    json.dumps(cert.evidence_ids),
                    json.dumps(cert.evidence_hashes),
                    cert.generated_at,
                    cert.signer_identity,
                    cert.signature_algorithm,
                    cert.signature,
                    raw_json,
                ),
            )

    def get_certificate(self, certificate_id: str) -> Optional[CustodyCertificateModel]:
        """Fetch a certificate by its unique ID."""
        sql = "SELECT certificate_json FROM certificates WHERE certificate_id = ?"
        cursor = self._conn.execute(sql, (certificate_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return CustodyCertificateModel.model_validate_json(row["certificate_json"])

    def list_certificates(self, case_id: Optional[str] = None) -> List[CustodyCertificateModel]:
        """List all certificates."""
        if case_id is not None:
            sql = "SELECT certificate_json FROM certificates WHERE case_id = ? ORDER BY rowid ASC"
            cursor = self._conn.execute(sql, (case_id,))
        else:
            sql = "SELECT certificate_json FROM certificates ORDER BY rowid ASC"
            cursor = self._conn.execute(sql)
        return [CustodyCertificateModel.model_validate_json(row["certificate_json"]) for row in cursor.fetchall()]
