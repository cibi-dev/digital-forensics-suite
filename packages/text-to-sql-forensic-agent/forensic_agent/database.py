"""Forensic SQLite Database Initialization & Utilities."""

from __future__ import annotations

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = BASE_DIR / "schema.sql"
SEED_PATH = BASE_DIR / "seed.sql"


def get_schema_sql() -> str:
    """Read and return schema.sql DDL."""
    return SCHEMA_PATH.read_text(encoding="utf-8")


def get_seed_sql() -> str:
    """Read and return seed.sql DML."""
    return SEED_PATH.read_text(encoding="utf-8")


def init_db(
    db_path: str | Path = ":memory:",
    seed: bool = True,
) -> sqlite3.Connection:
    """Create and initialize a forensic SQLite database connection.

    Args:
        db_path: Path to sqlite database file or ':memory:'
        seed: Whether to populate with seed.sql sample data

    Returns:
        sqlite3.Connection configured with foreign keys enabled and row_factory Row
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    # Apply schema
    schema_sql = get_schema_sql()
    conn.executescript(schema_sql)

    # Apply seed if requested
    if seed:
        seed_sql = get_seed_sql()
        conn.executescript(seed_sql)

    return conn
