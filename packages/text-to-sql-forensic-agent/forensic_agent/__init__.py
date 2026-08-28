"""Forensic Agent Package - Text-to-SQL for Police Narratives & Crime Analysis."""

from __future__ import annotations

from forensic_agent.database import (
    SCHEMA_PATH,
    SEED_PATH,
    get_schema_sql,
    get_seed_sql,
    init_db,
)
from forensic_agent.models import (
    ALLOWED_TABLES,
    ALLOWED_OPERATIONS,
    FORBIDDEN_SQL_KEYWORDS,
    Evidence,
    IncidentReport,
    QueryResult,
    RiskLevel,
    SQLOperation,
    SQLQuery,
    Suspect,
    SuspectStatus,
    Victim,
)
from forensic_agent.prompts import (
    FEW_SHOT_NARRATIVE_EXAMPLES,
    FEW_SHOT_SELECT_EXAMPLES,
    FORENSIC_SCHEMA_SQL,
    FORENSIC_TABLES_INFO,
    SQL_RULES,
    build_narrative_extraction_prompt,
    build_question_to_sql_prompt,
)
from forensic_agent.sql_generator import ForensicSQLGenerator, SQLGenerator
from forensic_agent.sql_guard import (
    SQLGuard,
    SQLGuardError,
    SQLSecurityViolationError,
    SQLSyntaxValidationError,
    validate_sql,
)

__all__ = [
    "Suspect",
    "Evidence",
    "Victim",
    "IncidentReport",
    "SQLQuery",
    "QueryResult",
    "RiskLevel",
    "SuspectStatus",
    "SQLOperation",
    "ALLOWED_TABLES",
    "ALLOWED_OPERATIONS",
    "FORBIDDEN_SQL_KEYWORDS",
    "SCHEMA_PATH",
    "SEED_PATH",
    "get_schema_sql",
    "get_seed_sql",
    "init_db",
    "FORENSIC_SCHEMA_SQL",
    "FORENSIC_TABLES_INFO",
    "SQL_RULES",
    "FEW_SHOT_NARRATIVE_EXAMPLES",
    "FEW_SHOT_SELECT_EXAMPLES",
    "build_narrative_extraction_prompt",
    "build_question_to_sql_prompt",
    "ForensicSQLGenerator",
    "SQLGenerator",
    "SQLGuard",
    "SQLGuardError",
    "SQLSecurityViolationError",
    "SQLSyntaxValidationError",
    "validate_sql",
]
