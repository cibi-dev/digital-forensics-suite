"""
Suite de integración de seguridad contra el schema REAL (schema.sql + seed.sql).

Regresiones cubiertas:
- C1: exfiltración vía INSERT ... SELECT desde tablas fuera de whitelist.
- H1: drift modelo<->schema en evidences.evidence_type y victims.
- H2: eliminación del bypass SQLQuery.execute().
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

pytest.importorskip("guardrails", reason="guardrails-engine opcional: vive en ml-from-scratch-engine")

from guardrails.llm import LLMClient, LLMResponse, Message
from guardrails.types import TokenUsage

from forensic_agent.executor import SQLExecutionError, SQLExecutor
from forensic_agent.models import SQLQuery
from forensic_agent.prompts import FORENSIC_SCHEMA_SQL  # noqa: F401
from forensic_agent.sql_generator import ForensicSQLGenerator
from forensic_agent.sql_guard import SQLGuard, SQLGuardError


class MockLLMClient(LLMClient):
    """Cliente LLM simulado que devuelve respuestas predefinidas."""

    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = list(responses)

    @property
    def supports_structured_output(self) -> bool:
        return True

    def complete(self, messages: list[Message]) -> LLMResponse:
        if not self.responses:
            raise RuntimeError("No hay más respuestas simuladas.")
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return LLMResponse(
            text=resp,
            finish_reason="STOP",
            usage=TokenUsage(prompt_tokens=10, completion_tokens=10),
        )

    def complete_structured(
        self, messages: list[Message], json_schema: dict[str, Any]
    ) -> LLMResponse:
        return self.complete(messages)

    def close(self) -> None:
        pass


REPORT_JSON = json.dumps({
    "incident_type": "Robo a mano armada",
    "date_approx": "2026-08-20 22:30",
    "location": "Banco Metropolitano, Sucursal 5",
    "risk_level": "Crítico",
    "suspects": [
        {
            "alias_or_name": "El Chacal",
            "physical_description": "1.85m, pasamontañas negro",
            "status": "En fuga",
        }
    ],
    "evidences": [
        {
            "item": "Fusil calibre 5.56",
            "location_found": "Salida de emergencia",
            "evidence_type": "Arma de fuego",
        }
    ],
    "victims": [
        {
            "name_or_identity": "Guardia de seguridad",
            "injury_status": "Herido leve",
            "statement_summary": "Fue desarmado por el sospechoso",
        }
    ],
    "summary": "Asalto bancario con fusil de asalto en sucursal 5.",
})


@pytest.fixture()
def seeded_executor() -> SQLExecutor:
    executor = SQLExecutor(db_path=":memory:")
    executor.init_db(seed_path=True)
    yield executor
    executor.close()


class TestSchemaAlignment:
    """H1: el schema real soporta las columnas que genera el pipeline."""

    def test_evidences_has_evidence_type_column(self, seeded_executor: SQLExecutor) -> None:
        res = seeded_executor.execute("SELECT evidence_type FROM evidences LIMIT 1")
        assert res.columns == ["evidence_type"]

    def test_victims_canonical_columns(self, seeded_executor: SQLExecutor) -> None:
        res = seeded_executor.execute(
            "SELECT name_or_identity, injury_status, statement_summary FROM victims LIMIT 1"
        )
        assert set(res.columns) == {"name_or_identity", "injury_status", "statement_summary"}


class TestIngestAgainstRealSchema:
    """Flujo completo de ingesta (LLM mockeado) contra schema.sql real."""

    def test_full_ingest_persists_all_entities(self) -> None:
        gen = ForensicSQLGenerator(llm_client=MockLLMClient([REPORT_JSON]))
        report, _ = gen.generate_insert_from_narrative("Asalto bancario...")

        executor = SQLExecutor(db_path=":memory:")
        executor.init_db(seed_path=True)
        try:
            inc_q, *child_qs = gen.incident_to_insert_queries(report)
            res_inc = executor.execute(inc_q)
            incident_id = res_inc.last_row_id
            assert incident_id is not None

            for q in child_qs:
                assert isinstance(q.params, dict)
                q.params["incident_id"] = incident_id
            executor.execute_many(child_qs)

            assert executor.execute(
                f"SELECT COUNT(*) AS n FROM suspects WHERE incident_id = {int(incident_id)}"  # nosec B608
            ).rows == [[1]]
            assert executor.execute("SELECT COUNT(*) AS n FROM evidences").rows[0][0] >= 7

            vic = executor.execute(
                "SELECT incident_id, name_or_identity, injury_status FROM victims "
                "WHERE name_or_identity = 'Guardia de seguridad'"
            )
            assert vic.row_count == 1
            assert vic.rows[0][0] == incident_id
            assert vic.rows[0][2] == "Herido leve"
        finally:
            executor.close()


class TestSQLGuardRegressions:
    """C1: bloqueo de INSERT ... SELECT con tablas fuera de whitelist."""

    def setup_method(self) -> None:
        self.guard = SQLGuard()

    def test_insert_select_from_foreign_table_blocked(self) -> None:
        with pytest.raises(SQLGuardError):
            self.guard.validate(
                "INSERT INTO incidents (incident_type, summary) SELECT 'x', password FROM secrets"
            )

    def test_insert_select_join_foreign_table_blocked(self) -> None:
        with pytest.raises(SQLGuardError):
            self.guard.validate(
                "INSERT INTO incidents (incident_type) SELECT u.name FROM users u JOIN incidents i ON 1"
            )

    def test_plain_insert_still_allowed(self) -> None:
        sql = self.guard.validate(
            "INSERT INTO victims (incident_id, name_or_identity) VALUES (?, ?)"
        )
        assert sql.startswith("INSERT INTO victims")

    def test_h2_execute_method_removed(self) -> None:
        assert not hasattr(SQLQuery, "execute")


class TestExecutorHardening:
    """M1/M2/M3: timeout anti-DoS, serialización de hilos y excepciones precisas."""

    def _seeded(self, **kwargs: Any) -> SQLExecutor:
        executor = SQLExecutor(db_path=":memory:", **kwargs)
        executor.init_db(seed_path=True)
        return executor

    def test_query_timeout_aborts_expensive_scan(self) -> None:
        """Un producto cartesiano masivo debe abortar por timeout (protección DoS)."""
        executor = self._seeded(query_timeout_ms=30)
        try:
            with executor._lock:
                # Setup de confianza: desactivar el handler de timeout para la carga masiva
                executor._conn.set_progress_handler(None, 0)
                executor.conn.executescript(
                    """
                    WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 2000)
                    INSERT INTO incidents (id, incident_type, risk_level)
                    SELECT n + 99, 'DoS', 'Bajo' FROM seq;
                    WITH RECURSIVE seq2(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq2 WHERE n < 2000)
                    INSERT INTO suspects (id, incident_id, alias_or_name)
                    SELECT n + 99, n + 99, 'Fantasma' || n FROM seq2;
                    """
                )
                executor._conn.set_progress_handler(executor._check_timeout, 1000)
            with pytest.raises(SQLExecutionError):
                executor.execute("SELECT COUNT(*) FROM incidents, suspects")
        finally:
            executor.close()

    def test_normal_queries_within_timeout_still_work(self) -> None:
        executor = self._seeded(query_timeout_ms=100)
        try:
            res = executor.execute("SELECT COUNT(*) AS n FROM incidents")
            assert res.row_count == 1
        finally:
            executor.close()

    def test_timeout_disabled_with_zero(self) -> None:
        executor = self._seeded(query_timeout_ms=0)
        try:
            res = executor.execute("SELECT COUNT(*) AS n FROM victims")
            assert res.rows[0][0] >= 6
        finally:
            executor.close()

    def test_concurrent_access_is_serialized(self) -> None:
        """check_same_thread=False + lock interno: consultas concurrentes sin corrupción."""
        import threading

        executor = self._seeded()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(20):
                    res = executor.execute("SELECT COUNT(*) AS n FROM incidents")
                    assert res.rows[0][0] >= 5
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        try:
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            assert not errors
        finally:
            executor.close()

    def test_integrity_error_wrapped_as_execution_error(self) -> None:
        """Violaciones de constraints se reportan como SQLExecutionError (no excepción cruda)."""
        executor = self._seeded()
        try:
            with pytest.raises(SQLExecutionError):
                executor.execute(
                    "INSERT INTO suspects (incident_id, alias_or_name) VALUES (999999, 'Fantasma')"
                )
        finally:
            executor.close()
