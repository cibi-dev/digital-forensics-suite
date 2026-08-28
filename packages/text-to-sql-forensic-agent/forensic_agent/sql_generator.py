"""
Módulo de generación y traducción SQL forense.
Integra guardrails-engine para extracción estructurada y generación determinista de consultas SQLite.
"""

from __future__ import annotations
import logging
import os
import re
from typing import Any

from forensic_agent.models import (
    IncidentReport,
    SQLQuery,
    Suspect,
    Evidence,
    Victim,
)
from forensic_agent.prompts import (
    build_narrative_extraction_prompt,
    build_question_to_sql_prompt,
)
from forensic_agent.sql_guard import (
    SQLGuardError,
    default_guard,
)

# Integración con guardrails-engine
try:
    from guardrails import SelfHealingEngine, GeminiClient
    from guardrails.llm import LLMClient
    GUARDRAILS_AVAILABLE = True
except ImportError:  # pragma: no cover
    GUARDRAILS_AVAILABLE = False
    SelfHealingEngine = None  # type: ignore
    GeminiClient = None  # type: ignore
    LLMClient = None  # type: ignore

logger = logging.getLogger(__name__)


class ForensicSQLGenerator:
    """Generador y traductor determinista de SQL para análisis e ingesta forense."""

    def __init__(
        self,
        engine: Any | None = None,
        llm_client: Any | None = None,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
        max_retries: int = 2,
        prefer_native: bool = True,
    ) -> None:
        """
        Inicializa el generador forense.

        Args:
            engine: Instancia opcional de SelfHealingEngine.
            llm_client: Cliente LLM opcional compatible con guardrails.
            api_key: Clave de API opcional (se busca en GEMINI_API_KEY si no se especifica).
            model: Identificador del modelo Gemini a utilizar.
            max_retries: Intentos de auto-curación ante fallos de esquema.
            prefer_native: Si True, intenta structured outputs nativos del cliente.
        """
        self.model = model
        self.max_retries = max_retries
        self.prefer_native = prefer_native

        if engine is not None:
            self.engine = engine
        elif llm_client is not None:
            if not GUARDRAILS_AVAILABLE or SelfHealingEngine is None:
                raise RuntimeError("guardrails-engine no está disponible en el entorno.")
            self.engine = SelfHealingEngine(
                llm_client=llm_client,
                max_retries=max_retries,
                prefer_native=prefer_native,
            )
        else:
            resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
            if (
                GUARDRAILS_AVAILABLE
                and GeminiClient is not None
                and SelfHealingEngine is not None
                and resolved_key
            ):
                client = GeminiClient(api_key=resolved_key, model=model)
                self.engine = SelfHealingEngine(
                    llm_client=client,
                    max_retries=max_retries,
                    prefer_native=prefer_native,
                )
            else:
                self.engine = None

    def _ensure_engine(self) -> Any:
        """Verifica que el motor de extracción esté configurado."""
        if self.engine is None:
            raise RuntimeError(
                "SelfHealingEngine no inicializado. Proporcione un motor, cliente LLM o configure GEMINI_API_KEY."
            )
        return self.engine

    def generate_insert_from_narrative(
        self, narrative: str
    ) -> tuple[IncidentReport, list[SQLQuery]]:
        """
        Extrae un informe estructurado de la narrativa policial y genera las sentencias INSERT correspondientes.

        Args:
            narrative: Texto libre con la narrativa o reporte policial.

        Returns:
            Tupla con el (IncidentReport extraído, lista de SQLQuery INSERT parametrizados).

        Raises:
            ValueError: Si la narrativa está vacía.
            RuntimeError: Si la extracción del LLM falla tras los reintentos.
        """
        if not narrative or not narrative.strip():
            raise ValueError("La narrativa policial no puede estar vacía.")

        engine = self._ensure_engine()
        prompt = build_narrative_extraction_prompt(narrative.strip())
        result = engine.extract(prompt=prompt, schema=IncidentReport)

        if not result.success or result.data is None:
            err_msg = result.error or "Fallo desconocido durante la extracción del informe policial."
            logger.error("Error al extraer informe de narrativa: %s", err_msg)
            raise RuntimeError(f"Error en la extracción forense: {err_msg}")

        report: IncidentReport = result.data
        queries = self._build_insert_queries_from_report(report)
        return report, queries

    def _build_insert_queries_from_report(
        self, report: IncidentReport
    ) -> list[SQLQuery]:
        """
        Construye las consultas INSERT parametrizadas a partir de un IncidentReport validado.
        """
        queries: list[SQLQuery] = []

        # 1. Inserción del incidente principal
        incident_sql = (
            "INSERT INTO incidents (incident_type, date_approx, location, risk_level, summary) "
            "VALUES (:incident_type, :date_approx, :location, :risk_level, :summary)"
        )
        incident_params = {
            "incident_type": report.incident_type,
            "date_approx": report.date_approx,
            "location": report.location,
            "risk_level": report.risk_level,
            "summary": report.summary,
        }
        queries.append(
            SQLQuery(
                operation="INSERT",
                table="incidents",
                sql_parameterized=incident_sql,
                params=incident_params,
                explanation=f"Inserta registro principal del incidente tipo '{report.incident_type}' en '{report.location}'.",
            )
        )

        # 2. Inserción de sospechosos
        suspect_sql = (
            "INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) "
            "VALUES (:incident_id, :alias_or_name, :physical_description, :status)"
        )
        for suspect in report.suspects:
            queries.append(
                SQLQuery(
                    operation="INSERT",
                    table="suspects",
                    sql_parameterized=suspect_sql,
                    params={
                        "incident_id": None,  # Se vincula con el rowid del incidente en la ejecución
                        "alias_or_name": suspect.alias_or_name,
                        "physical_description": suspect.physical_description,
                        "status": suspect.status,
                    },
                    explanation=f"Inserta sospechoso '{suspect.alias_or_name}' (Estado: {suspect.status}).",
                )
            )

        # 3. Inserción de evidencias
        evidence_sql = (
            "INSERT INTO evidences (incident_id, item, location_found, evidence_type) "
            "VALUES (:incident_id, :item, :location_found, :evidence_type)"
        )
        for evidence in report.evidences:
            queries.append(
                SQLQuery(
                    operation="INSERT",
                    table="evidences",
                    sql_parameterized=evidence_sql,
                    params={
                        "incident_id": None,
                        "item": evidence.item,
                        "location_found": evidence.location_found,
                        "evidence_type": evidence.evidence_type,
                    },
                    explanation=f"Inserta evidencia '{evidence.item}' ({evidence.evidence_type}) hallada en '{evidence.location_found}'.",
                )
            )

        # 4. Inserción de víctimas
        victim_sql = (
            "INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) "
            "VALUES (:incident_id, :name_or_identity, :injury_status, :statement_summary)"
        )
        for victim in report.victims:
            queries.append(
                SQLQuery(
                    operation="INSERT",
                    table="victims",
                    sql_parameterized=victim_sql,
                    params={
                        "incident_id": None,
                        "name_or_identity": victim.name_or_identity,
                        "injury_status": victim.injury_status,
                        "statement_summary": victim.statement_summary,
                    },
                    explanation=f"Inserta víctima '{victim.name_or_identity}' (Estado: {victim.injury_status}).",
                )
            )

        return queries

    def generate_select_from_question(self, question: str) -> SQLQuery:
        """
        Traduce una pregunta en lenguaje natural a una consulta SELECT SQL parametrizada.

        Args:
            question: Pregunta analítica o forense en lenguaje natural.

        Returns:
            Instancia validada de SQLQuery con la consulta SELECT parametrizada.

        Raises:
            ValueError: Si la pregunta está vacía o si la consulta generada no es un SELECT válido.
            RuntimeError: Si la generación LLM falla o si la consulta viola las reglas de seguridad.
        """
        if not question or not question.strip():
            raise ValueError("La pregunta forense no puede estar vacía.")

        engine = self._ensure_engine()
        prompt = build_question_to_sql_prompt(question.strip())
        result = engine.extract(prompt=prompt, schema=SQLQuery)

        if not result.success or result.data is None:
            err_msg = result.error or "Fallo desconocido durante la traducción a SQL."
            logger.error("Error al generar consulta SELECT: %s", err_msg)
            raise RuntimeError(f"Error en la generación SQL: {err_msg}")

        query: SQLQuery = result.data

        # Validaciones de seguridad deterministas
        self._validate_select_query_safety(query)

        return query

    def _validate_select_query_safety(self, query: SQLQuery) -> None:
        """
        Verifica deterministamente que la consulta generada sea un SELECT seguro y sin inyecciones destructivas
        delegando en SQLGuard.
        """
        if query.operation != "SELECT":
            raise ValueError(
                f"Operación SQL inválida: se esperaba 'SELECT', se obtuvo '{query.operation}'."
            )
        try:
            default_guard.validate(query)
        except SQLGuardError as e:
            raise ValueError(f"Consulta SELECT no válida o insegura: {e}") from e

    def extract_incident(self, narrative: str) -> IncidentReport:
        """Extrae un IncidentReport estructurado a partir de una narrativa policial."""
        report, _ = self.generate_insert_from_narrative(narrative)
        return report

    def incident_to_insert_queries(
        self, report: IncidentReport, incident_id: int | None = None
    ) -> list[SQLQuery]:
        """Genera consultas INSERT a partir de un reporte estructurado."""
        queries = self._build_insert_queries_from_report(report)
        if incident_id is not None:
            for q in queries:
                if q.table != "incidents" and isinstance(q.params, dict) and "incident_id" in q.params:
                    q.params["incident_id"] = incident_id
        return queries

    def text_to_query(self, question: str) -> SQLQuery:
        """Traduce una pregunta en lenguaje natural a un SQLQuery SELECT."""
        return self.generate_select_from_question(question)

    def close(self) -> None:
        """Cierra los recursos del motor o cliente subyacente."""
        if self.engine is not None and hasattr(self.engine, "close") and callable(self.engine.close):
            self.engine.close()

    def __enter__(self) -> ForensicSQLGenerator:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# Alias de conveniencia
SQLGenerator = ForensicSQLGenerator
