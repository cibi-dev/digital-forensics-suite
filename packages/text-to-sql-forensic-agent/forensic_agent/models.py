"""
Modelos Pydantic v2 para el agente forense de texto a SQL.
Define estructuras para informes de incidentes, entidades forenses, consultas SQL parametrizadas
y resultados de ejecución.
"""

from __future__ import annotations

import re
import warnings
from typing import Any, Iterable, Literal, TypeAlias
from pydantic import BaseModel, Field, field_validator, model_validator

from forensic_agent.sql_guard import (
    ALLOWED_OPERATIONS,
    ALLOWED_TABLES,
    DANGEROUS_KEYWORDS,
    FORBIDDEN_OPERATIONS,
    FORBIDDEN_SQL_KEYWORDS,
    SQLGuard,
    SQLGuardError,
)

RiskLevel: TypeAlias = Literal["Bajo", "Medio", "Alto", "Crítico"]
SuspectStatus: TypeAlias = Literal["Identificado", "Detenido", "En fuga", "Desconocido"]
SQLOperation: TypeAlias = Literal["SELECT", "INSERT"]


class Suspect(BaseModel):
    """Representación estructurada de un sospechoso vinculado a un incidente."""

    id: int | None = None
    incident_id: int | None = None
    alias_or_name: str = Field(
        min_length=1,
        description="Nombre o alias conocido del sospechoso",
    )
    physical_description: str | None = Field(
        default=None,
        description="Rasgos físicos descritos (estatura, vestimenta, tatuajes, etc.)",
    )
    status: SuspectStatus = Field(
        default="Desconocido",
        description="Estado procesal o situación actual del sospechoso",
    )


class Evidence(BaseModel):
    """Representación estructurada de un indicio o elemento probatorio forense."""

    id: int | None = None
    incident_id: int | None = None
    item: str = Field(
        min_length=1,
        description="Descripción del elemento o evidencia física",
    )
    location_found: str | None = Field(
        default=None,
        description="Lugar o punto específico donde fue recolectada la evidencia",
    )
    evidence_type: str = Field(
        default="Otro",
        description="Clasificación de la evidencia (Arma de fuego, Balística, Digital, Documental, etc.)",
    )


class Victim(BaseModel):
    """Representación estructurada de una víctima o persona afectada."""

    id: int | None = None
    incident_id: int | None = None
    name_or_alias: str | None = Field(
        default=None,
        description="Nombre o alias de la víctima",
    )
    name_or_identity: str | None = Field(
        default=None,
        description="Identidad o referencia de la víctima",
    )
    injuries: str | None = Field(
        default=None,
        description="Descripción de lesiones o estado físico",
    )
    injury_status: Literal[
        "Ileso", "Herido leve", "Herido grave", "Fallecido", "Desconocido"
    ] | str | None = Field(
        default=None,
        description="Estado de salud o gravedad de las lesiones",
    )
    statement_summary: str | None = Field(
        default=None,
        description="Resumen de la declaración o testimonio proporcionado",
    )

    @model_validator(mode="after")
    def sync_aliases(self) -> Victim:
        if self.name_or_alias is None and self.name_or_identity is not None:
            self.name_or_alias = self.name_or_identity
        elif self.name_or_identity is None and self.name_or_alias is not None:
            self.name_or_identity = self.name_or_alias

        if self.injuries is None and self.injury_status is not None:
            self.injuries = str(self.injury_status)
        elif self.injury_status is None and self.injuries is not None:
            self.injury_status = self.injuries
        return self


class IncidentReport(BaseModel):
    """Informe estructurado completo de un incidente forense/policial."""

    id: int | None = None
    incident_type: str = Field(
        min_length=1,
        description="Tipo de delito o incidente investigado",
    )
    date_approx: str | None = Field(
        default=None,
        description="Fecha y hora aproximada de los hechos (ISO YYYY-MM-DD o YYYY-MM-DD HH:MM)",
    )
    location: str | None = Field(
        default=None,
        description="Ubicación o dirección exacta donde ocurrieron los hechos",
    )
    risk_level: RiskLevel = Field(
        description="Nivel de riesgo o gravedad del incidente",
    )
    summary: str | None = Field(
        default=None,
        description="Síntesis narrativa concisa y objetiva de los hechos",
    )
    suspects: list[Suspect] = Field(
        default_factory=list,
        description="Lista de sospechosos identificados o descritos",
    )
    evidences: list[Evidence] = Field(
        default_factory=list,
        description="Lista de evidencias o indicios recolectados",
    )
    victims: list[Victim] = Field(
        default_factory=list,
        description="Lista de víctimas afectadas en el incidente",
    )

    def to_flat_dict(self) -> dict[str, Any]:
        """Convierte los atributos de nivel superior a un diccionario plano."""
        data: dict[str, Any] = {
            "incident_type": self.incident_type,
            "date_approx": self.date_approx,
            "location": self.location,
            "risk_level": self.risk_level,
            "summary": self.summary,
        }
        if self.id is not None:
            data["id"] = self.id
        return data

    def to_insert_queries(self) -> list[SQLQuery]:
        """Genera la lista de SQLQuery INSERT parametrizados para la ingesta."""
        queries: list[SQLQuery] = []

        # Consulta para tabla incidents
        if self.id is not None:
            inc_sql = (
                "INSERT INTO incidents (id, incident_type, date_approx, location, risk_level, summary) "
                "VALUES (:id, :incident_type, :date_approx, :location, :risk_level, :summary)"
            )
            inc_params = {
                "id": self.id,
                "incident_type": self.incident_type,
                "date_approx": self.date_approx,
                "location": self.location,
                "risk_level": self.risk_level,
                "summary": self.summary,
            }
        else:
            inc_sql = (
                "INSERT INTO incidents (incident_type, date_approx, location, risk_level, summary) "
                "VALUES (:incident_type, :date_approx, :location, :risk_level, :summary)"
            )
            inc_params = {
                "incident_type": self.incident_type,
                "date_approx": self.date_approx,
                "location": self.location,
                "risk_level": self.risk_level,
                "summary": self.summary,
            }

        queries.append(
            SQLQuery(
                operation="INSERT",
                table="incidents",
                sql_parameterized=inc_sql,
                params=inc_params,
                explanation=f"Inserta registro principal del incidente '{self.incident_type}'.",
            )
        )

        # Consultas para suspects
        for s in self.suspects:
            s_inc_id = s.incident_id if s.incident_id is not None else self.id
            s_sql = (
                "INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) "
                "VALUES (:incident_id, :alias_or_name, :physical_description, :status)"
            )
            queries.append(
                SQLQuery(
                    operation="INSERT",
                    table="suspects",
                    sql_parameterized=s_sql,
                    params={
                        "incident_id": s_inc_id,
                        "alias_or_name": s.alias_or_name,
                        "physical_description": s.physical_description,
                        "status": s.status,
                    },
                    explanation=f"Inserta sospechoso '{s.alias_or_name}'.",
                )
            )

        # Consultas para evidences
        for e in self.evidences:
            e_inc_id = e.incident_id if e.incident_id is not None else self.id
            e_sql = (
                "INSERT INTO evidences (incident_id, item, location_found) "
                "VALUES (:incident_id, :item, :location_found)"
            )
            queries.append(
                SQLQuery(
                    operation="INSERT",
                    table="evidences",
                    sql_parameterized=e_sql,
                    params={
                        "incident_id": e_inc_id,
                        "item": e.item,
                        "location_found": e.location_found,
                    },
                    explanation=f"Inserta evidencia '{e.item}'.",
                )
            )

        # Consultas para victims
        for v in self.victims:
            v_inc_id = v.incident_id if v.incident_id is not None else self.id
            v_sql = (
                "INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) "
                "VALUES (:incident_id, :name_or_identity, :injury_status, :statement_summary)"
            )
            queries.append(
                SQLQuery(
                    operation="INSERT",
                    table="victims",
                    sql_parameterized=v_sql,
                    params={
                        "incident_id": v_inc_id,
                        "name_or_identity": v.name_or_alias or v.name_or_identity,
                        "injury_status": v.injury_status or (str(v.injuries) if v.injuries else None),
                        "statement_summary": v.statement_summary,
                    },
                    explanation=f"Inserta víctima '{v.name_or_alias or v.name_or_identity}'.",
                )
            )

        return queries


class SQLQuery(BaseModel):
    """Representación y validador de consultas SQL parametrizadas y seguras."""

    operation: SQLOperation = Field(
        default="SELECT",
        description="Operación SQL permitida (estrictamente SELECT o INSERT)",
    )
    table: str = Field(
        default="incidents",
        description="Nombre de la tabla principal o tablas afectadas",
    )
    sql_parameterized: str = Field(
        default="",
        description="Sentencia SQL parametrizada con marcadores (:param o ?)",
    )
    params: dict[str, Any] | list[Any] | tuple[Any, ...] = Field(
        default_factory=dict,
        description="Parámetros para la consulta SQL",
    )
    explanation: str = Field(
        default="",
        description="Explicación técnica o forense de la consulta",
    )

    @model_validator(mode="before")
    @classmethod
    def preprocess_inputs(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "sql" in data and "sql_parameterized" not in data:
                data["sql_parameterized"] = data["sql"]
            sql_text = str(data.get("sql_parameterized", "") or data.get("sql", "")).strip()
            if "operation" not in data or not data["operation"]:
                if sql_text.upper().startswith("INSERT"):
                    data["operation"] = "INSERT"
                else:
                    data["operation"] = "SELECT"
            if "table" not in data or not data["table"]:
                found = re.findall(r"\b(incidents|suspects|evidences|victims)\b", sql_text, re.IGNORECASE)
                data["table"] = found[0].lower() if found else "incidents"
        return data

    @field_validator("table")
    @classmethod
    def validate_table_name(cls, v: str) -> str:
        tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9_]+", v)]
        # Debe haber al menos una tabla válida de la lista permitida
        valid_found = any(t in ALLOWED_TABLES for t in tokens)
        if not valid_found:
            raise ValueError(f"table '{v}' does not contain any allowed tables: {sorted(ALLOWED_TABLES)}")
        return v

    @model_validator(mode="after")
    def validate_operation_alignment(self) -> SQLQuery:
        sql_trimmed = self.sql_parameterized.strip()
        first_token = sql_trimmed.split()[0].upper() if sql_trimmed else ""
        if self.operation == "SELECT" and first_token != "SELECT":
            raise ValueError(f"SQL statement must start with SELECT for operation SELECT, got '{first_token}'")
        if self.operation == "INSERT" and first_token != "INSERT":
            raise ValueError(f"SQL statement must start with INSERT for operation INSERT, got '{first_token}'")
        return self

    def is_read_only(self) -> bool:
        """Indica si la consulta es de solo lectura (SELECT)."""
        return self.operation == "SELECT"

    def is_mutation(self, ) -> bool:
        """Indica si la consulta altera la base de datos (INSERT)."""
        return self.operation == "INSERT"

    def validate_safety(self, allowed_tables: Iterable[str] | None = None) -> bool:
        """
        Valida que la consulta cumpla con los guardrails de seguridad delegando en SQLGuard.
        Lanza ValueError si se detecta una violación.
        """
        guard = SQLGuard(allowed_tables=allowed_tables)
        try:
            guard.validate(self)
            return True
        except SQLGuardError as e:
            raise ValueError(f"Violación de seguridad SQL: {e}") from e

    def is_safe(self, allowed_tables: Iterable[str] | None = None) -> bool:
        """Comprueba de forma booleana si la consulta es segura."""
        try:
            return self.validate_safety(allowed_tables=allowed_tables)
        except (ValueError, Exception):
            return False

    def to_executable_sql(self) -> str:
        """
        Interpola los parámetros para inspección o debugging.

        ADVERTENCIA: NUNCA ejecutar el resultado en bases de datos o producción.
        Utilice siempre consultas parametrizadas contra el motor de ejecución.
        """
        warnings.warn(
            "to_executable_sql() es únicamente para depuración o inspección. NUNCA ejecutar el resultado.",
            UserWarning,
            stacklevel=2,
        )

        def _format_value(val: Any) -> str:
            if val is None:
                return "NULL"
            if isinstance(val, bool):
                return "1" if val else "0"
            if isinstance(val, (int, float)):
                return repr(val)
            escaped = str(val).replace("'", "''")
            return f"'{escaped}'"

        sql = self.sql_parameterized
        if isinstance(self.params, dict):
            for key, val in self.params.items():
                pattern = r":" + re.escape(key) + r"\b"
                formatted = _format_value(val)
                sql = re.sub(pattern, lambda m: formatted, sql)
        elif isinstance(self.params, (list, tuple)):
            for val in self.params:
                formatted = _format_value(val)
                sql = sql.replace("?", formatted, 1)
        return sql

    def get_params_tuple(self) -> tuple[Any, ...]:
        """Obtiene los parámetros en formato tupla posicional."""
        if isinstance(self.params, (list, tuple)):
            return tuple(self.params)
        elif isinstance(self.params, dict):
            return tuple(self.params.values())
        return ()

    def get_params_dict(self) -> dict[str, Any]:
        """Obtiene los parámetros en formato diccionario nombrado."""
        if isinstance(self.params, dict):
            return dict(self.params)
        elif isinstance(self.params, (list, tuple)):
            return {f"p{i}": v for i, v in enumerate(self.params)}
        return {}


class QueryResult(BaseModel):
    """Resultado de la ejecución de una consulta SQL."""

    operation: str = Field(default="SELECT")
    columns: list[str] = Field(default_factory=list)
    rows: list[list[Any]] = Field(default_factory=list)
    row_count: int = 0
    last_row_id: int | None = None
    affected_rows: int = 0
    execution_time_ms: float = 0.0
    query: str = ""

    @property
    def is_empty(self) -> bool:
        """Indica si el resultado no contiene filas."""
        return len(self.rows) == 0

    def format_table(self, style: Literal["markdown", "ascii"] = "markdown") -> str:
        """Formatea las filas y columnas como una tabla limpia Markdown o ASCII.

        Args:
            style: 'markdown' o 'ascii'.

        Returns:
            Representación tabular en texto.
        """
        if not self.columns and not self.rows:
            if self.operation == "INSERT":
                return f"INSERT exitoso (ID generado: {self.last_row_id}, filas afectadas: {self.affected_rows})"
            return "(Sin datos)"

        headers = self.columns if self.columns else [f"col_{i}" for i in range(len(self.rows[0]))]

        # Convertir todos los valores a strings para medir anchos
        str_rows: list[list[str]] = []
        for row in self.rows:
            str_rows.append(["NULL" if val is None else str(val) for val in row])

        col_widths: list[int] = []
        for i, header in enumerate(headers):
            header_len = len(str(header))
            max_val_len = max((len(row[i]) for row in str_rows), default=0)
            col_widths.append(max(header_len, max_val_len))

        if style == "markdown":
            header_line = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"
            sep_line = "|-" + "-|-".join("-" * col_widths[i] for i in range(len(headers))) + "-|"
            row_lines = [
                "| " + " | ".join(row[i].ljust(col_widths[i]) for i in range(len(headers))) + " |"
                for row in str_rows
            ]
            if not row_lines:
                return f"{header_line}\n{sep_line}\n| " + " | ".join(" ".ljust(col_widths[i]) for i in range(len(headers))) + " | (0 filas)"
            return "\n".join([header_line, sep_line] + row_lines)

        else:  # ASCII style
            border = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
            header_line = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"
            row_lines = [
                "| " + " | ".join(row[i].ljust(col_widths[i]) for i in range(len(headers))) + " |"
                for row in str_rows
            ]
            if not row_lines:
                return f"{border}\n{header_line}\n{border}\n| " + " | ".join(" ".ljust(col_widths[i]) for i in range(len(headers))) + " |\n" + f"{border}\n(0 filas)"
            return "\n".join([border, header_line, border] + row_lines + [border])

