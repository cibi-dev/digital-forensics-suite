"""
Módulo de seguridad y guardrails deterministas para consultas SQL forenses.

Implementa validación estricta, listas blancas de operaciones y tablas,
detección de inyecciones y cláusulas LIMIT automáticas.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from forensic_agent.models import SQLQuery

# ============================================================================
# Constantes canónicas compartidas de seguridad SQL
# ============================================================================

ALLOWED_TABLES: frozenset[str] = frozenset({
    "incidents",
    "suspects",
    "evidences",
    "victims",
})

ALLOWED_OPERATIONS: frozenset[str] = frozenset({"SELECT", "INSERT"})

FORBIDDEN_OPERATIONS: frozenset[str] = frozenset({
    "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE",
    "ATTACH", "DETACH", "PRAGMA", "VACUUM", "EXEC",
    "EXECUTE", "CREATE", "REPLACE", "GRANT", "REVOKE",
    "MERGE", "UPSERT", "CALL", "DO", "SHOW", "DESCRIBE",
    "EXPLAIN", "BEGIN", "COMMIT", "ROLLBACK", "SET",
    "LOCK", "UNLOCK", "COPY", "LOAD",
})

DANGEROUS_KEYWORDS: frozenset[str] = frozenset({
    "DROP", "DELETE", "UPDATE", "ALTER", "TRUNCATE",
    "ATTACH", "DETACH", "PRAGMA", "VACUUM", "EXEC",
    "EXECUTE", "CREATE", "REPLACE", "GRANT", "REVOKE",
    "SHUTDOWN", "XP_CMDSHELL", "LOAD_EXTENSION",
    "BENCHMARK", "SLEEP",
})

DANGEROUS_TABLES_AND_SCHEMAS: frozenset[str] = frozenset({
    "sqlite_master",
    "sqlite_schema",
    "sqlite_temp_master",
    "sqlite_temp_schema",
    "sqlite_sequence",
    "sqlite_stat1",
    "sqlite_stat4",
    "information_schema",
    "pg_catalog",
    "sys",
    "mysql",
    "performance_schema",
})

FORBIDDEN_SQL_KEYWORDS: frozenset[str] = DANGEROUS_KEYWORDS


class SQLGuardError(Exception):
    """Excepción base para errores de validación de SQLGuard."""
    pass


class SQLSecurityViolationError(SQLGuardError):
    """Excepción lanzada cuando una consulta viola las políticas de seguridad."""
    pass


class SQLSyntaxValidationError(SQLGuardError):
    """Excepción lanzada cuando la sintaxis SQL es inválida o vacía."""
    pass


class SQLGuard:
    """
    Guardrail de seguridad para consultas SQL generadas por LLMs en contextos forenses.
    
    Asegura que:
    1. Solo se ejecuten operaciones de lectura (SELECT) o inserción (INSERT).
    2. Las tablas referenciadas pertenezcan estrictamente a la lista blanca permitida.
    3. No existan inyecciones SQL (comentarios, consultas apiladas, tautologías, llamadas al sistema).
    4. Las consultas SELECT incluyan una cláusula LIMIT que no exceda el máximo permitido (por defecto 100).
    """

    DEFAULT_ALLOWED_TABLES: frozenset[str] = ALLOWED_TABLES
    DEFAULT_ALLOWED_OPERATIONS: frozenset[str] = ALLOWED_OPERATIONS
    FORBIDDEN_OPERATIONS: frozenset[str] = FORBIDDEN_OPERATIONS
    DANGEROUS_KEYWORDS: frozenset[str] = DANGEROUS_KEYWORDS
    DANGEROUS_TABLES_AND_SCHEMAS: frozenset[str] = DANGEROUS_TABLES_AND_SCHEMAS

    def __init__(
        self,
        allowed_tables: Iterable[str] | None = None,
        allowed_operations: Iterable[str] | None = None,
        max_limit: int = 100,
        default_limit: int = 100,
    ) -> None:
        """
        Inicializa una instancia de SQLGuard con configuraciones de seguridad.
        
        Args:
            allowed_tables: Conjunto de tablas permitidas (por defecto: incidents, suspects, evidences, victims).
            allowed_operations: Operaciones SQL permitidas (por defecto: SELECT, INSERT).
            max_limit: Límite máximo de filas permitidas en consultas SELECT.
            default_limit: Límite a añadir automáticamente si no se especifica.
        """
        if allowed_tables is not None:
            self.allowed_tables: frozenset[str] = frozenset(t.lower() for t in allowed_tables)
        else:
            self.allowed_tables = self.DEFAULT_ALLOWED_TABLES

        if allowed_operations is not None:
            self.allowed_operations: frozenset[str] = frozenset(op.upper() for op in allowed_operations)
        else:
            self.allowed_operations = self.DEFAULT_ALLOWED_OPERATIONS

        self.max_limit = max_limit
        self.default_limit = default_limit

    def validate(self, query: SQLQuery | str) -> str:
        """
        Valida una consulta SQL (o modelo SQLQuery) contra todas las reglas de seguridad
        y devuelve la sentencia SQL sanitizada lista para ejecución.
        
        Args:
            query: Cadena SQL o instancia de SQLQuery.
            
        Returns:
            str: Consulta SQL validada y con LIMIT garantizado.
            
        Raises:
            SQLSyntaxValidationError: Si la consulta está vacía o tiene sintaxis básica inválida.
            SQLSecurityViolationError: Si la consulta viola alguna directriz de seguridad.
        """
        raw_sql = self._extract_raw_sql(query)
        clean_sql = raw_sql.strip()

        if not clean_sql:
            raise SQLSyntaxValidationError("SQL query cannot be empty")

        # 1. Comprobar balance de comillas y paréntesis
        self._check_balanced_syntax(clean_sql)

        # 2. Comprobar comentarios maliciosos
        self._check_comment_injection(clean_sql)

        # 3. Comprobar consultas apiladas (punto y coma)
        self._check_semicolons(clean_sql)

        # 4. Enmascarar literales de cadena (simples y dobles) para análisis léxico seguro
        masked_sql = self._mask_string_literals(clean_sql)

        # 5. Comprobar operación inicial permitida
        operation = self._validate_operation(masked_sql)

        # 6. Comprobar palabras clave peligrosas e inyecciones lógicas
        self._check_dangerous_keywords(masked_sql)
        self._check_injection_patterns(masked_sql)

        # 7. Validar lista blanca de tablas referenciadas (recursivo para subconsultas)
        # Usamos SQL con comillas simples enmascaradas para permitir identificadores de tabla entre comillas dobles
        sql_for_tables = re.sub(r"'(?:''|[^'])*'", "'__STR__'", clean_sql)
        self._validate_tables(sql_for_tables, operation)

        # 8. Guardrail de LIMIT para SELECT
        guarded_sql = self._enforce_limit(clean_sql, operation)

        return guarded_sql

    def _extract_raw_sql(self, query: SQLQuery | str) -> str:
        """Extrae la cadena SQL y valida metadatos si provienen de SQLQuery."""
        if query is None:
            raise SQLSyntaxValidationError("Query cannot be None")

        if isinstance(query, str):
            return query

        if hasattr(query, "sql_parameterized"):
            operation = getattr(query, "operation", None)
            if operation is not None:
                op_str = str(operation).upper()
                if op_str not in self.allowed_operations:
                    raise SQLSecurityViolationError(
                        f"SQLQuery operation '{op_str}' is not in allowed operations {sorted(self.allowed_operations)}"
                    )

            table = getattr(query, "table", None)
            if table is not None:
                tbl_tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9_]+", str(table))]
                if not any(t in self.allowed_tables for t in tbl_tokens):
                    raise SQLSecurityViolationError(
                        f"SQLQuery table '{table}' is not in allowed tables (not in permitted tables): {sorted(self.allowed_tables)}"
                    )

            sql_param = getattr(query, "sql_parameterized", None)
            if not isinstance(sql_param, str):
                raise SQLSyntaxValidationError("SQLQuery.sql_parameterized must be a string")
            return sql_param

        if hasattr(query, "sql") and isinstance(getattr(query, "sql"), str):
            return getattr(query, "sql")

        raise SQLSyntaxValidationError(f"Expected str or SQLQuery, received {type(query).__name__}")

    def _check_balanced_syntax(self, sql: str) -> None:
        """Verifica que no haya comillas o paréntesis sin cerrar."""
        # Remover comillas escapadas estándar SQL ('') o barra (\')
        cleaned_single = re.sub(r"''|\\'", "", sql)
        if cleaned_single.count("'") % 2 != 0:
            raise SQLSyntaxValidationError("Unbalanced single quotes detected in query")

        cleaned_double = re.sub(r'""|\\"', "", sql)
        if cleaned_double.count('"') % 2 != 0:
            raise SQLSyntaxValidationError("Unbalanced double quotes detected in query")

        # Paréntesis balanceados fuera de cadenas
        masked = self._mask_string_literals(sql)
        open_count = 0
        for char in masked:
            if char == "(":
                open_count += 1
            elif char == ")":
                open_count -= 1
                if open_count < 0:
                    raise SQLSyntaxValidationError("Unmatched closing parenthesis detected in query")
        if open_count != 0:
            raise SQLSyntaxValidationError("Unmatched opening parenthesis detected in query")

    def _check_comment_injection(self, sql: str) -> None:
        """Rechaza trucos de evasión basados en comentarios SQL."""
        if "--" in sql:
            raise SQLSecurityViolationError("SQL comment trick detected: '--' is prohibited (forbidden SQL keywords / comment injection)")
        if "/*" in sql or "*/" in sql:
            raise SQLSecurityViolationError("SQL comment trick detected: '/*' or '*/' is prohibited")
        if "#" in sql:
            raise SQLSecurityViolationError("SQL comment trick detected: '#' is prohibited")

    def _check_semicolons(self, sql: str) -> None:
        """Rechaza consultas apiladas (stacked queries) o uso de punto y coma."""
        if ";" in sql:
            raise SQLSecurityViolationError("Prohibited multi-statement SQL query detected: stacked queries or semicolons (';') are prohibited")

    def _mask_string_literals(self, sql: str) -> str:
        """Reemplaza los literales de cadena ('...' y \"...\") con marcadores neutros para análisis seguro."""
        masked = re.sub(r"'(?:''|[^'])*'", "'__STR__'", sql)
        masked = re.sub(r'"(?:""|[^"])*"', '"__STR__"', masked)
        return masked

    def _validate_operation(self, masked_sql: str) -> str:
        """Verifica que la operación inicial sea estrictamente permitida."""
        tokens = re.findall(r"[a-zA-Z_]+", masked_sql)
        if not tokens:
            raise SQLSyntaxValidationError("No valid SQL command tokens found in query")

        first_token = tokens[0].upper()

        if first_token in self.FORBIDDEN_OPERATIONS:
            raise SQLSecurityViolationError(
                f"Forbidden SQL operation detected: '{first_token}' is strictly prohibited"
            )

        if first_token not in self.allowed_operations:
            raise SQLSecurityViolationError(
                f"Unauthorized operation: '{first_token}'. Only {sorted(self.allowed_operations)} are allowed"
            )

        return first_token

    def _check_dangerous_keywords(self, masked_sql: str) -> None:
        """Busca palabras clave peligrosas o DDL/DML destructivo en cualquier parte de la consulta."""
        # Palabras clave prohibidas como tokens aislados
        pattern = re.compile(
            r"\b(" + "|".join(sorted(self.DANGEROUS_KEYWORDS)) + r")\b",
            re.IGNORECASE,
        )
        match = pattern.search(masked_sql)
        if match:
            keyword = match.group(1).upper()
            raise SQLSecurityViolationError(
                f"Dangerous SQL keyword detected in query: '{keyword}'"
            )

        # Inyecciones de exportación o lectura de archivos
        if re.search(r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b", masked_sql, re.IGNORECASE):
            raise SQLSecurityViolationError("File export operations ('INTO OUTFILE/DUMPFILE') are prohibited")
        if re.search(r"\bLOAD_FILE\b", masked_sql, re.IGNORECASE):
            raise SQLSecurityViolationError("File read operations ('LOAD_FILE') are prohibited")

        # Catálogos y tablas internas de sistemas de base de datos
        for bad_table in self.DANGEROUS_TABLES_AND_SCHEMAS:
            if re.search(r"\b" + re.escape(bad_table) + r"\b", masked_sql, re.IGNORECASE):
                raise SQLSecurityViolationError(
                    f"Access to database system table/schema '{bad_table}' is prohibited"
                )

    def _check_injection_patterns(self, masked_sql: str) -> None:
        """Detecta patrones comunes de inyección SQL sin parametrizar (tautologías, booleanos)."""
        # Tautologías numéricas o alfanuméricas: OR 1=1, WHERE 1=1, OR 'a'='a', WHERE "a"="a"
        if re.search(r"\b(?:OR|WHERE)\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1['\"]?", masked_sql, re.IGNORECASE):
            raise SQLSecurityViolationError("SQL injection pattern detected: boolean tautology (e.g. OR 1=1)")

        # Tautologías de cadenas vacías o enmascaradas: OR '__STR__'='__STR__', WHERE "__STR__"="__STR__"
        if re.search(r"\b(?:OR|WHERE)\b\s+['\"]__STR__['\"]\s*=\s*['\"]__STR__['\"]", masked_sql, re.IGNORECASE):
            raise SQLSecurityViolationError("SQL injection pattern detected: string tautology (e.g. OR ''='')")

        # Tautologías con booleanos literales: OR TRUE, WHERE TRUE, OR 1
        if re.search(r"\b(?:OR|WHERE)\b\s+TRUE\b", masked_sql, re.IGNORECASE):
            raise SQLSecurityViolationError("SQL injection pattern detected: 'OR TRUE' tautology")

        # Funciones de carga de extensiones o ejecución remota
        if re.search(r"\b(?:load_extension|writefile|readfile|edit)\s*\(", masked_sql, re.IGNORECASE):
            raise SQLSecurityViolationError("Dangerous SQLite extension function detected")

    def _clean_table_name(self, raw_table: str) -> str:
        """Limpia comillas, delimitadores y esquemas de un identificador de tabla."""
        # Limpiar delimitadores
        cleaned = raw_table.strip().strip('"\'`[]')

        # Manejar prefijos de esquema (ej. main.incidents)
        if "." in cleaned:
            parts = cleaned.split(".", 1)
            schema = parts[0].strip().strip('"\'`[]').lower()
            tbl = parts[1].strip().strip('"\'`[]').lower()
            if schema not in ("", "main"):
                raise SQLSecurityViolationError(f"Unauthorized schema prefix '{schema}'")
            return tbl

        return cleaned.lower()

    def _extract_parenthesized_block(self, s: str, start_idx: int) -> tuple[str, int]:
        """Dado un string y el índice de '(', retorna el contenido interior del bloque y el índice de ')' de cierre."""
        depth = 0
        for i in range(start_idx, len(s)):
            if s[i] == "(":
                depth += 1
            elif s[i] == ")":
                depth -= 1
                if depth == 0:
                    return s[start_idx + 1:i], i
        return s[start_idx + 1:], len(s)

    def _extract_all_tables(self, sql_text: str, operation: str) -> set[str]:
        """Extrae de forma exhaustiva y recursiva todas las tablas referenciadas en la consulta y subconsultas."""
        extracted: set[str] = set()

        if operation == "INSERT":
            match = re.search(
                r"\bINSERT\s+INTO\s+([a-zA-Z0-9_.\"\[\]`]+)",
                sql_text,
                re.IGNORECASE,
            )
            if not match:
                raise SQLSyntaxValidationError("Malformed INSERT statement: missing target table")
            tbl = self._clean_table_name(match.group(1))
            extracted.add(tbl)

        # 1. Extraer tablas de cláusulas FROM (incluyendo subconsultas FROM (...) y listas separadas por comas)
        from_iter = re.finditer(r"\bFROM\s+", sql_text, re.IGNORECASE)
        for fm in from_iter:
            start_pos = fm.end()
            remainder = sql_text[start_pos:]
            idx = 0
            while idx < len(remainder):
                # Saltar espacios
                while idx < len(remainder) and remainder[idx] in " \t\n\r":
                    idx += 1
                if idx >= len(remainder):
                    break

                # Si encontramos un paréntesis: subconsulta FROM (...)
                if remainder[idx] == "(":
                    inner_sql, close_idx = self._extract_parenthesized_block(remainder, idx)
                    extracted.update(self._extract_all_tables(inner_sql, "SELECT"))
                    idx = close_idx + 1
                    # Saltar alias opcional después de subconsulta
                    alias_match = re.match(r"^\s*(?:AS\s+)?([a-zA-Z0-9_\"\[\]`]+)", remainder[idx:], re.IGNORECASE)
                    if alias_match:
                        idx += alias_match.end()
                else:
                    # Comprobar si llegamos a una palabra clave delimitadora de cláusula
                    clause_match = re.match(
                        r"^(?:WHERE|JOIN|LEFT|RIGHT|INNER|CROSS|NATURAL|FULL|OUTER|GROUP|HAVING|ORDER|LIMIT|UNION|ON|USING|SET|VALUES)\b|\)",
                        remainder[idx:],
                        re.IGNORECASE,
                    )
                    if clause_match:
                        break

                    # Extraer identificador de tabla
                    chunk_match = re.match(r"^([a-zA-Z0-9_.\"\[\]`]+)", remainder[idx:])
                    if chunk_match:
                        tbl_raw = chunk_match.group(1)
                        tbl = self._clean_table_name(tbl_raw)
                        extracted.add(tbl)
                        idx += chunk_match.end()
                        # Saltar alias si existe
                        alias_match = re.match(r"^\s+(?:AS\s+)?([a-zA-Z0-9_\"\[\]`]+)", remainder[idx:], re.IGNORECASE)
                        if alias_match:
                            idx += alias_match.end()
                    else:
                        idx += 1

                # Si el siguiente carácter relevante es una coma, continuamos con la siguiente tabla en la lista FROM
                comma_match = re.match(r"^\s*,", remainder[idx:])
                if comma_match:
                    idx += comma_match.end()
                else:
                    break

        # 2. Extraer tablas de cláusulas JOIN
        join_iter = re.finditer(r"\bJOIN\s+", sql_text, re.IGNORECASE)
        for jm in join_iter:
            start_pos = jm.end()
            remainder = sql_text[start_pos:]
            remainder_stripped = remainder.lstrip()
            offset = len(remainder) - len(remainder_stripped)
            if remainder_stripped.startswith("("):
                inner_sql, _ = self._extract_parenthesized_block(remainder, offset)
                extracted.update(self._extract_all_tables(inner_sql, "SELECT"))
            else:
                tbl_match = re.match(r"^([a-zA-Z0-9_.\"\[\]`]+)", remainder_stripped)
                if tbl_match:
                    tbl = self._clean_table_name(tbl_match.group(1))
                    extracted.add(tbl)

        # 3. Extraer cualquier otra subconsulta (ej. WHERE id IN (SELECT ...) o (SELECT ...))
        select_iter = re.finditer(r"\(\s*SELECT\b", sql_text, re.IGNORECASE)
        for sm in select_iter:
            inner_sql, _ = self._extract_parenthesized_block(sql_text, sm.start())
            extracted.update(self._extract_all_tables(inner_sql, "SELECT"))

        return extracted

    def _validate_tables(self, sql_for_tables: str, operation: str) -> None:
        """Extrae todas las tablas referenciadas recursivamente y valida que estén en la lista blanca."""
        extracted_tables = self._extract_all_tables(sql_for_tables, operation)

        if not extracted_tables:
            raise SQLSecurityViolationError("Query does not reference any allowed forensic tables")

        # Verificar cada tabla contra la lista blanca
        for tbl in extracted_tables:
            if tbl not in self.allowed_tables:
                raise SQLSecurityViolationError(
                    f"Table '{tbl}' is not in the whitelist (permitted tables): {sorted(self.allowed_tables)}"
                )

    def _enforce_limit(self, clean_sql: str, operation: str) -> str:
        """Asegura que las consultas SELECT tengan una cláusula LIMIT válida <= max_limit."""
        if operation != "SELECT":
            return clean_sql

        # Verificar todas las cláusulas LIMIT en la consulta (incluyendo subconsultas)
        limit_matches = re.finditer(
            r"\bLIMIT\s+([^\s,;)]+)(?:\s*(?:,|\bOFFSET\b)\s*([^\s,;)]+))?",
            clean_sql,
            re.IGNORECASE,
        )

        for lm in limit_matches:
            raw_val = lm.group(1).strip()
            if raw_val.startswith(":") or raw_val == "?":
                continue
            try:
                limit_num = int(raw_val)
            except ValueError:
                raise SQLSecurityViolationError(f"Non-integer LIMIT clause detected: '{raw_val}'")

            if limit_num <= 0:
                raise SQLSecurityViolationError(
                    f"LIMIT must be a positive integer, got {limit_num}"
                )

            if limit_num > self.max_limit:
                raise SQLSecurityViolationError(
                    f"LIMIT {limit_num} exceeds maximum allowed limit of {self.max_limit}"
                )

        # Comprobar si la consulta principal termina con una cláusula LIMIT
        has_outer_limit = bool(
            re.search(r"\bLIMIT\s+(?:\d+|:[a-zA-Z0-9_]+|\?)(?:\s+OFFSET\s+(?:\d+|:[a-zA-Z0-9_]+|\?))?\s*$", clean_sql, re.IGNORECASE)
        )

        if not has_outer_limit:
            return f"{clean_sql} LIMIT {self.default_limit}"

        return clean_sql


# Instancia por defecto lista para usar
default_guard = SQLGuard()


def validate_sql(query: SQLQuery | str) -> str:
    """Función de conveniencia a nivel de módulo para validar SQL usando el guard por defecto."""
    return default_guard.validate(query)

