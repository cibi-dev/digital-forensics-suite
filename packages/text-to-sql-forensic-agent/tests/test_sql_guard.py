"""
Suite de tests exhaustiva para SQLGuard y seguridad de consultas forenses.
"""
from __future__ import annotations

import pytest

from forensic_agent.models import SQLQuery
from forensic_agent.sql_guard import (
    SQLGuard,
    SQLGuardError,
    SQLSecurityViolationError,
    SQLSyntaxValidationError,
    validate_sql,
)


@pytest.fixture
def guard() -> SQLGuard:
    """Instancia estándar de SQLGuard."""
    return SQLGuard()


# ============================================================================
# 1. PRUEBAS DE OPERACIONES VÁLIDAS (SELECT & INSERT)
# ============================================================================

class TestValidOperations:
    """Verifica que las consultas SELECT e INSERT legítimas sean aceptadas y formateadas."""

    def test_valid_select_simple_appends_limit(self, guard: SQLGuard) -> None:
        """SELECT simple sin LIMIT debe pasar y recibir LIMIT 100 automáticamente."""
        sql = "SELECT * FROM incidents"
        result = guard.validate(sql)
        assert result == "SELECT * FROM incidents LIMIT 100"

    def test_valid_select_with_existing_limit(self, guard: SQLGuard) -> None:
        """SELECT con LIMIT <= 100 debe conservarse sin cambios."""
        sql = "SELECT id, title FROM suspects LIMIT 25"
        result = guard.validate(sql)
        assert result == "SELECT id, title FROM suspects LIMIT 25"

    def test_valid_select_with_max_limit(self, guard: SQLGuard) -> None:
        """SELECT con LIMIT 100 exacto debe ser permitido."""
        sql = "SELECT * FROM evidences LIMIT 100"
        result = guard.validate(sql)
        assert result == "SELECT * FROM evidences LIMIT 100"

    def test_valid_select_with_limit_and_offset(self, guard: SQLGuard) -> None:
        """SELECT con LIMIT y OFFSET válidos debe ser aceptado."""
        sql = "SELECT id, full_name FROM victims ORDER BY id DESC LIMIT 20 OFFSET 10"
        result = guard.validate(sql)
        assert result == "SELECT id, full_name FROM victims ORDER BY id DESC LIMIT 20 OFFSET 10"

    def test_valid_select_with_joins(self, guard: SQLGuard) -> None:
        """Consultas con JOINs entre tablas permitidas deben validarse correctamente."""
        sql = (
            "SELECT i.title, s.name, e.description "
            "FROM incidents i "
            "JOIN suspects s ON i.id = s.incident_id "
            "LEFT JOIN evidences e ON i.id = e.incident_id "
            "WHERE i.risk_level = 'HIGH' LIMIT 50"
        )
        result = guard.validate(sql)
        assert result == sql

    def test_valid_select_all_allowed_tables(self, guard: SQLGuard) -> None:
        """Todas las tablas de la lista blanca deben ser accesibles."""
        for table in ["incidents", "suspects", "evidences", "victims"]:
            sql = f"SELECT * FROM {table}"  # nosec B608
            result = guard.validate(sql)
            assert result == f"SELECT * FROM {table} LIMIT 100"  # nosec B608

    def test_valid_select_with_subquery(self, guard: SQLGuard) -> None:
        """Subconsultas sobre tablas permitidas deben pasar."""
        sql = (
            "SELECT * FROM incidents "
            "WHERE id IN (SELECT incident_id FROM evidences WHERE type = 'DNA' LIMIT 10)"
        )
        result = guard.validate(sql)
        assert result == f"{sql} LIMIT 100"

    def test_valid_insert_parameterized(self, guard: SQLGuard) -> None:
        """Sentencia INSERT con parámetros posicionales ('?') debe pasar sin alterar LIMIT."""
        sql = "INSERT INTO incidents (title, date, risk_level) VALUES (?, ?, ?)"
        result = guard.validate(sql)
        assert result == sql
        assert "LIMIT" not in result

    def test_valid_insert_named_parameters(self, guard: SQLGuard) -> None:
        """Sentencia INSERT con parámetros nombrados (':param') debe ser válida."""
        sql = "INSERT INTO suspects (name, alias, incident_id) VALUES (:name, :alias, :incident_id)"
        result = guard.validate(sql)
        assert result == sql

    def test_valid_sqlquery_pydantic_instance(self, guard: SQLGuard) -> None:
        """Validar una instancia Pydantic de SQLQuery."""
        query = SQLQuery(
            operation="SELECT",
            table="evidences",
            sql_parameterized="SELECT id, hash FROM evidences WHERE incident_id = ?",
            params=[42],
        )
        result = guard.validate(query)
        assert result == "SELECT id, hash FROM evidences WHERE incident_id = ? LIMIT 100"

    def test_valid_sqlquery_insert(self, guard: SQLGuard) -> None:
        """Validar una instancia Pydantic de SQLQuery con operación INSERT."""
        query = SQLQuery(
            operation="INSERT",
            table="victims",
            sql_parameterized="INSERT INTO victims (full_name, age) VALUES (?, ?)",
            params=["Jane Doe", 34],
        )
        result = guard.validate(query)
        assert result == "INSERT INTO victims (full_name, age) VALUES (?, ?)"

    def test_valid_quoted_identifiers(self, guard: SQLGuard) -> None:
        """Validar identificadores con comillas dobles, backticks o corchetes."""
        assert guard.validate('SELECT * FROM "incidents"') == 'SELECT * FROM "incidents" LIMIT 100'
        assert guard.validate("SELECT * FROM `suspects`") == "SELECT * FROM `suspects` LIMIT 100"
        assert guard.validate("SELECT * FROM [evidences]") == "SELECT * FROM [evidences] LIMIT 100"

    def test_valid_schema_prefix_main(self, guard: SQLGuard) -> None:
        """El prefijo de esquema 'main.' debe ser permitido."""
        sql = "SELECT * FROM main.incidents"
        result = guard.validate(sql)
        assert result == "SELECT * FROM main.incidents LIMIT 100"


# ============================================================================
# 2. RECHAZO DE OPERACIONES PROHIBIDAS (DDL / DML DESTRUCTIVO)
# ============================================================================

class TestRejectForbiddenOperations:
    """Verifica el rechazo estricto de operaciones no permitidas."""

    @pytest.mark.parametrize("operation,sql", [
        ("DROP", "DROP TABLE suspects"),
        ("DROP_VIEW", "DROP VIEW IF EXISTS incident_view"),
        ("DELETE", "DELETE FROM incidents WHERE id = 1"),
        ("UPDATE", "UPDATE suspects SET status = 'cleared' WHERE id = 5"),
        ("ALTER", "ALTER TABLE victims ADD COLUMN confidential TEXT"),
        ("ATTACH", "ATTACH DATABASE '/tmp/pwn.db' AS pwn"),
        ("DETACH", "DETACH DATABASE pwn"),
        ("PRAGMA", "PRAGMA table_info(incidents)"),
        ("VACUUM", "VACUUM"),
        ("EXEC", "EXEC sp_executesql N'SELECT 1'"),
        ("EXECUTE", "EXECUTE stmt_name"),
        ("CREATE", "CREATE TABLE backdoor (id INT)"),
        ("TRUNCATE", "TRUNCATE TABLE evidences"),
        ("REPLACE", "REPLACE INTO incidents (id, title) VALUES (1, 'Hacked')"),
        ("GRANT", "GRANT ALL PRIVILEGES ON incidents TO guest"),
        ("REVOKE", "REVOKE SELECT ON incidents FROM guest"),
    ])
    def test_reject_forbidden_operations(self, guard: SQLGuard, operation: str, sql: str) -> None:
        """Cada operación prohibida debe lanzar SQLSecurityViolationError."""
        with pytest.raises(SQLSecurityViolationError, match="(?i)(forbidden|unauthorized|prohibited|dangerous)"):
            guard.validate(sql)

    def test_reject_dangerous_keyword_in_subquery(self, guard: SQLGuard) -> None:
        """Palabras clave destructivas en subconsultas deben ser bloqueadas."""
        sql = "SELECT * FROM incidents WHERE id = (DELETE FROM suspects RETURNING id)"
        with pytest.raises(SQLSecurityViolationError, match="(?i)dangerous SQL keyword"):
            guard.validate(sql)


# ============================================================================
# 3. RECHAZO DE CONSULTAS APILADAS Y PUNTO Y COMA (STACKED QUERIES)
# ============================================================================

class TestRejectStackedQueries:
    """Verifica la detección y bloqueo de inyecciones multiconsulta y punto y coma."""

    def test_reject_stacked_drop_after_select(self, guard: SQLGuard) -> None:
        """SELECT seguido de DROP mediante ';' debe lanzar violación de seguridad."""
        sql = "SELECT * FROM incidents; DROP TABLE suspects"
        with pytest.raises(SQLSecurityViolationError, match="(?i)semicolons"):
            guard.validate(sql)

    def test_reject_stacked_select_queries(self, guard: SQLGuard) -> None:
        """Múltiples SELECT separados por ';' deben ser rechazados."""
        sql = "SELECT * FROM incidents; SELECT * FROM suspects"
        with pytest.raises(SQLSecurityViolationError, match="(?i)semicolons"):
            guard.validate(sql)

    def test_reject_trailing_semicolon(self, guard: SQLGuard) -> None:
        """Cualquier ';' al final debe ser rechazado para forzar consultas sin concatenar."""
        sql = "SELECT * FROM incidents;"
        with pytest.raises(SQLSecurityViolationError, match="(?i)semicolons"):
            guard.validate(sql)

    def test_reject_embedded_semicolon_in_insert(self, guard: SQLGuard) -> None:
        """INSERT con ';' embebido debe ser rechazado."""
        sql = "INSERT INTO incidents (title) VALUES ('hacked'); DELETE FROM victims"
        with pytest.raises(SQLSecurityViolationError, match="(?i)semicolons"):
            guard.validate(sql)


# ============================================================================
# 4. ENFORCEMENT DE LÍMITE (LIMIT GUARD)
# ============================================================================

class TestLimitEnforcement:
    """Verifica el control automático y límites numéricos de la cláusula LIMIT."""

    def test_limit_appended_when_missing(self, guard: SQLGuard) -> None:
        """Consulta SELECT compleja sin LIMIT recibe LIMIT 100."""
        sql = "SELECT i.id, i.date FROM incidents i WHERE i.risk_level = 'CRITICAL'"
        result = guard.validate(sql)
        assert result.endswith("LIMIT 100")

    def test_limit_exceeding_max_rejected(self, guard: SQLGuard) -> None:
        """LIMIT superior a 100 debe ser rechazado."""
        sql = "SELECT * FROM incidents LIMIT 101"
        with pytest.raises(SQLSecurityViolationError, match="LIMIT 101 exceeds maximum"):
            guard.validate(sql)

    def test_limit_large_number_rejected(self, guard: SQLGuard) -> None:
        """LIMIT masivo (10000) debe ser rechazado."""
        sql = "SELECT * FROM suspects LIMIT 10000"
        with pytest.raises(SQLSecurityViolationError, match="exceeds maximum"):
            guard.validate(sql)

    def test_limit_zero_rejected(self, guard: SQLGuard) -> None:
        """LIMIT 0 no es válido y debe ser rechazado."""
        sql = "SELECT * FROM evidences LIMIT 0"
        with pytest.raises(SQLSecurityViolationError, match="LIMIT must be a positive integer"):
            guard.validate(sql)

    def test_limit_negative_rejected(self, guard: SQLGuard) -> None:
        """LIMIT negativo debe ser rechazado."""
        sql = "SELECT * FROM victims LIMIT -1"
        with pytest.raises(SQLSecurityViolationError, match="LIMIT must be a positive integer"):
            guard.validate(sql)

    def test_limit_subquery_exceeding_max_rejected(self, guard: SQLGuard) -> None:
        """LIMIT > 100 dentro de una subconsulta debe ser detectado y rechazado."""
        sql = "SELECT * FROM incidents WHERE id IN (SELECT incident_id FROM evidences LIMIT 500)"
        with pytest.raises(SQLSecurityViolationError, match="exceeds maximum"):
            guard.validate(sql)


# ============================================================================
# 5. LISTA BLANCA DE TABLAS Y ESQUEMAS
# ============================================================================

class TestTableWhitelist:
    """Verifica que solo las 4 tablas forenses autorizadas puedan ser consultadas."""

    def test_reject_unauthorized_table_users(self, guard: SQLGuard) -> None:
        """Acceso a tabla 'users' debe ser bloqueado."""
        sql = "SELECT * FROM users"
        with pytest.raises(SQLSecurityViolationError, match="Table 'users' is not in the whitelist"):
            guard.validate(sql)

    def test_reject_sqlite_master_catalog(self, guard: SQLGuard) -> None:
        """Acceso al catálogo del sistema 'sqlite_master' debe ser bloqueado."""
        sql = "SELECT name FROM sqlite_master WHERE type='table'"
        with pytest.raises(SQLSecurityViolationError, match="(?i)(prohibited|whitelist|system table)"):
            guard.validate(sql)

    def test_reject_sqlite_schema(self, guard: SQLGuard) -> None:
        """Acceso a 'sqlite_schema' debe ser bloqueado."""
        sql = "SELECT sql FROM sqlite_schema"
        with pytest.raises(SQLSecurityViolationError, match="(?i)(prohibited|whitelist|system table)"):
            guard.validate(sql)

    def test_reject_unauthorized_join_table(self, guard: SQLGuard) -> None:
        """JOIN con una tabla no autorizada debe ser bloqueado."""
        sql = "SELECT * FROM incidents i JOIN passwords p ON i.id = p.id"
        with pytest.raises(SQLSecurityViolationError, match="Table 'passwords' is not in the whitelist"):
            guard.validate(sql)

    def test_reject_unauthorized_subquery_table(self, guard: SQLGuard) -> None:
        """Subconsulta que acceda a tabla no autorizada debe ser bloqueada."""
        sql = "SELECT * FROM incidents WHERE id IN (SELECT incident_id FROM secret_tokens)"
        with pytest.raises(SQLSecurityViolationError, match="Table 'secret_tokens' is not in the whitelist"):
            guard.validate(sql)

    def test_reject_insert_into_unauthorized_table(self, guard: SQLGuard) -> None:
        """INSERT en tabla no autorizada debe ser bloqueado."""
        sql = "INSERT INTO admin_users (name) VALUES ('evil')"
        with pytest.raises(SQLSecurityViolationError, match="Table 'admin_users' is not in the whitelist"):
            guard.validate(sql)

    def test_reject_unauthorized_schema_prefix(self, guard: SQLGuard) -> None:
        """Uso de esquemas externos no 'main' debe ser bloqueado."""
        sql = "SELECT * FROM evil_db.incidents"
        with pytest.raises(SQLSecurityViolationError, match="Unauthorized schema prefix 'evil_db'"):
            guard.validate(sql)

    def test_reject_no_table_referenced(self, guard: SQLGuard) -> None:
        """Consultas que no referencien ninguna tabla forense (ej. SELECT 1) deben ser bloqueadas."""
        sql = "SELECT 1"
        with pytest.raises(SQLSecurityViolationError, match="does not reference any allowed forensic tables"):
            guard.validate(sql)


# ============================================================================
# 6. DETECCIÓN DE TRUCOS DE EVASIÓN BASADOS EN COMENTARIOS
# ============================================================================

class TestCommentBypasses:
    """Verifica el bloqueo de trucos de evasión con comentarios SQL."""

    def test_reject_inline_dash_comment(self, guard: SQLGuard) -> None:
        """Comentario '--' debe ser rechazado."""
        sql = "SELECT * FROM incidents WHERE id = 1 -- comment bypass"
        with pytest.raises(SQLSecurityViolationError, match="SQL comment trick detected: '--'"):
            guard.validate(sql)

    def test_reject_block_comment(self, guard: SQLGuard) -> None:
        """Comentario '/* ... */' debe ser rechazado."""
        sql = "SELECT * FROM /* comment */ incidents"
        with pytest.raises(SQLSecurityViolationError, match="SQL comment trick detected: '/\\*'"):
            guard.validate(sql)

    def test_reject_hash_comment(self, guard: SQLGuard) -> None:
        """Comentario '#' estilo MySQL/SQLite debe ser rechazado."""
        sql = "SELECT * FROM incidents # trailing comment"
        with pytest.raises(SQLSecurityViolationError, match="SQL comment trick detected: '#'"):
            guard.validate(sql)


# ============================================================================
# 7. DETECCIÓN DE INYECCIONES LÓGICAS Y EXPORTACIÓN DE ARCHIVOS
# ============================================================================

class TestInjectionPatterns:
    """Verifica el bloqueo de inyecciones de tautología, llamadas al sistema y exfiltración."""

    def test_reject_tautology_or_1_1(self, guard: SQLGuard) -> None:
        """Inyección booleana 'OR 1=1' debe ser bloqueada."""
        sql = "SELECT * FROM incidents WHERE title = '' OR 1=1"
        with pytest.raises(SQLSecurityViolationError, match="boolean tautology"):
            guard.validate(sql)

    def test_reject_tautology_or_quoted_1_1(self, guard: SQLGuard) -> None:
        """Inyección de cadenas 'OR '1'='1'' debe ser bloqueada."""
        sql = "SELECT * FROM incidents WHERE title = 'a' OR '1'='1'"
        with pytest.raises(SQLSecurityViolationError, match="boolean tautology"):
            guard.validate(sql)

    def test_reject_tautology_or_empty_strings(self, guard: SQLGuard) -> None:
        """Inyección 'OR ''=''' debe ser bloqueada."""
        sql = "SELECT * FROM incidents WHERE title = '' OR ''=''"
        with pytest.raises(SQLSecurityViolationError, match="(?i)tautology"):
            guard.validate(sql)

    def test_reject_tautology_or_true(self, guard: SQLGuard) -> None:
        """Inyección 'OR TRUE' debe ser bloqueada."""
        sql = "SELECT * FROM incidents WHERE title = 'test' OR TRUE"
        with pytest.raises(SQLSecurityViolationError, match="(?i)tautology"):
            guard.validate(sql)

    def test_reject_into_outfile_export(self, guard: SQLGuard) -> None:
        """Exportación mediante INTO OUTFILE debe ser bloqueada."""
        sql = "SELECT * FROM incidents INTO OUTFILE '/tmp/dump.txt'"
        with pytest.raises(SQLSecurityViolationError, match="File export operations"):
            guard.validate(sql)

    def test_reject_load_file(self, guard: SQLGuard) -> None:
        """Lectura arbitraria mediante LOAD_FILE debe ser bloqueada."""
        sql = "SELECT LOAD_FILE('/etc/passwd') FROM incidents"
        with pytest.raises(SQLSecurityViolationError, match="File read operations"):
            guard.validate(sql)

    def test_reject_sqlite_load_extension(self, guard: SQLGuard) -> None:
        """Llamadas a load_extension de SQLite deben ser bloqueadas."""
        sql = "SELECT load_extension('/path/evil.so') FROM incidents"
        with pytest.raises(SQLSecurityViolationError, match="(?i)(load_extension|dangerous)"):
            guard.validate(sql)


# ============================================================================
# 8. VALIDACIÓN DE SINTAXIS Y ENTRADAS INVÁLIDAS
# ============================================================================

class TestSyntaxValidation:
    """Verifica el comportamiento ante sintaxis inválida, comillas desbalanceadas y entradas nulas."""

    def test_reject_none_query(self, guard: SQLGuard) -> None:
        """None debe lanzar SQLSyntaxValidationError."""
        with pytest.raises(SQLSyntaxValidationError, match="cannot be None"):
            guard.validate(None)  # type: ignore[arg-type]

    def test_reject_empty_string(self, guard: SQLGuard) -> None:
        """Cadena vacía debe lanzar SQLSyntaxValidationError."""
        with pytest.raises(SQLSyntaxValidationError, match="cannot be empty"):
            guard.validate("")

    def test_reject_whitespace_string(self, guard: SQLGuard) -> None:
        """Espacios en blanco deben lanzar SQLSyntaxValidationError."""
        with pytest.raises(SQLSyntaxValidationError, match="cannot be empty"):
            guard.validate("   \n\t  ")

    def test_reject_invalid_data_type(self, guard: SQLGuard) -> None:
        """Tipos de datos no soportados deben lanzar SQLSyntaxValidationError."""
        with pytest.raises(SQLSyntaxValidationError, match="Expected str or SQLQuery"):
            guard.validate(12345)  # type: ignore[arg-type]

    def test_reject_unbalanced_single_quotes(self, guard: SQLGuard) -> None:
        """Comillas simples desbalanceadas deben lanzar SQLSyntaxValidationError."""
        sql = "SELECT * FROM incidents WHERE title = 'unclosed string"
        with pytest.raises(SQLSyntaxValidationError, match="Unbalanced single quotes"):
            guard.validate(sql)

    def test_reject_unbalanced_double_quotes(self, guard: SQLGuard) -> None:
        """Comillas dobles desbalanceadas deben lanzar SQLSyntaxValidationError."""
        sql = 'SELECT * FROM "incidents WHERE id = 1'
        with pytest.raises(SQLSyntaxValidationError, match="Unbalanced double quotes"):
            guard.validate(sql)

    def test_reject_unbalanced_parentheses_open(self, guard: SQLGuard) -> None:
        """Paréntesis abiertos sin cerrar deben lanzar SQLSyntaxValidationError."""
        sql = "SELECT * FROM incidents WHERE (id = 1"
        with pytest.raises(SQLSyntaxValidationError, match="Unmatched opening parenthesis"):
            guard.validate(sql)

    def test_reject_unbalanced_parentheses_close(self, guard: SQLGuard) -> None:
        """Paréntesis de cierre sobrantes deben lanzar SQLSyntaxValidationError."""
        sql = "SELECT * FROM incidents WHERE id = 1)"
        with pytest.raises(SQLSyntaxValidationError, match="Unmatched closing parenthesis"):
            guard.validate(sql)

    def test_reject_malformed_insert_no_table(self, guard: SQLGuard) -> None:
        """INSERT sin tabla destino debe lanzar SQLSyntaxValidationError."""
        sql = "INSERT VALUES (1, 2, 3)"
        with pytest.raises(SQLSyntaxValidationError, match="Malformed INSERT"):
            guard.validate(sql)


# ============================================================================
# 9. VALIDACIÓN DE MODELO SQLQuery Y CONFIGURACIÓN PERSONALIZADA
# ============================================================================

class TestSQLQueryIntegrationAndCustomConfig:
    """Verifica integración con SQLQuery y parametrización de SQLGuard."""

    def test_sqlquery_with_unauthorized_operation_rejected(self, guard: SQLGuard) -> None:
        """SQLQuery con operation='DELETE' debe lanzar SQLSecurityViolationError."""
        raw_query = SQLQuery.model_construct(
            operation="DELETE",  # type: ignore[arg-type]
            table="incidents",
            sql_parameterized="DELETE FROM incidents WHERE id = 1",
            params={},
        )
        with pytest.raises(SQLSecurityViolationError, match="not in allowed operations"):
            guard.validate(raw_query)

    def test_sqlquery_with_unauthorized_table_rejected(self, guard: SQLGuard) -> None:
        """SQLQuery con tabla no permitida debe lanzar SQLSecurityViolationError."""
        query = SQLQuery.model_construct(
            operation="SELECT",
            table="super_admin",
            sql_parameterized="SELECT * FROM super_admin",
            params={},
        )
        with pytest.raises(SQLSecurityViolationError, match="not in allowed tables"):
            guard.validate(query)

    def test_module_level_validate_sql_helper(self) -> None:
        """La función validate_sql() del módulo debe utilizar el guard por defecto."""
        sql = "SELECT * FROM suspects"
        result = validate_sql(sql)
        assert result == "SELECT * FROM suspects LIMIT 100"

    def test_custom_guard_configuration(self) -> None:
        """SQLGuard configurado con tablas o límites personalizados debe respetar su configuración."""
        custom_guard = SQLGuard(
            allowed_tables=["custom_cases"],
            allowed_operations=["SELECT"],
            max_limit=25,
            default_limit=25,
        )
        # La tabla por defecto 'incidents' ahora debe ser rechazada
        with pytest.raises(SQLSecurityViolationError, match="not in the whitelist"):
            custom_guard.validate("SELECT * FROM incidents")

        # La tabla personalizada 'custom_cases' debe ser aceptada con LIMIT 25
        valid_res = custom_guard.validate("SELECT * FROM custom_cases")
        assert valid_res == "SELECT * FROM custom_cases LIMIT 25"

        # LIMIT 50 debe exceder el max_limit personalizado de 25
        with pytest.raises(SQLSecurityViolationError, match="exceeds maximum"):
            custom_guard.validate("SELECT * FROM custom_cases LIMIT 50")


# ============================================================================
# 10. PRUEBAS DE SEGURIDAD P3: VALIDACIÓN RECURSIVA DE SUBCONSULTAS
# ============================================================================

class TestSubqueryWhitelistValidation:
    """P3: Verificación de listas blancas de tablas en subconsultas arbitrarias."""

    def test_reject_sqlite_master_in_from_subquery(self, guard: SQLGuard) -> None:
        """Subconsulta en FROM sobre sqlite_master debe ser bloqueada."""
        sql = "SELECT * FROM (SELECT * FROM sqlite_master)"
        with pytest.raises(SQLGuardError, match="(?i)(whitelist|prohibited|permitted tables)"):
            guard.validate(sql)

    def test_allow_allowed_table_in_where_subquery(self, guard: SQLGuard) -> None:
        """Subconsulta en WHERE sobre tabla permitida (suspects) debe ser aceptada."""
        sql = "SELECT * FROM incidents WHERE id IN (SELECT incident_id FROM suspects)"
        result = guard.validate(sql)
        assert "incidents" in result
        assert "suspects" in result
        assert result.endswith("LIMIT 100")

    def test_allow_allowed_table_in_from_subquery(self, guard: SQLGuard) -> None:
        """Subconsulta en FROM sobre tabla permitida (incidents) debe ser aceptada."""
        sql = "SELECT * FROM (SELECT * FROM incidents)"
        result = guard.validate(sql)
        assert "incidents" in result

    def test_reject_nested_subquery_unauthorized_table(self, guard: SQLGuard) -> None:
        """Subconsultas anidadas profundamente sobre tablas no autorizadas deben ser bloqueadas."""
        sql = "SELECT * FROM (SELECT * FROM (SELECT * FROM sqlite_temp_master))"
        with pytest.raises(SQLGuardError):
            guard.validate(sql)

    def test_reject_join_subquery_unauthorized_table(self, guard: SQLGuard) -> None:
        """JOIN con subconsulta a tabla del sistema o privada debe ser bloqueado."""
        sql = "SELECT * FROM incidents i JOIN (SELECT id FROM accounts) a ON i.id = a.id"
        with pytest.raises(SQLGuardError):
            guard.validate(sql)

    def test_reject_subquery_in_where_unauthorized_table(self, guard: SQLGuard) -> None:
        """Subconsulta en WHERE que acceda a sqlite_schema debe ser bloqueada."""
        sql = "SELECT * FROM incidents WHERE id IN (SELECT id FROM sqlite_schema)"
        with pytest.raises(SQLGuardError):
            guard.validate(sql)


# ============================================================================
# 11. PRUEBAS DE SEGURIDAD P4: ENMASCARADO DE COMILLAS DOBLES Y LITERALES
# ============================================================================

class TestDoubleQuoteMaskingAndLiterals:
    """P4: Enmascarado seguro de literales con comillas simples y dobles."""

    def test_single_quote_keyword_literal_not_false_positive(self, guard: SQLGuard) -> None:
        """Palabra clave 'DROP' dentro de comillas simples no debe generar falso positivo."""
        sql = "SELECT * FROM incidents WHERE summary = 'DROP'"
        result = guard.validate(sql)
        assert result.startswith("SELECT * FROM incidents WHERE summary = 'DROP'")

    def test_double_quote_keyword_literal_not_false_positive(self, guard: SQLGuard) -> None:
        """Palabra clave 'DROP' dentro de comillas dobles no debe generar falso positivo."""
        sql = 'SELECT * FROM incidents WHERE summary = "DROP"'
        result = guard.validate(sql)
        assert result.startswith('SELECT * FROM incidents WHERE summary = "DROP"')

    def test_double_quote_drop_table_phrase_not_false_positive(self, guard: SQLGuard) -> None:
        """Frase 'DROP TABLE suspects' dentro de comillas dobles no debe ser bloqueada."""
        sql = 'SELECT * FROM incidents WHERE summary = "DROP TABLE suspects"'
        result = guard.validate(sql)
        assert 'DROP TABLE suspects' in result

    def test_double_quoted_allowed_table_name_validated(self, guard: SQLGuard) -> None:
        """Identificador de tabla entre comillas dobles (\"incidents\") debe ser permitido."""
        sql = 'SELECT * FROM "incidents"'
        result = guard.validate(sql)
        assert result == 'SELECT * FROM "incidents" LIMIT 100'

    def test_double_quoted_unauthorized_table_name_rejected(self, guard: SQLGuard) -> None:
        """Identificador no autorizado entre comillas dobles (\"sqlite_master\") debe ser rechazado."""
        sql = 'SELECT * FROM "sqlite_master"'
        with pytest.raises(SQLGuardError):
            guard.validate(sql)

    def test_string_tautology_with_double_quotes_blocked(self, guard: SQLGuard) -> None:
        """Inyección de tautología con comillas dobles (\"a\"=\"a\") debe ser bloqueada."""
        sql = 'SELECT * FROM incidents WHERE "a"="a"'
        with pytest.raises(SQLSecurityViolationError, match="tautology"):
            guard.validate(sql)

