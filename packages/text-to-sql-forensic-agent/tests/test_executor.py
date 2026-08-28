"""Suite de pruebas unitarias y de integración para SQLExecutor y formateo de resultados."""

import sqlite3
import tempfile
from pathlib import Path
import pytest

from forensic_agent.executor import SQLExecutionError, SQLExecutor
from forensic_agent.models import QueryResult, SQLQuery
from forensic_agent.sql_guard import SQLGuard, SQLGuardError


@pytest.fixture
def memory_executor() -> SQLExecutor:
    """Fixture que provee un SQLExecutor en memoria con el esquema base cargado."""
    executor = SQLExecutor(db_path=":memory:")
    executor.init_db()
    return executor


@pytest.fixture
def seeded_executor() -> SQLExecutor:
    """Fixture que provee un SQLExecutor en memoria con esquema y datos semilla cargados."""
    executor = SQLExecutor(db_path=":memory:")
    executor.init_db(seed_path=True)
    return executor


class TestSQLExecutorInitDB:
    """Pruebas de inicialización de esquema y datos semilla."""

    def test_init_db_in_memory_creates_tables(self, memory_executor: SQLExecutor):
        """Verifica que init_db crea todas las tablas e índices esperados."""
        cursor = memory_executor.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [row[0] for row in cursor.fetchall()]
        
        assert "incidents" in tables
        assert "suspects" in tables
        assert "evidences" in tables
        assert "victims" in tables

    def test_init_db_with_seed(self, seeded_executor: SQLExecutor):
        """Verifica que el seed inicializa correctamente los registros de prueba."""
        res_inc = seeded_executor.execute("SELECT COUNT(*) AS total FROM incidents")
        assert res_inc.rows[0][0] >= 5

        res_sus = seeded_executor.execute("SELECT COUNT(*) AS total FROM suspects")
        assert res_sus.rows[0][0] >= 5

        res_ev = seeded_executor.execute("SELECT COUNT(*) AS total FROM evidences")
        assert res_ev.rows[0][0] >= 5

        res_vic = seeded_executor.execute("SELECT COUNT(*) AS total FROM victims")
        assert res_vic.rows[0][0] >= 4

    def test_init_db_custom_schema_and_seed(self, tmp_path: Path):
        """Prueba la inicialización con archivos de esquema y seed personalizados."""
        custom_schema = tmp_path / "custom_schema.sql"
        custom_schema.write_text("CREATE TABLE test_items (id INTEGER PRIMARY KEY, name TEXT);", encoding="utf-8")

        custom_seed = tmp_path / "custom_seed.sql"
        custom_seed.write_text("INSERT INTO test_items (name) VALUES ('Item A'), ('Item B');", encoding="utf-8")

        executor = SQLExecutor(db_path=":memory:")
        executor.init_db(schema_path=custom_schema, seed_path=custom_seed)

        cursor = executor.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM test_items")
        assert cursor.fetchone()[0] == 2

    def test_init_db_file_not_found(self):
        """Lanza FileNotFoundError si la ruta al esquema o seed no existe."""
        executor = SQLExecutor(db_path=":memory:")
        with pytest.raises(FileNotFoundError):
            executor.init_db(schema_path="/ruta/inexistente/esquema.sql")

        with pytest.raises(FileNotFoundError):
            executor.init_db(seed_path="/ruta/inexistente/seed.sql")


class TestSQLExecutorQueries:
    """Pruebas de ejecución de sentencias SELECT e INSERT."""

    def test_execute_select_empty_table(self, memory_executor: SQLExecutor):
        """SELECT en tabla vacía retorna QueryResult con columnas pero 0 filas."""
        result = memory_executor.execute("SELECT id, incident_type, risk_level FROM incidents")
        assert isinstance(result, QueryResult)
        assert result.operation == "SELECT"
        assert result.columns == ["id", "incident_type", "risk_level"]
        assert result.rows == []
        assert result.row_count == 0
        assert result.is_empty is True
        assert result.execution_time_ms >= 0.0

    def test_execute_select_with_data(self, seeded_executor: SQLExecutor):
        """SELECT retorna datos correctos y tiempo de ejecución medido."""
        result = seeded_executor.execute(
            "SELECT id, incident_type, risk_level FROM incidents WHERE risk_level = 'Alto'"
        )
        assert result.operation == "SELECT"
        assert len(result.rows) >= 1
        assert result.columns == ["id", "incident_type", "risk_level"]
        for row in result.rows:
            assert row[2] == "Alto"
        assert result.execution_time_ms > 0.0

    def test_execute_parameterized_select(self, seeded_executor: SQLExecutor):
        """SELECT parametrizado con lista/tupla de parámetros."""
        query = SQLQuery(
            operation="SELECT",
            table="suspects",
            sql_parameterized="SELECT alias_or_name, status FROM suspects WHERE status = ?",
            params=["En fuga"],
        )
        result = seeded_executor.execute(query)
        assert result.row_count >= 1
        for row in result.rows:
            assert row[1] == "En fuga"

    def test_execute_insert_single_record(self, memory_executor: SQLExecutor):
        """INSERT devuelve last_row_id y affected_rows == 1."""
        query = SQLQuery(
            operation="INSERT",
            table="incidents",
            sql_parameterized=(
                "INSERT INTO incidents (incident_type, date_approx, location, risk_level, summary) "
                "VALUES (?, ?, ?, ?, ?)"
            ),
            params=["Robo con fuerza", "2026-08-21 14:00", "Calle 50 #12", "Alto", "Ingreso forzado nocturno."],
        )
        result = memory_executor.execute(query)
        assert result.operation == "INSERT"
        assert result.last_row_id == 1
        assert result.affected_rows == 1

        # Verificar que se insertó correctamente
        check_res = memory_executor.execute("SELECT id, incident_type FROM incidents WHERE id = 1")
        assert check_res.row_count == 1
        assert check_res.rows[0][1] == "Robo con fuerza"


class TestSQLExecutorTransactions:
    """Pruebas de comportamiento transaccional y rollback en fallos."""

    def test_transaction_commit_persists(self, memory_executor: SQLExecutor):
        """Las inserciones sucesivas se confirman y persisten en la conexión."""
        for i in range(1, 4):
            memory_executor.execute(
                SQLQuery(
                    operation="INSERT",
                    table="incidents",
                    sql_parameterized="INSERT INTO incidents (incident_type, location, summary) VALUES (?, ?, ?)",
                    params=[f"Caso {i}", f"Lugar {i}", f"Resumen {i}"],
                )
            )

        res = memory_executor.execute("SELECT COUNT(*) FROM incidents")
        assert res.rows[0][0] == 3

    def test_transaction_rollback_on_constraint_violation(self, memory_executor: SQLExecutor):
        """Violación de FK o CHECK constraint realiza rollback del cambio."""
        # 1. Insertar incidente válido
        memory_executor.execute(
            SQLQuery(
                operation="INSERT",
                table="incidents",
                sql_parameterized="INSERT INTO incidents (id, incident_type, location) VALUES (10, 'Fraude', 'Online')",
            )
        )

        # 2. Intentar insertar sospechoso con incident_id inexistente (FK violation)
        # Nota: foreign_keys está ON
        with pytest.raises(SQLExecutionError):
            memory_executor.execute(
                SQLQuery(
                    operation="INSERT",
                    table="suspects",
                    sql_parameterized="INSERT INTO suspects (incident_id, alias_or_name) VALUES (999, 'Fantasma')",
                )
            )

        # 3. Verificar que el estado de la base de datos se mantiene consistente
        res = memory_executor.execute("SELECT COUNT(*) FROM suspects WHERE alias_or_name = 'Fantasma'")
        assert res.rows[0][0] == 0

    def test_execute_many_atomic_success(self, memory_executor: SQLExecutor):
        """execute_many ejecuta múltiples sentencias en una transacción exitosa."""
        queries = [
            SQLQuery(
                operation="INSERT",
                table="incidents",
                sql_parameterized="INSERT INTO incidents (id, incident_type, location) VALUES (1, 'Robo', 'Centro')",
            ),
            SQLQuery(
                operation="INSERT",
                table="suspects",
                sql_parameterized="INSERT INTO suspects (incident_id, alias_or_name, status) VALUES (1, 'Sujeto A', 'Detenido')",
            ),
            SQLQuery(
                operation="INSERT",
                table="evidences",
                sql_parameterized="INSERT INTO evidences (incident_id, item) VALUES (1, 'Cuchillo')",
            ),
        ]
        results = memory_executor.execute_many(queries)
        assert len(results) == 3

        check_res = memory_executor.execute("SELECT COUNT(*) FROM suspects WHERE incident_id = 1")
        assert check_res.rows[0][0] == 1

    def test_execute_many_atomic_rollback_on_failure(self, memory_executor: SQLExecutor):
        """execute_many realiza rollback de TODO el lote si alguna sentencia falla."""
        queries = [
            SQLQuery(
                operation="INSERT",
                table="incidents",
                sql_parameterized="INSERT INTO incidents (id, incident_type, location) VALUES (100, 'Incendio', 'Bosque')",
            ),
            # Esta sentencia fallará por FK violation (incident_id 99999 no existe)
            SQLQuery(
                operation="INSERT",
                table="suspects",
                sql_parameterized="INSERT INTO suspects (incident_id, alias_or_name) VALUES (99999, 'Pirómano')",
            ),
        ]

        with pytest.raises(SQLExecutionError):
            memory_executor.execute_many(queries)

        # El incidente 100 NO debe existir debido al rollback atómico
        check_inc = memory_executor.execute("SELECT COUNT(*) FROM incidents WHERE id = 100")
        assert check_inc.rows[0][0] == 0


class TestSQLGuardIntegration:
    """Pruebas de rechazo de consultas maliciosas o prohibidas vía SQLGuard."""

    @pytest.mark.parametrize(
        "malicious_sql",
        [
            "DROP TABLE incidents;",
            "DELETE FROM suspects WHERE 1=1",
            "UPDATE incidents SET risk_level = 'Bajo'",
            "ALTER TABLE incidents ADD COLUMN hacked TEXT",
            "CREATE TABLE backdoor (id INT)",
            "SELECT * FROM incidents; DROP TABLE suspects;",
            "SELECT * FROM users_private_credentials",
            "SELECT load_extension('malicious.so')",
        ],
    )
    def test_sql_guard_rejects_dangerous_queries(self, memory_executor: SQLExecutor, malicious_sql: str):
        """SQLGuard previene la ejecución de comandos DDL destructivos o inyecciones."""
        with pytest.raises(SQLGuardError):
            memory_executor.execute(malicious_sql)

    def test_sql_guard_enforces_limit(self, seeded_executor: SQLExecutor):
        """SQLGuard agrega automáticamente cláusula LIMIT a SELECTs sin LIMIT."""
        result = seeded_executor.execute("SELECT id, incident_type FROM incidents")
        assert "LIMIT" in result.query.upper()


class TestTableFormatting:
    """Pruebas del formateador de tablas Markdown y ASCII en QueryResult."""

    def test_format_table_markdown(self):
        """Verifica el formato de tabla Markdown con alineación y encabezados."""
        qr = QueryResult(
            operation="SELECT",
            columns=["id", "delito", "riesgo"],
            rows=[
                [1, "Robo con intimidación", "Alto"],
                [2, "Homicidio", "Crítico"],
            ],
            row_count=2,
        )
        md = qr.format_table(style="markdown")
        lines = md.split("\n")
        assert len(lines) == 4
        assert "| id" in lines[0] and "delito" in lines[0] and "riesgo" in lines[0]
        assert lines[1].startswith("|-") and lines[1].endswith("-|")
        assert "Robo con intimidación" in lines[2]
        assert "Homicidio" in lines[3]

    def test_format_table_ascii(self):
        """Verifica el formato de tabla ASCII con bordes de cuadrícula."""
        qr = QueryResult(
            operation="SELECT",
            columns=["id", "alias", "estado"],
            rows=[
                [1, "El Flaco", "En fuga"],
                [2, "El Ruso", "Detenido"],
            ],
            row_count=2,
        )
        ascii_tbl = qr.format_table(style="ascii")
        lines = ascii_tbl.split("\n")
        assert lines[0].startswith("+") and lines[0].endswith("+")
        assert "| id" in lines[1]
        assert "El Flaco" in ascii_tbl
        assert "Detenido" in ascii_tbl

    def test_format_table_with_none_values(self):
        """Formatea valores None como 'NULL'."""
        qr = QueryResult(
            operation="SELECT",
            columns=["id", "descripcion"],
            rows=[[1, None]],
            row_count=1,
        )
        md = qr.format_table(style="markdown")
        assert "NULL" in md

    def test_format_table_empty(self):
        """Formatea resultado vacío de manera limpia."""
        qr = QueryResult(
            operation="SELECT",
            columns=["id", "nombre"],
            rows=[],
            row_count=0,
        )
        md = qr.format_table(style="markdown")
        assert "(0 filas)" in md


class TestSQLExecutorContextManagerAndFiles:
    """Pruebas de persistencia de archivos y context manager."""

    def test_context_manager_lifecycle(self):
        """Verifica que el context manager abre y cierra correctamente la conexión."""
        with SQLExecutor(db_path=":memory:") as executor:
            executor.init_db()
            res = executor.execute("SELECT id FROM incidents")
            assert res.row_count == 0
        
        # Conexión cerrada al salir del bloque
        with pytest.raises(SQLExecutionError):
            _ = executor.conn

    def test_file_database_persistence(self, tmp_path: Path):
        """Verifica que una base de datos basada en archivo persiste datos entre instancias."""
        db_file = tmp_path / "forensic_test.db"

        # Instancia 1: Crear e insertar
        with SQLExecutor(db_path=db_file) as exec1:
            exec1.init_db(seed_path=True)
            exec1.execute(
                SQLQuery(
                    operation="INSERT",
                    table="incidents",
                    sql_parameterized="INSERT INTO incidents (id, incident_type, location) VALUES (99, 'Secuestro', 'Valle Central')",
                )
            )

        # Instancia 2: Leer y verificar persistencia
        with SQLExecutor(db_path=db_file) as exec2:
            res = exec2.execute("SELECT id, incident_type, location FROM incidents WHERE id = 99")
            assert res.row_count == 1
            assert res.rows[0][1] == "Secuestro"


# ============================================================================
# P9: PRUEBAS DE CONEXIÓN DE SOLO LECTURA (READ-ONLY URI MODE)
# ============================================================================

class TestReadOnlyConnection:
    """P9: Verificación del modo de solo lectura (read_only=True)."""

    def test_read_only_select_succeeds(self, tmp_path: Path) -> None:
        """Consultas SELECT sobre base de datos de solo lectura se ejecutan exitosamente."""
        db_file = tmp_path / "ro_test.db"
        with SQLExecutor(db_path=db_file) as setup_exec:
            setup_exec.init_db(seed_path=True)

        with SQLExecutor(db_path=db_file, read_only=True) as ro_exec:
            res = ro_exec.execute("SELECT COUNT(*) AS total FROM incidents")
            assert res.rows[0][0] >= 5

    def test_read_only_insert_fails_operational_error(self, tmp_path: Path) -> None:
        """Intentos de INSERT contra conexión read_only=True lanzan OperationalError de SQLite."""
        db_file = tmp_path / "ro_test_insert.db"
        with SQLExecutor(db_path=db_file) as setup_exec:
            setup_exec.init_db()

        with SQLExecutor(db_path=db_file, read_only=True) as ro_exec:
            # 1. Fallo vía método execute() de SQLExecutor
            with pytest.raises(SQLExecutionError) as exc_info:
                ro_exec.execute(
                    SQLQuery(
                        operation="INSERT",
                        table="incidents",
                        sql_parameterized="INSERT INTO incidents (incident_type, risk_level) VALUES (?, ?)",
                        params=["Homicidio", "Crítico"],
                    )
                )
            assert isinstance(exc_info.value.__cause__, sqlite3.OperationalError)
            assert "readonly database" in str(exc_info.value.__cause__).lower()

            # 2. Fallo directo contra el objeto conn
            with pytest.raises(sqlite3.OperationalError, match="(?i)readonly database"):
                ro_exec.conn.execute("INSERT INTO incidents (incident_type, risk_level) VALUES ('Test', 'Bajo')")

    def test_read_only_non_existent_file_raises_file_not_found(self, tmp_path: Path) -> None:
        """Abrir un archivo inexistente en modo read_only=True debe lanzar FileNotFoundError."""
        missing_db = tmp_path / "missing.db"
        with pytest.raises(FileNotFoundError):
            SQLExecutor(db_path=missing_db, read_only=True)

