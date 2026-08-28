"""Test suite for forensic Pydantic models, SQLQuery safety, and SQLite schema/seed data."""

from __future__ import annotations

import sqlite3
import pytest
from pydantic import ValidationError

from forensic_agent.database import (
    SCHEMA_PATH,
    SEED_PATH,
    get_schema_sql,
    get_seed_sql,
    init_db,
)
from forensic_agent.models import (
    ALLOWED_TABLES,
    Evidence,
    IncidentReport,
    SQLQuery,
    Suspect,
    Victim,
)


class TestSuspectModel:
    """Tests for the Suspect model validation and serialization."""

    def test_create_valid_suspect_defaults(self) -> None:
        suspect = Suspect(alias_or_name="El Loco")
        assert suspect.alias_or_name == "El Loco"
        assert suspect.status == "Desconocido"
        assert suspect.physical_description is None
        assert suspect.id is None
        assert suspect.incident_id is None

    def test_create_valid_suspect_full(self) -> None:
        suspect = Suspect(
            id=1,
            incident_id=2,
            alias_or_name="Juan Pérez",
            physical_description="1.75m, cicatriz en ceja",
            status="Detenido",
        )
        assert suspect.id == 1
        assert suspect.incident_id == 2
        assert suspect.status == "Detenido"
        assert suspect.physical_description == "1.75m, cicatriz en ceja"

    @pytest.mark.parametrize("status", ["Identificado", "Detenido", "En fuga", "Desconocido"])
    def test_valid_statuses(self, status: str) -> None:
        suspect = Suspect(alias_or_name="Test", status=status)  # type: ignore[arg-type]
        assert suspect.status == status

    def test_invalid_status_raises(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            Suspect(alias_or_name="Test", status="Invalido")  # type: ignore[arg-type]
        assert "status" in str(exc_info.value)

    def test_empty_alias_raises(self) -> None:
        with pytest.raises(ValidationError):
            Suspect(alias_or_name="")


class TestEvidenceModel:
    """Tests for the Evidence model."""

    def test_create_valid_evidence(self) -> None:
        evidence = Evidence(
            id=10,
            incident_id=1,
            item="Arma de fuego calibre 9mm",
            location_found="Guantera del vehículo",
        )
        assert evidence.id == 10
        assert evidence.item == "Arma de fuego calibre 9mm"
        assert evidence.location_found == "Guantera del vehículo"

    def test_evidence_empty_item_raises(self) -> None:
        with pytest.raises(ValidationError):
            Evidence(item="")


class TestVictimModel:
    """Tests for the Victim model."""

    def test_create_valid_victim(self) -> None:
        victim = Victim(
            id=5,
            incident_id=1,
            name_or_alias="Carlos Ruiz",
            injuries="Politraumatismo leve",
            statement_summary="Declara haber sido interceptado por 2 personas armadas.",
        )
        assert victim.id == 5
        assert victim.name_or_alias == "Carlos Ruiz"
        assert victim.injuries == "Politraumatismo leve"
        assert "interceptado" in (victim.statement_summary or "")

    def test_victim_minimal_valid(self) -> None:
        victim = Victim()
        assert victim.id is None
        assert victim.name_or_alias is None
        assert victim.injuries is None


class TestIncidentReportModel:
    """Tests for IncidentReport model composition and helper methods."""

    def test_create_valid_incident_report_full(self) -> None:
        report = IncidentReport(
            id=1,
            incident_type="Robo con intimidación",
            date_approx="2026-03-12 21:30",
            location="Av. Providencia 1420",
            risk_level="Alto",
            summary="Asalto a farmacia de turno.",
            suspects=[
                Suspect(alias_or_name="El Chino", status="Detenido"),
                Suspect(alias_or_name="El Flaco", status="En fuga"),
            ],
            evidences=[
                Evidence(item="Vaina servida 9mm", location_found="Piso principal"),
            ],
            victims=[
                Victim(name_or_alias="Camila V.", injuries="Crisis de pánico"),
            ],
        )

        assert report.incident_type == "Robo con intimidación"
        assert report.risk_level == "Alto"
        assert len(report.suspects) == 2
        assert len(report.evidences) == 1
        assert len(report.victims) == 1

    def test_invalid_risk_level_raises(self) -> None:
        with pytest.raises(ValidationError):
            IncidentReport(
                incident_type="Homicidio",
                risk_level="Extremo",  # type: ignore[arg-type]
            )

    def test_to_flat_dict(self) -> None:
        report = IncidentReport(
            id=10,
            incident_type="Hurto agravado",
            risk_level="Bajo",
            summary="Sustracción de mercadería",
            suspects=[Suspect(alias_or_name="Sujeto A")],
        )
        flat = report.to_flat_dict()
        assert flat["id"] == 10
        assert flat["incident_type"] == "Hurto agravado"
        assert "suspects" not in flat
        assert "evidences" not in flat

    def test_to_insert_queries_with_id(self) -> None:
        report = IncidentReport(
            id=1,
            incident_type="Extorsión",
            date_approx="2026-08-01 11:30",
            location="Barrio Franklin",
            risk_level="Alto",
            summary="Exigencia de dinero bajo amenazas.",
            suspects=[Suspect(alias_or_name="Yeico", status="En fuga")],
            evidences=[Evidence(item="Panfleto extorsivo", location_found="Cortina metálica")],
            victims=[Victim(name_or_alias="Manuel C.", statement_summary="Exigieron $500.000.")],
        )

        queries = report.to_insert_queries()
        assert len(queries) == 4
        assert queries[0].table == "incidents"
        assert queries[0].operation == "INSERT"
        assert ":id" in queries[0].sql_parameterized
        assert queries[1].table == "suspects"
        assert queries[2].table == "evidences"
        assert queries[3].table == "victims"

        for q in queries:
            assert q.validate_safety() is True

    def test_to_insert_queries_without_id(self) -> None:
        report = IncidentReport(
            incident_type="Hurto agravado",
            risk_level="Bajo",
            suspects=[Suspect(alias_or_name="Marcela T.", status="Detenido")],
        )
        queries = report.to_insert_queries()
        assert len(queries) == 2
        assert ":id" not in queries[0].sql_parameterized
        assert queries[0].validate_safety() is True

    def test_serialization_roundtrip(self) -> None:
        report = IncidentReport(
            incident_type="Fraude informático",
            risk_level="Medio",
            suspects=[Suspect(alias_or_name="Hacker X", status="Identificado")],
        )
        json_data = report.model_dump_json()
        restored = IncidentReport.model_validate_json(json_data)
        assert restored.incident_type == report.incident_type
        assert restored.suspects[0].alias_or_name == "Hacker X"


class TestSQLQueryModel:
    """Tests for SQLQuery validation, safety guardrails, parameter handling, and execution."""

    def test_valid_select_query(self) -> None:
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents WHERE risk_level = :risk_level",
            params={"risk_level": "Alto"},
            explanation="Busca todos los incidentes clasificados con nivel de riesgo Alto.",
        )
        assert query.operation == "SELECT"
        assert query.is_read_only() is True
        assert query.is_mutation() is False
        assert query.validate_safety() is True
        assert query.is_safe() is True

    def test_valid_insert_query(self) -> None:
        query = SQLQuery(
            operation="INSERT",
            table="evidences",
            sql_parameterized="INSERT INTO evidences (incident_id, item, location_found) VALUES (?, ?, ?)",
            params=[1, "Cuchillo táctico", "Bajo asiento"],
            explanation="Registra nueva evidencia incautada.",
        )
        assert query.operation == "INSERT"
        assert query.is_read_only() is False
        assert query.is_mutation() is True
        assert query.validate_safety() is True

    def test_invalid_table_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            SQLQuery(
                operation="SELECT",
                table="users_passwords",
                sql_parameterized="SELECT * FROM users_passwords",
                params={},
                explanation="Intento de acceso a tabla no permitida",
            )
        assert "allowed tables" in str(exc_info.value)

    def test_invalid_operation_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            SQLQuery(
                operation="DELETE",  # type: ignore[arg-type]
                table="incidents",
                sql_parameterized="DELETE FROM incidents WHERE id = 1",
                params={},
                explanation="Intento de borrado no permitido",
            )
        assert "operation" in str(exc_info.value)

    def test_sql_mismatch_with_operation_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            SQLQuery(
                operation="SELECT",
                table="incidents",
                sql_parameterized="INSERT INTO incidents (incident_type) VALUES ('test')",
                params={},
                explanation="Mismatch operation SELECT with INSERT query",
            )
        assert "SQL statement must start with SELECT" in str(exc_info.value)

    @pytest.mark.parametrize("forbidden_keyword", ["DROP", "DELETE", "TRUNCATE", "ALTER", "PRAGMA", "ATTACH"])
    def test_safety_catches_prohibited_keywords(self, forbidden_keyword: str) -> None:
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized=f"SELECT * FROM incidents WHERE id = 1 -- {forbidden_keyword} TABLE incidents",  # nosec B608
            params={},
            explanation="Intento de inyección",
        )
        assert query.is_safe() is False
        with pytest.raises(ValueError, match="forbidden SQL keywords"):
            query.validate_safety()

    def test_safety_catches_multistatement_injection(self) -> None:
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents; SELECT * FROM suspects",
            params={},
            explanation="Multi-statement query",
        )
        assert query.is_safe() is False
        with pytest.raises(ValueError, match="multi-statement"):
            query.validate_safety()

    def test_safety_with_custom_allowed_tables(self) -> None:
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents",
            params={},
        )
        assert query.validate_safety(allowed_tables={"incidents"}) is True
        assert query.is_safe(allowed_tables={"suspects"}) is False
        with pytest.raises(ValueError, match="not in permitted tables"):
            query.validate_safety(allowed_tables={"suspects"})

    def test_to_executable_sql_named_params(self) -> None:
        query = SQLQuery(
            operation="SELECT",
            table="suspects",
            sql_parameterized="SELECT * FROM suspects WHERE incident_id = :inc_id AND status = :status AND physical_description IS NOT :desc",
            params={"inc_id": 2, "status": "En fuga", "desc": None},
            explanation="Filtra sospechosos prófugos del caso 2.",
        )
        executable = query.to_executable_sql()
        assert "incident_id = 2" in executable
        assert "status = 'En fuga'" in executable
        assert "NULL" in executable

    def test_to_executable_sql_positional_params(self) -> None:
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents WHERE risk_level = ? AND id > ? AND summary IS NOT ?",
            params=["Alto", 3, None],
            explanation="Filtra incidentes de alto riesgo posteriores al id 3.",
        )
        executable = query.to_executable_sql()
        assert "risk_level = 'Alto'" in executable
        assert "id > 3" in executable
        assert "NULL" in executable

    def test_to_executable_sql_emits_user_warning(self) -> None:
        """P5: to_executable_sql debe emitir UserWarning alertando sobre el riesgo de ejecución."""
        import warnings
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents WHERE id = :id",
            params={"id": 1},
        )
        with pytest.warns(UserWarning, match="to_executable_sql\\(\\) es únicamente para depuración"):
            _ = query.to_executable_sql()

    def test_to_executable_sql_typed_escaping(self) -> None:
        """P5: to_executable_sql debe tipar correctamente None, numéricos, booleanos y cadenas con comillas."""
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents WHERE a = :a AND b = :b AND c = :c AND d = :d AND e = :e AND f = :f",
            params={
                "a": None,
                "b": True,
                "c": False,
                "d": 42,
                "e": 3.1415,
                "f": "O'Reilly & 'Sons'",
            },
        )
        with pytest.warns(UserWarning):
            sql = query.to_executable_sql()
        assert "a = NULL" in sql
        assert "b = 1" in sql
        assert "c = 0" in sql
        assert "d = 42" in sql
        assert "e = 3.1415" in sql
        assert "f = 'O''Reilly & ''Sons'''" in sql

    def test_to_executable_sql_escapes_injection_payload(self) -> None:
        """P5: Inyecciones de comillas simples dentro de parámetros son debidamente duplicadas (escapadas)."""
        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents WHERE summary = :payload",
            params={"payload": "test' OR '1'='1"},
        )
        with pytest.warns(UserWarning):
            sql = query.to_executable_sql()
        assert "summary = 'test'' OR ''1''=''1'" in sql


    def test_get_params_tuple_and_dict(self) -> None:
        q_dict = SQLQuery(
            operation="SELECT",
            table="victims",
            sql_parameterized="SELECT * FROM victims WHERE incident_id = :id",
            params={"id": 1},
            explanation="Obtiene víctimas del incidente 1.",
        )
        assert q_dict.get_params_dict() == {"id": 1}
        assert q_dict.get_params_tuple() == (1,)

        q_list = SQLQuery(
            operation="SELECT",
            table="victims",
            sql_parameterized="SELECT * FROM victims WHERE incident_id = ?",
            params=[1],
            explanation="Obtiene víctimas del incidente 1.",
        )
        assert q_list.get_params_tuple() == (1,)
        assert q_list.get_params_dict() == {"p0": 1}

        q_empty = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents",
            params={},
        )
        assert q_empty.get_params_tuple() == ()
        assert q_empty.get_params_dict() == {}


class TestDatabaseSchemaAndSeed:
    """Tests for SQLite DDL schema creation, constraints, foreign keys, and seed data integrity."""

    def test_schema_and_seed_files_exist(self) -> None:
        assert SCHEMA_PATH.exists()
        assert SEED_PATH.exists()
        schema_sql = get_schema_sql()
        seed_sql = get_seed_sql()
        assert "CREATE TABLE IF NOT EXISTS incidents" in schema_sql
        assert "CREATE TABLE IF NOT EXISTS suspects" in schema_sql
        assert "CREATE TABLE IF NOT EXISTS evidences" in schema_sql
        assert "CREATE TABLE IF NOT EXISTS victims" in schema_sql
        assert "Robo con intimidación" in seed_sql

    def test_init_db_in_memory_creates_all_tables_and_indexes(self) -> None:
        conn = init_db(":memory:", seed=False)
        cursor = conn.cursor()

        # Verify all 4 tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cursor.fetchall()}
        assert ALLOWED_TABLES.issubset(tables)

        # Verify indexes exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_incidents_type" in indexes
        assert "idx_incidents_date" in indexes
        assert "idx_incidents_risk" in indexes
        assert "idx_suspects_incident_id" in indexes
        assert "idx_evidences_incident_id" in indexes
        assert "idx_victims_incident_id" in indexes
        conn.close()

    def test_check_constraint_risk_level(self) -> None:
        conn = init_db(":memory:", seed=False)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO incidents (incident_type, risk_level) VALUES ('Test', 'Invalido')"
            )
        conn.close()

    def test_check_constraint_suspect_status(self) -> None:
        conn = init_db(":memory:", seed=False)
        conn.execute("INSERT INTO incidents (id, incident_type) VALUES (1, 'Test')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO suspects (incident_id, alias_or_name, status) VALUES (1, 'Test', 'Invalido')"
            )
        conn.close()

    def test_foreign_key_cascade_delete(self) -> None:
        conn = init_db(":memory:", seed=False)
        conn.execute("INSERT INTO incidents (id, incident_type) VALUES (100, 'Robo')")
        conn.execute("INSERT INTO suspects (incident_id, alias_or_name) VALUES (100, 'Sospechoso 1')")
        conn.execute("INSERT INTO evidences (incident_id, item) VALUES (100, 'Evidencia 1')")
        conn.execute("INSERT INTO victims (incident_id, name_or_identity) VALUES (100, 'Victima 1')")
        conn.commit()

        # Delete incident
        conn.execute("DELETE FROM incidents WHERE id = 100")
        conn.commit()

        # Child tables must be empty due to CASCADE
        assert conn.execute("SELECT COUNT(*) FROM suspects WHERE incident_id = 100").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM evidences WHERE incident_id = 100").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM victims WHERE incident_id = 100").fetchone()[0] == 0
        conn.close()

    def test_seed_data_loaded_correctly(self) -> None:
        conn = init_db(":memory:", seed=True)
        cursor = conn.cursor()

        # Verify 6 incidents
        cursor.execute("SELECT id, incident_type, risk_level FROM incidents ORDER BY id")
        incidents = cursor.fetchall()
        assert len(incidents) == 6

        expected_types = [
            "Robo con intimidación",
            "Homicidio frustrado",
            "Fraude informático",
            "Tráfico de estupefacientes",
            "Hurto agravado",
            "Extorsión",
        ]
        actual_types = [row["incident_type"] for row in incidents]
        assert actual_types == expected_types

        # Verify counts in child tables
        cursor.execute("SELECT COUNT(*) FROM suspects")
        suspects_count = cursor.fetchone()[0]
        assert suspects_count >= 6

        cursor.execute("SELECT COUNT(*) FROM evidences")
        evidences_count = cursor.fetchone()[0]
        assert evidences_count >= 6

        cursor.execute("SELECT COUNT(*) FROM victims")
        victims_count = cursor.fetchone()[0]
        assert victims_count >= 6
        conn.close()

    def test_sqlquery_against_seed_database_via_cursor(self) -> None:
        conn = init_db(":memory:", seed=True)
        cursor = conn.cursor()

        query = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT id, incident_type, location, risk_level FROM incidents WHERE risk_level = :risk ORDER BY id",
            params={"risk": "Crítico"},
            explanation="Obtiene incidentes con nivel de riesgo Crítico",
        )
        assert query.validate_safety() is True

        cursor.execute(query.sql_parameterized, query.params)
        rows = cursor.fetchall()
        assert len(rows) == 2
        incident_types = [r["incident_type"] for r in rows]
        assert "Homicidio frustrado" in incident_types
        assert "Tráfico de estupefacientes" in incident_types

        # Test insert query execution
        ins_query = SQLQuery(
            operation="INSERT",
            table="incidents",
            sql_parameterized="INSERT INTO incidents (incident_type, risk_level, summary) VALUES (:type, :risk, :sum)",
            params={"type": "Secuestro", "risk": "Crítico", "sum": "Caso nuevo"},
            explanation="Inserta nuevo caso crítico",
        )
        assert ins_query.validate_safety() is True
        cursor.execute(ins_query.sql_parameterized, ins_query.params)
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE incident_type = 'Secuestro'")
        assert cursor.fetchone()[0] == 1

        conn.close()

    def test_cross_table_join_query(self) -> None:
        conn = init_db(":memory:", seed=True)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT i.incident_type, s.alias_or_name, e.item, v.name_or_identity
            FROM incidents i
            LEFT JOIN suspects s ON i.id = s.incident_id
            LEFT JOIN evidences e ON i.id = e.incident_id
            LEFT JOIN victims v ON i.id = v.incident_id
            WHERE i.id = 1
        """)
        rows = cursor.fetchall()
        assert len(rows) > 0
        conn.close()
