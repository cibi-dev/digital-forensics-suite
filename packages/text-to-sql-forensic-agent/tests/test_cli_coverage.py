"""Pruebas adicionales para cobertura completa de la CLI de forensic-sql."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from forensic_agent.cli import main, _sanitize_error_message, _mask_pii_name, _mask_pii_params
from forensic_agent.models import IncidentReport, Suspect, Victim, Evidence, SQLQuery


def test_sanitize_and_mask_helpers():
    assert _sanitize_error_message("") == ""
    assert "[RUTA]" in _sanitize_error_message("Error in /home/user/file.py")
    assert "[TEXTO_DELIMITADO]" in _sanitize_error_message("Prefix <<<INPUT_USUARIO secret INPUT_USUARIO>>> Suffix")
    
    assert _mask_pii_name(None) == "Anónimo"
    assert _mask_pii_name("A") == "A***"
    assert _mask_pii_name("Carlos") == "Ca***"
    
    assert _mask_pii_params({"key1": "val1", "key2": "val2"}) == ["key1", "key2"]
    assert "2 parámetros" in _mask_pii_params(["a", "b"])
    assert _mask_pii_params(123) == 123


def test_cli_ingest_with_evidences_victims_and_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "test_exec.db"
    main(["init-db", "--db", str(db_file)])

    mock_gen = MagicMock()
    mock_gen.extract_incident.return_value = IncidentReport(
        incident_type="Homicidio",
        risk_level="Crítico",
        location="Av. Principal 456",
        suspects=[Suspect(alias_or_name="El Sombra", physical_description="Alto", status="Identificado")],
        victims=[Victim(name_or_identity="Juan Perez", injury_status="Fallecido", statement_summary="N/A")],
        evidences=[Evidence(item="Arma 9mm", location_found="Piso 2", evidence_type="Física")],
        summary="Caso de homicidio investigado",
    )
    monkeypatch.setattr("forensic_agent.cli.SQLGenerator", lambda: mock_gen)

    ret = main(["ingest", "Reporte completo con evidencias", "--db", str(db_file), "--verbose", "--yes"])
    assert ret == 0


def test_cli_query_with_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "test_query.db"
    main(["init-db", "--db", str(db_file), "--seed"])

    mock_gen = MagicMock()
    mock_gen.text_to_query.return_value = SQLQuery(
        operation="SELECT",
        table="incidents",
        sql_parameterized="SELECT id, incident_type, risk_level FROM incidents LIMIT 2",
        params={},
        explanation="Consulta dos incidentes",
    )
    monkeypatch.setattr("forensic_agent.cli.SQLGenerator", lambda: mock_gen)

    ret = main(["query", "¿Cuáles son los 2 primeros incidentes?", "--db", str(db_file), "--verbose", "--yes", "--style", "markdown"])
    assert ret == 0


def test_cli_query_missing_db_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    mock_gen = MagicMock()
    mock_gen.text_to_query.return_value = SQLQuery(
        operation="SELECT",
        table="incidents",
        sql_parameterized="SELECT * FROM incidents",
        params={},
    )
    monkeypatch.setattr("forensic_agent.cli.SQLGenerator", lambda: mock_gen)

    ret = main(["query", "¿Hay casos?", "--db", str(tmp_path / "missing.db"), "--yes"])
    assert ret == 1


def test_cli_generator_exceptions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def mock_fail(*args, **kwargs):
        raise ValueError("Error simulado de LLM")

    mock_gen = MagicMock()
    mock_gen.extract_incident.side_effect = mock_fail
    mock_gen.text_to_query.side_effect = mock_fail
    monkeypatch.setattr("forensic_agent.cli.SQLGenerator", lambda: mock_gen)

    ret1 = main(["ingest", "Reporte...", "--verbose", "--yes"])
    assert ret1 == 1

    ret2 = main(["query", "¿Pregunta?", "--verbose", "--yes"])
    assert ret2 == 1


def test_cli_query_and_ingest_execution_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from forensic_agent.executor import SQLExecutionError
    from forensic_agent.sql_guard import SQLGuardError

    db_file = tmp_path / "test_err.db"
    main(["init-db", "--db", str(db_file)])

    # Mock SQLGenerator
    mock_gen = MagicMock()
    mock_gen.extract_incident.return_value = IncidentReport(
        incident_type="Robo",
        risk_level="Bajo",
        summary="Test error",
    )
    mock_gen.text_to_query.return_value = SQLQuery(
        operation="SELECT",
        table="incidents",
        sql_parameterized="SELECT * FROM incidents",
        params={},
    )
    monkeypatch.setattr("forensic_agent.cli.SQLGenerator", lambda: mock_gen)

    # Mock SQLExecutor in ingest raising SQLExecutionError
    def mock_exec_fail(*args, **kwargs):
        raise SQLExecutionError("Database disk failure")

    monkeypatch.setattr("forensic_agent.executor.SQLExecutor.execute", mock_exec_fail)

    ret_ingest = main(["ingest", "Texto", "--db", str(db_file), "--verbose", "--yes"])
    assert ret_ingest == 1

    ret_query = main(["query", "Pregunta", "--db", str(db_file), "--verbose", "--yes"])
    assert ret_query == 1


def test_cli_read_input_source_error(tmp_path: Path):
    missing_file = tmp_path / "does_not_exist.txt"
    ret = main(["query", "-f", str(missing_file), "--yes"])
    assert ret == 1

