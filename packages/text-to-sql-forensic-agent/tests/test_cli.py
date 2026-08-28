"""Pruebas unitarias para la interfaz de línea de comandos (CLI) de forensic-sql."""

from pathlib import Path
import pytest

from forensic_agent.cli import build_parser, main
from forensic_agent.executor import SQLExecutor


class TestCLIParsing:
    """Pruebas de análisis de argumentos de la CLI."""

    def test_parser_init_db_defaults(self):
        """Verifica los valores por defecto del comando init-db."""
        parser = build_parser()
        args = parser.parse_args(["init-db"])
        assert args.command == "init-db"
        assert args.db == "forensic_cases.db"
        assert args.seed is False

    def test_parser_init_db_with_seed(self):
        """Verifica flags de seed y db personalizada."""
        parser = build_parser()
        args = parser.parse_args(["init-db", "--db", "test.db", "--seed"])
        assert args.command == "init-db"
        assert args.db == "test.db"
        assert args.seed is True

    def test_parser_ingest_flags(self):
        """Verifica argumentos de ingest."""
        parser = build_parser()
        args = parser.parse_args(["ingest", "Reporte de robo...", "--dry-run", "--verbose"])
        assert args.command == "ingest"
        assert args.narrative == "Reporte de robo..."
        assert args.dry_run is True
        assert args.verbose is True

    def test_parser_query_flags(self):
        """Verifica argumentos de query."""
        parser = build_parser()
        args = parser.parse_args(["query", "¿Cuántos sospechosos?", "--db", "cases.db", "--style", "ascii"])
        assert args.command == "query"
        assert args.question == "¿Cuántos sospechosos?"
        assert args.db == "cases.db"
        assert args.style == "ascii"


class TestCLIExecution:
    """Pruebas de ejecución de subcomandos CLI."""

    def test_main_without_args_returns_1(self, capsys: pytest.CaptureFixture[str]):
        """Sin argumentos muestra ayuda y retorna código 1."""
        ret = main([])
        assert ret == 1
        captured = capsys.readouterr()
        assert "usage:" in captured.out or "usage:" in captured.err

    def test_main_init_db_with_seed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """init-db crea base de datos SQLite y carga seed."""
        db_path = tmp_path / "cli_test.db"
        ret = main(["init-db", "--db", str(db_path), "--seed"])
        assert ret == 0

        captured = capsys.readouterr()
        assert "Esquema SQLite aplicado correctamente" in captured.out
        is_exists = db_path.exists()
        assert is_exists is True

        # Verificar tablas y registros
        with SQLExecutor(db_path=db_path) as executor:
            res = executor.execute("SELECT COUNT(*) FROM incidents")
            assert res.rows[0][0] >= 5

    def test_main_ingest_empty_narrative_fails(self, capsys: pytest.CaptureFixture[str]):
        """ingest sin narrativa ni archivo retorna código de error 1."""
        ret = main(["ingest", ""])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Debe proporcionar una narrativa" in captured.err

    def test_main_query_empty_question_fails(self, capsys: pytest.CaptureFixture[str]):
        """query con pregunta vacía retorna código de error 1."""
        ret = main(["query", "   "])
        assert ret == 1
        captured = capsys.readouterr()
        assert "La pregunta no puede estar vacía" in captured.err

    # =========================================================================
    # P2: Modo Offline y Advertencias de Gemini
    # =========================================================================

    def test_cli_offline_flag_ingest_fails(self, capsys: pytest.CaptureFixture[str]):
        """--no-llm en ingest debe fallar con código 1 y mensaje explicativo."""
        ret = main(["ingest", "Reporte de robo", "--no-llm"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "modo offline" in captured.err.lower()

    def test_cli_offline_flag_query_fails(self, capsys: pytest.CaptureFixture[str]):
        """--no-llm en query debe fallar con código 1 y mensaje explicativo."""
        ret = main(["query", "¿Cuántos incidentes hay?", "--no-llm"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "modo offline" in captured.err.lower()

    def test_cli_offline_env_var_fails(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
        """FORENSIC_OFFLINE=1 debe activar el bloqueo offline."""
        monkeypatch.setenv("FORENSIC_OFFLINE", "1")
        ret = main(["ingest", "Reporte de robo"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "modo offline" in captured.err.lower()

    def test_cli_gemini_warning_emitted_and_suppressed(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
        """Verifica emisión de advertencia a Gemini y supresión con --yes y variable de entorno."""
        from unittest.mock import MagicMock
        from forensic_agent.models import IncidentReport
        import forensic_agent.cli

        mock_gen = MagicMock()
        mock_gen.extract_incident.return_value = IncidentReport(
            incident_type="Robo",
            risk_level="Bajo",
            summary="Test",
        )
        monkeypatch.setattr(forensic_agent.cli, "SQLGenerator", lambda: mock_gen)

        # 1. Por defecto emite advertencia
        main(["ingest", "Reporte", "--dry-run"])
        cap1 = capsys.readouterr()
        assert "El texto se enviará a la API de Gemini" in cap1.err

        # 2. Con --yes se suprime
        main(["ingest", "Reporte", "--dry-run", "--yes"])
        cap2 = capsys.readouterr()
        assert "El texto se enviará a la API de Gemini" not in cap2.err

        # 3. Con FORENSIC_NO_WARN=1 se suprime
        monkeypatch.setenv("FORENSIC_NO_WARN", "1")
        main(["ingest", "Reporte", "--dry-run"])
        cap3 = capsys.readouterr()
        assert "El texto se enviará a la API de Gemini" not in cap3.err

    # =========================================================================
    # P6: Exclusión mutua, límites de archivo y escritura protegida
    # =========================================================================

    def test_cli_mutual_exclusion_narrative_and_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """Pasar narrativa como argumento posicional y -f a la vez debe retornar código 2."""
        sample_file = tmp_path / "report.txt"
        sample_file.write_text("Reporte archivo", encoding="utf-8")

        ret = main(["ingest", "Reporte posicional", "-f", str(sample_file)])
        assert ret == 2
        captured = capsys.readouterr()
        assert "simultáneamente" in captured.err

    def test_cli_mutual_exclusion_question_and_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """Pasar pregunta posicional y -f a la vez en query debe retornar código 2."""
        q_file = tmp_path / "question.txt"
        q_file.write_text("¿Pregunta archivo?", encoding="utf-8")

        ret = main(["query", "¿Pregunta posicional?", "-f", str(q_file)])
        assert ret == 2
        captured = capsys.readouterr()
        assert "simultáneamente" in captured.err

    def test_cli_file_size_limit_exceeded(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """Archivos superiores a 1 MB deben ser rechazados."""
        large_file = tmp_path / "large_report.txt"
        large_file.write_bytes(b"A" * (1024 * 1024 + 50))

        ret = main(["ingest", "-f", str(large_file), "--yes"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "1 MB" in captured.err

    def test_cli_invalid_utf8_file_rejected(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """Archivos con codificación no válida o binarios deben retornar error de decodificación."""
        corrupt_file = tmp_path / "corrupt.txt"
        corrupt_file.write_bytes(b"\x80\x81\xFF\xFE\x00")

        ret = main(["ingest", "-f", str(corrupt_file), "--yes"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "decodificar" in captured.err or "UTF-8" in captured.err

    def test_cli_ingest_missing_db_without_create_fails(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch):
        """Ingest sobre base de datos inexistente sin --create debe sugerir init-db o --create."""
        from unittest.mock import MagicMock
        from forensic_agent.models import IncidentReport
        import forensic_agent.cli

        mock_gen = MagicMock()
        mock_gen.extract_incident.return_value = IncidentReport(
            incident_type="Robo",
            risk_level="Bajo",
            summary="Test",
        )
        monkeypatch.setattr(forensic_agent.cli, "SQLGenerator", lambda: mock_gen)

        missing_db = tmp_path / "non_existent_cases.db"
        ret = main(["ingest", "Reporte de robo...", "--db", str(missing_db), "--yes"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "init-db" in captured.err or "--create" in captured.err

    def test_cli_ingest_missing_db_with_create_succeeds(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Ingest con flag --create inicializa automáticamente la base de datos."""
        from unittest.mock import MagicMock
        from forensic_agent.models import IncidentReport
        import forensic_agent.cli

        mock_gen = MagicMock()
        mock_gen.extract_incident.return_value = IncidentReport(
            incident_type="Robo a comercio",
            risk_level="Medio",
            summary="Caso creado con --create",
        )
        monkeypatch.setattr(forensic_agent.cli, "SQLGenerator", lambda: mock_gen)

        new_db = tmp_path / "auto_created.db"
        ret = main(["ingest", "Reporte de robo...", "--db", str(new_db), "--create", "--yes"])
        assert ret == 0
        assert new_db.exists()

    # =========================================================================
    # P7: Anonimización de PII y Lectura por Stdin
    # =========================================================================

    def test_cli_pii_redacted_in_verbose_by_default(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch):
        """En modo verbose/dry-run, los nombres y parámetros se anonimizan por defecto."""
        from unittest.mock import MagicMock
        from forensic_agent.models import IncidentReport, Suspect, Victim
        import forensic_agent.cli

        mock_gen = MagicMock()
        mock_gen.extract_incident.return_value = IncidentReport(
            incident_type="Secuestro",
            risk_level="Crítico",
            location="Calle Secreta 123",
            suspects=[Suspect(alias_or_name="Carlos Mendez", status="En fuga")],
            victims=[Victim(name_or_identity="Ana Gomez", injury_status="Ileso")],
            summary="Secuestro extorsivo",
        )
        monkeypatch.setattr(forensic_agent.cli, "SQLGenerator", lambda: mock_gen)

        ret = main(["ingest", "Reporte confidencial...", "--dry-run", "--yes"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Ca***" in captured.out
        assert "Carlos Mendez" not in captured.out
        assert "An***" in captured.out
        assert "Ana Gomez" not in captured.out
        assert "[REDACTADO]" in captured.out

    def test_cli_show_pii_reveals_sensitive_data(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch):
        """Con --show-pii se muestran los nombres y ubicaciones completas."""
        from unittest.mock import MagicMock
        from forensic_agent.models import IncidentReport, Suspect, Victim
        import forensic_agent.cli

        mock_gen = MagicMock()
        mock_gen.extract_incident.return_value = IncidentReport(
            incident_type="Secuestro",
            risk_level="Crítico",
            location="Calle Secreta 123",
            suspects=[Suspect(alias_or_name="Carlos Mendez", status="En fuga")],
            victims=[Victim(name_or_identity="Ana Gomez", injury_status="Ileso")],
            summary="Secuestro extorsivo",
        )
        monkeypatch.setattr(forensic_agent.cli, "SQLGenerator", lambda: mock_gen)

        ret = main(["ingest", "Reporte confidencial...", "--dry-run", "--show-pii", "--yes"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Carlos Mendez" in captured.out
        assert "Ana Gomez" in captured.out
        assert "Calle Secreta 123" in captured.out

    def test_cli_stdin_reading_for_query(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch):
        """query con -f - debe leer la pregunta desde stdin."""
        from unittest.mock import MagicMock
        from forensic_agent.models import SQLQuery
        import forensic_agent.cli
        import io

        mock_gen = MagicMock()
        mock_gen.text_to_query.return_value = SQLQuery(
            operation="SELECT",
            table="incidents",
            sql_parameterized="SELECT * FROM incidents LIMIT 10",
            params={},
        )
        monkeypatch.setattr(forensic_agent.cli, "SQLGenerator", lambda: mock_gen)
        monkeypatch.setattr("sys.stdin", io.StringIO("¿Pregunta desde stdin?"))

        ret = main(["query", "-f", "-", "--dry-run", "--yes"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "DRY-RUN" in captured.out

