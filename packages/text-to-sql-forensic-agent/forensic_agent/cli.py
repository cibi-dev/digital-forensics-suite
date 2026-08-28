"""Interfaz de Línea de Comandos (CLI) para el Agente Forense Text-to-SQL."""

import argparse
import os
from pathlib import Path
import re
import sys
from typing import Any, Sequence

from forensic_agent.executor import SQLExecutionError, SQLExecutor
from forensic_agent.models import SQLQuery
from forensic_agent.sql_generator import SQLGenerator
from forensic_agent.sql_guard import SQLGuardError

MAX_FILE_BYTES: int = 1024 * 1024  # 1 MB


def _sanitize_error_message(msg: str) -> str:
    """Elimina rutas absolutas del sistema de archivos y bloques de prompt de los mensajes de error."""
    if not msg:
        return ""
    # Enmascarar rutas absolutas estilo Unix/Windows
    sanitized = re.sub(r"/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+", "[RUTA]", str(msg))
    # Enmascarar bloques de delimitadores de prompt si existieran
    sanitized = re.sub(r"<<<INPUT_USUARIO[\s\S]*?INPUT_USUARIO>>>", "[TEXTO_DELIMITADO]", sanitized)
    return sanitized


def _mask_pii_name(name: str | None) -> str:
    """Enmascara nombres o alias para proteger PII en salidas de consola."""
    if not name:
        return "Anónimo"
    if len(name) <= 2:
        return name + "***"
    return name[:2] + "***"


def _mask_pii_params(params: Any) -> Any:
    """Anonimiza parámetros SQL mostrando únicamente las claves o cantidades."""
    if isinstance(params, dict):
        return list(params.keys())
    elif isinstance(params, (list, tuple)):
        return f"[{len(params)} parámetros]"
    return params


def _check_offline(args: argparse.Namespace) -> bool:
    """Verifica si el modo offline está activo vía argumento o variable de entorno."""
    return getattr(args, "no_llm", False) or os.environ.get("FORENSIC_OFFLINE") == "1"


def _print_gemini_warning(args: argparse.Namespace) -> None:
    """Emite una advertencia sobre envío de datos a LLM externo a menos que se haya suprimido."""
    is_suppressed = getattr(args, "yes", False) or os.environ.get("FORENSIC_NO_WARN") == "1"
    if not is_suppressed:
        print(
            "⚠️  El texto se enviará a la API de Gemini. No uses datos reales de casos sin autorización.",
            file=sys.stderr,
        )


def _read_input_source(file_arg: str | None) -> tuple[str | None, str | None]:
    """
    Lee contenido desde un archivo o stdin con límite estricto de 1 MB.
    Retorna tupla (contenido, mensaje_error).
    """
    if not file_arg:
        return None, None

    if file_arg == "-":
        try:
            content = sys.stdin.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                return None, "La entrada desde stdin excede el tamaño máximo permitido de 1 MB."
            return content, None
        except Exception as e:
            return None, f"Error al leer desde stdin: {type(e).__name__}"

    file_path = Path(file_arg)
    if not file_path.exists():
        return None, f"Archivo no encontrado: {file_path.name}"

    try:
        with file_path.open("r", encoding="utf-8") as f:
            content = f.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                return None, "El archivo excede el tamaño máximo permitido de 1 MB."
            return content, None
    except UnicodeDecodeError:
        return None, "Error al decodificar el archivo: formato o codificación inválida (se requiere UTF-8)."
    except OSError as e:
        return None, f"Error al leer el archivo: {type(e).__name__}"


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de la CLI con subcomandos."""
    parser = argparse.ArgumentParser(
        prog="forensic-sql",
        description="Agente Forense Determinista Text-to-SQL para Análisis de Narrativas Policiales.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        title="Subcomandos disponibles",
        description="Ejecute 'forensic-sql <comando> --help' para más detalles.",
    )

    # 1. Subcomando: init-db
    init_parser = subparsers.add_parser(
        "init-db",
        help="Inicializa la base de datos SQLite con el esquema forense y datos opcionales.",
    )
    init_parser.add_argument(
        "--db",
        type=str,
        default="forensic_cases.db",
        help="Ruta al archivo de base de datos SQLite (default: forensic_cases.db).",
    )
    init_parser.add_argument(
        "--seed",
        action="store_true",
        help="Aplica el conjunto de datos de prueba semilla tras crear el esquema.",
    )
    init_parser.add_argument(
        "--schema-file",
        type=str,
        default=None,
        help="Ruta a un archivo DDL personalizado de esquema SQL.",
    )
    init_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Muestra información detallada de la ejecución.",
    )

    # 2. Subcomando: ingest
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Extrae entidades de una narrativa policial e inserta registros en la base de datos.",
    )
    ingest_parser.add_argument(
        "narrative",
        type=str,
        nargs="?",
        default=None,
        help="Texto de la narrativa o reporte policial entre comillas.",
    )
    ingest_parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=None,
        help="Ruta a un archivo de texto con la narrativa policial, o '-' para leer desde stdin.",
    )
    ingest_parser.add_argument(
        "--db",
        type=str,
        default="forensic_cases.db",
        help="Ruta a la base de datos SQLite destino (default: forensic_cases.db).",
    )
    ingest_parser.add_argument(
        "--create",
        action="store_true",
        help="Crea e inicializa la base de datos automáticamente si no existe.",
    )
    ingest_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra las entidades extraídas y el SQL generado sin ejecutarlo en la DB.",
    )
    ingest_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Muestra información detallada de la extracción y parámetros SQL.",
    )
    ingest_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Modo offline: deshabilita el uso de LLM externo.",
    )
    ingest_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Suprime las advertencias de envío de datos a la API de LLM.",
    )
    ingest_parser.add_argument(
        "--show-pii",
        action="store_true",
        help="Muestra datos de identificación personal sin anonimizar en la salida verbose/dry-run.",
    )

    # 3. Subcomando: query
    query_parser = subparsers.add_parser(
        "query",
        help="Convierte una pregunta en lenguaje natural a SELECT SQL y muestra los resultados.",
    )
    query_parser.add_argument(
        "question",
        type=str,
        nargs="?",
        default=None,
        help="Pregunta forense en lenguaje natural (ej. '¿Cuántos sospechosos en fuga hay?')",
    )
    query_parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=None,
        help="Ruta a un archivo con la pregunta forense, o '-' para leer desde stdin.",
    )
    query_parser.add_argument(
        "--db",
        type=str,
        default="forensic_cases.db",
        help="Ruta a la base de datos SQLite a consultar (default: forensic_cases.db).",
    )
    query_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra el SQL generado y validado sin ejecutarlo contra la base de datos.",
    )
    query_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Muestra el SQL generado, parámetros, plan de ejecución y métricas.",
    )
    query_parser.add_argument(
        "--style",
        choices=["markdown", "ascii"],
        default="markdown",
        help="Estilo visual de la tabla de resultados (default: markdown).",
    )
    query_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Modo offline: deshabilita el uso de LLM externo.",
    )
    query_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Suprime las advertencias de envío de datos a la API de LLM.",
    )
    query_parser.add_argument(
        "--show-pii",
        action="store_true",
        help="Muestra parámetros completos sin anonimizar en la salida verbose/dry-run.",
    )

    return parser


def handle_init_db(args: argparse.Namespace) -> int:
    """Maneja el subcomando init-db."""
    db_path = args.db
    print(f"🔧 Inicializando base de datos en: {Path(db_path).name}")
    try:
        executor = SQLExecutor(db_path=db_path)
        executor.init_db(schema_path=args.schema_file, seed_path=args.seed)
        executor.close()
        print("✅ Esquema SQLite aplicado correctamente.")
        if args.seed:
            print("🌱 Datos iniciales (seed) cargados exitosamente.")
        return 0
    except (SQLExecutionError, FileNotFoundError) as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error al inicializar base de datos ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1


def handle_ingest(args: argparse.Namespace) -> int:
    """Maneja el subcomando ingest."""
    # Validación de argumentos mutuamente excluyentes
    if args.narrative and args.file:
        print("❌ No se puede especificar la narrativa como argumento y archivo (-f) simultáneamente.", file=sys.stderr)
        return 2

    narrative_text = args.narrative
    if args.file:
        content, err = _read_input_source(args.file)
        if err:
            print(f"❌ {err}", file=sys.stderr)
            return 1
        narrative_text = content

    if not narrative_text or not narrative_text.strip():
        print("❌ Debe proporcionar una narrativa vía argumento o archivo con -f.", file=sys.stderr)
        return 1

    # Verificación de modo offline
    if _check_offline(args):
        print(
            "❌ Ingesta no disponible en modo offline (--no-llm o FORENSIC_OFFLINE=1): "
            "la extracción de entidades requiere LLM externo.",
            file=sys.stderr,
        )
        return 1

    # Advertencia de privacidad
    _print_gemini_warning(args)

    print("🔍 Analizando narrativa policial y extrayendo entidades forenses...")
    try:
        generator = SQLGenerator()
        report = generator.extract_incident(narrative_text.strip())
    except Exception as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error al procesar narrativa con LLM ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1

    show_pii = getattr(args, "show_pii", False) or os.environ.get("FORENSIC_SHOW_PII") == "1"

    if args.verbose or args.dry_run:
        print("\n📋 REPORTE FORENSE EXTRAÍDO:")
        print(f"  • Delito: {report.incident_type}")
        print(f"  • Nivel de Riesgo: {report.risk_level}")
        print(f"  • Ubicación: {report.location if show_pii else '[REDACTADO]'}")
        print(f"  • Fecha/Hora: {report.date_approx or 'No especificada'}")
        print(f"  • Sospechosos identificados: {len(report.suspects)}")
        for s in report.suspects:
            s_name = s.alias_or_name if show_pii else _mask_pii_name(s.alias_or_name)
            s_desc = s.physical_description or "Sin descripción"
            print(f"    - {s_name} [{s.status}]: {s_desc}")
        print(f"  • Evidencias recolectadas: {len(report.evidences)}")
        for ev in report.evidences:
            print(f"    - {ev.item} (Lugar: {ev.location_found or 'N/A'})")
        print(f"  • Víctimas: {len(report.victims)}")
        for v in report.victims:
            v_name_raw = v.name_or_alias or v.name_or_identity or "Anónima"
            v_name = v_name_raw if show_pii else _mask_pii_name(v_name_raw)
            print(f"    - {v_name} ({v.injury_status or 'Sin datos'})")
        print(f"  • Síntesis: {report.summary}\n")

    if args.dry_run:
        queries = generator.incident_to_insert_queries(report, incident_id=1)
        print("🔍 [DRY-RUN] Sentencias SQL preparadas (no ejecutadas):")
        for q in queries:
            params_display = q.params if show_pii else _mask_pii_params(q.params)
            print(f"  SQL: {q.sql_parameterized}")
            print(f"  PARÁMETROS: {params_display}\n")
        return 0

    # Verificación o creación de base de datos
    db_path = args.db
    if not Path(db_path).exists():
        if getattr(args, "create", False):
            print(f"⚠️  Base de datos no encontrada en '{Path(db_path).name}'. Creando e inicializando esquema...")
            try:
                temp_exec = SQLExecutor(db_path=db_path)
                temp_exec.init_db()
                temp_exec.close()
            except Exception as e:
                if getattr(args, "verbose", False):
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                sanitized_msg = _sanitize_error_message(str(e))
                print(f"❌ Error creando base de datos ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
                return 1
        else:
            print(
                f"❌ Base de datos no encontrada en '{Path(db_path).name}'. "
                f"Ejecute 'init-db' primero o use el flag --create.",
                file=sys.stderr,
            )
            return 1

    try:
        executor = SQLExecutor(db_path=db_path)
        with executor:
            # 1. Insertar incidente y obtener ID
            inc_query = SQLQuery(
                operation="INSERT",
                table="incidents",
                sql_parameterized=(
                    "INSERT INTO incidents (incident_type, date_approx, location, risk_level, summary) "
                    "VALUES (?, ?, ?, ?, ?)"
                ),
                params=[
                    report.incident_type,
                    report.date_approx,
                    report.location,
                    report.risk_level,
                    report.summary,
                ],
            )
            res_inc = executor.execute(inc_query)
            incident_id = res_inc.last_row_id

            # 2. Insertar entidades vinculadas
            child_queries = []
            for s in report.suspects:
                child_queries.append(
                    SQLQuery(
                        operation="INSERT",
                        table="suspects",
                        sql_parameterized=(
                            "INSERT INTO suspects (incident_id, alias_or_name, physical_description, status) "
                            "VALUES (?, ?, ?, ?)"
                        ),
                        params=[incident_id, s.alias_or_name, s.physical_description, s.status],
                    )
                )
            for ev in report.evidences:
                child_queries.append(
                    SQLQuery(
                        operation="INSERT",
                        table="evidences",
                        sql_parameterized=(
                            "INSERT INTO evidences (incident_id, item, location_found, evidence_type) "
                            "VALUES (?, ?, ?, ?)"
                        ),
                        params=[incident_id, ev.item, ev.location_found, ev.evidence_type],
                    )
                )
            for v in report.victims:
                child_queries.append(
                    SQLQuery(
                        operation="INSERT",
                        table="victims",
                        sql_parameterized=(
                            "INSERT INTO victims (incident_id, name_or_identity, injury_status, statement_summary) "
                            "VALUES (?, ?, ?, ?)"
                        ),
                        params=[
                            incident_id,
                            v.name_or_alias or v.name_or_identity,
                            v.injury_status or v.injuries,
                            v.statement_summary,
                        ],
                    )
                )

            if child_queries:
                executor.execute_many(child_queries)

        print(f"✅ Ingesta completada con éxito. Incidente ID registrado: {incident_id}")
        print(
            f"   📊 Registros guardados: {len(report.suspects)} sospechosos, "
            f"{len(report.evidences)} evidencias, {len(report.victims)} víctimas."
        )
        return 0

    except (SQLGuardError, SQLExecutionError) as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error al ejecutar inserción en base de datos ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1
    except Exception as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error inesperado ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1


def handle_query(args: argparse.Namespace) -> int:
    """Maneja el subcomando query."""
    # Validación de argumentos mutuamente excluyentes
    if args.question and args.file:
        print("❌ No se puede especificar la pregunta como argumento y archivo (-f) simultáneamente.", file=sys.stderr)
        return 2

    question = args.question
    if args.file:
        content, err = _read_input_source(args.file)
        if err:
            print(f"❌ {err}", file=sys.stderr)
            return 1
        question = content

    question_clean = (question or "").strip()
    if not question_clean:
        print("❌ La pregunta no puede estar vacía.", file=sys.stderr)
        return 1

    # Verificación de modo offline
    if _check_offline(args):
        print(
            "❌ Consulta no disponible en modo offline (--no-llm o FORENSIC_OFFLINE=1): "
            "la traducción text-to-sql requiere LLM externo.",
            file=sys.stderr,
        )
        return 1

    # Advertencia de privacidad
    _print_gemini_warning(args)

    print("🔎 Traduciendo consulta a SQL...")
    try:
        generator = SQLGenerator()
        sql_query = generator.text_to_query(question_clean)
    except Exception as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error en la generación de SQL ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1

    show_pii = getattr(args, "show_pii", False) or os.environ.get("FORENSIC_SHOW_PII") == "1"

    if args.verbose or args.dry_run:
        print("\n📝 CONSULTA SQL GENERADA:")
        print(f"  SQL: {sql_query.sql_parameterized}")
        params_display = sql_query.params if show_pii else _mask_pii_params(sql_query.params)
        print(f"  Parámetros: {params_display}")
        if sql_query.explanation:
            print(f"  Explicación: {sql_query.explanation}")
        print()

    if args.dry_run:
        print("🔍 [DRY-RUN] Consulta validada y completada (no ejecutada contra DB).")
        return 0

    db_path = args.db
    if not Path(db_path).exists():
        print(f"❌ Base de datos no encontrada en '{Path(db_path).name}'. Ejecute 'init-db' primero.", file=sys.stderr)
        return 1

    try:
        # Modo solo lectura estricto mediante SQLite URI mode=ro
        executor = SQLExecutor(db_path=db_path, read_only=True)
        with executor:
            result = executor.execute(sql_query)

        print("\n📊 RESULTADO DE LA CONSULTA:")
        print(result.format_table(style=args.style))
        print(f"\n⏱️  {result.row_count} fila(s) obtenida(s) en {result.execution_time_ms:.2f} ms.\n")
        return 0
    except (SQLGuardError, SQLExecutionError) as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error durante la ejecución de la consulta ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1
    except Exception as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sanitized_msg = _sanitize_error_message(str(e))
        print(f"❌ Error inesperado ({type(e).__name__}): {sanitized_msg}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada principal para la CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "init-db":
        return handle_init_db(args)
    elif args.command == "ingest":
        return handle_ingest(args)
    elif args.command == "query":
        return handle_query(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

