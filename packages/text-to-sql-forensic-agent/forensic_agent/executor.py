"""Ejecutor de consultas SQLite transaccional y seguro con validación previa de SQLGuard."""

from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Literal, Sequence

from forensic_agent.models import QueryResult, SQLQuery
from forensic_agent.sql_guard import SQLGuard, SQLGuardError


class SQLExecutionError(Exception):
    """Excepción lanzada durante fallos en la ejecución de consultas SQL."""
    pass


class SQLQueryTimeoutError(SQLExecutionError):
    """Excepción lanzada cuando una consulta excede el tiempo máximo permitido."""
    pass


class SQLExecutor:
    """Administrador de conexiones y ejecutor transaccional de SQLite.

    Thread-safe (serialización interna mediante lock) y con protección anti-DoS
    mediante timeout de ejecución por consulta (progress handler).
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        guard: SQLGuard | None = None,
        autocommit: bool = False,
        query_timeout_ms: int = 5000,
        read_only: bool = False,
    ):
        """Inicializa el ejecutor con una conexión SQLite en memoria o persistente.

        Args:
            db_path: Ruta al archivo SQLite o ':memory:'.
            guard: Instancia personalizada de SQLGuard (opcional).
            autocommit: Modo de autocommit en sqlite3 (por defecto False para manejo manual/transaccional).
            query_timeout_ms: Tiempo máximo de ejecución por consulta en ms (0 desactiva el límite).
                Protege contra DoS mediante productos cartesianos costosos generados por LLM.
            read_only: Si True, abre la conexión en modo de solo lectura usando URI sqlite file:...mode=ro.
        """
        self.db_path = str(db_path)
        self.guard = guard or SQLGuard()
        self._is_closed = False
        self.query_timeout_ms = query_timeout_ms
        self.read_only = read_only
        self._lock = threading.Lock()
        self._query_start = 0.0

        if self.read_only:
            if self.db_path == ":memory:":
                self._conn = sqlite3.connect("file::memory:?mode=ro&cache=shared", uri=True, check_same_thread=False)
            else:
                db_file = Path(self.db_path).resolve()
                if not db_file.exists():
                    raise FileNotFoundError(f"Base de datos no encontrada para modo de solo lectura: {db_file}")
                self._conn = sqlite3.connect(f"file:{db_file.as_posix()}?mode=ro", uri=True, check_same_thread=False)
        else:
            if self.db_path != ":memory:":
                db_file = Path(self.db_path)
                db_file.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)

        self._conn.row_factory = sqlite3.Row
        # Activar claves foráneas en SQLite
        self._conn.execute("PRAGMA foreign_keys = ON;")

        if self.query_timeout_ms > 0:
            self._conn.set_progress_handler(self._check_timeout, 1000)

    def _check_timeout(self) -> int:
        """Progress handler: aborta la consulta si supera el tiempo máximo."""
        elapsed_ms = (time.perf_counter() - self._query_start) * 1000.0
        if elapsed_ms > self.query_timeout_ms:
            raise SQLQueryTimeoutError(
                f"La consulta excedió el tiempo máximo de {self.query_timeout_ms} ms"
            )
        return 0

    @property
    def conn(self) -> sqlite3.Connection:
        """Devuelve la conexión activa a la base de datos."""
        if self._is_closed:
            raise SQLExecutionError("La conexión a la base de datos está cerrada.")
        return self._conn

    def init_db(
        self,
        schema_path: str | Path | None = None,
        seed_path: str | Path | bool | None = None,
    ) -> None:
        """Inicializa las tablas y opcionalmente inserta datos semilla.

        Args:
            schema_path: Ruta a archivo SQL con DDL. Si es None, usa el esquema por defecto.
            seed_path: Ruta a archivo SQL con datos iniciales, o True para usar seed por defecto.

        Raises:
            FileNotFoundError: Si algún archivo SQL especificado no existe.
            SQLExecutionError: Si ocurre un error ejecutando el DDL o seed.
        """
        base_dir = Path(__file__).resolve().parent

        # 1. Cargar y ejecutar DDL
        if schema_path is None:
            resolved_schema = base_dir / "schema.sql"
        else:
            resolved_schema = Path(schema_path)

        if not resolved_schema.exists():
            raise FileNotFoundError(f"Archivo de esquema no encontrado: {resolved_schema}")

        schema_sql = resolved_schema.read_text(encoding="utf-8")
        try:
            with self.conn:
                self.conn.executescript(schema_sql)
        except sqlite3.Error as e:
            raise SQLExecutionError(f"Error al inicializar esquema SQLite: {e}") from e

        # 2. Cargar y ejecutar Seed si se solicita
        if seed_path:
            if seed_path is True:
                resolved_seed = base_dir / "seed.sql"
            else:
                resolved_seed = Path(seed_path)

            if not resolved_seed.exists():
                raise FileNotFoundError(f"Archivo seed no encontrado: {resolved_seed}")

            seed_sql = resolved_seed.read_text(encoding="utf-8")
            try:
                with self.conn:
                    self.conn.executescript(seed_sql)
            except sqlite3.Error as e:
                raise SQLExecutionError(f"Error al aplicar datos semilla: {e}") from e

    def execute(
        self,
        query: SQLQuery | str,
        params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
    ) -> QueryResult:
        """Valida mediante SQLGuard y ejecuta una consulta SQL dentro de una transacción segura.

        Args:
            query: Objeto SQLQuery o cadena SQL cruda.
            params: Parámetros adicionales en caso de recibir una cadena SQL.

        Returns:
            QueryResult con filas, columnas, tiempo de ejecución o IDs afectados.

        Raises:
            SQLGuardError: Si la consulta no pasa las reglas de seguridad.
            SQLExecutionError: Si ocurre un error de ejecución o violación de restricciones.
        """
        if isinstance(query, SQLQuery):
            op = query.operation
            raw_params = query.params if params is None else params
            validated_sql = self.guard.validate(query)
        else:
            clean_sql = str(query).strip()
            op = "INSERT" if clean_sql.upper().startswith("INSERT") else "SELECT"
            raw_params = params if params is not None else ()
            validated_sql = self.guard.validate(clean_sql)

        t_start = time.perf_counter()
        with self._lock:
            self._query_start = t_start
            try:
                with self.conn:
                    cursor = self.conn.cursor()
                    exec_params = raw_params or ()
                    cursor.execute(validated_sql, exec_params)

                    elapsed_ms = (time.perf_counter() - t_start) * 1000.0

                    if op == "SELECT":
                        columns = [d[0] for d in cursor.description] if cursor.description else []
                        rows = [list(r) for r in cursor.fetchall()]
                        return QueryResult(
                            operation="SELECT",
                            columns=columns,
                            rows=rows,
                            row_count=len(rows),
                            execution_time_ms=elapsed_ms,
                            query=validated_sql,
                        )
                    else:  # INSERT
                        last_id = cursor.lastrowid
                        affected = cursor.rowcount
                        return QueryResult(
                            operation="INSERT",
                            last_row_id=last_id,
                            affected_rows=affected,
                            row_count=affected,
                            execution_time_ms=elapsed_ms,
                            query=validated_sql,
                        )
            except SQLGuardError:
                raise
            except sqlite3.Error as e:
                # sqlite3 context manager ya ejecuta rollback en excepción
                if isinstance(e, sqlite3.OperationalError) and "interrupted" in str(e):
                    raise SQLQueryTimeoutError(
                        f"La consulta excedió el tiempo máximo de {self.query_timeout_ms} ms"
                    ) from e
                raise SQLExecutionError(f"Fallo en ejecución SQL: {e}") from e

    def execute_many(self, queries: Sequence[SQLQuery | str]) -> list[QueryResult]:
        """Ejecuta una secuencia de consultas dentro de una única transacción atómica.

        Si alguna consulta falla o viola SQLGuard, se realiza ROLLBACK completo de todas.

        Args:
            queries: Lista de consultas a ejecutar secuencialmente.

        Returns:
            Lista de QueryResult correspondientes.
        """
        # 1. Pre-validar todas las consultas antes de ejecutar
        validated_items: list[tuple[Literal["SELECT", "INSERT"], str, Any]] = []
        for q in queries:
            op: Literal["SELECT", "INSERT"]
            if isinstance(q, SQLQuery):
                op = q.operation
                v_sql = self.guard.validate(q)
                p = q.params or ()
            else:
                clean_sql = str(q).strip()
                op = "INSERT" if clean_sql.upper().startswith("INSERT") else "SELECT"
                v_sql = self.guard.validate(clean_sql)
                p = ()
            validated_items.append((op, v_sql, p))

        results: list[QueryResult] = []
        with self._lock:
            self._query_start = time.perf_counter()
            try:
                with self.conn:
                    cursor = self.conn.cursor()
                    for op, v_sql, p in validated_items:
                        t_start = time.perf_counter()
                        cursor.execute(v_sql, p)
                        elapsed_ms = (time.perf_counter() - t_start) * 1000.0

                        if op == "SELECT":
                            columns = [d[0] for d in cursor.description] if cursor.description else []
                            rows = [list(r) for r in cursor.fetchall()]
                            results.append(
                                QueryResult(
                                    operation="SELECT",
                                    columns=columns,
                                    rows=rows,
                                    row_count=len(rows),
                                    execution_time_ms=elapsed_ms,
                                    query=v_sql,
                                )
                            )
                        else:
                            results.append(
                                QueryResult(
                                    operation="INSERT",
                                    last_row_id=cursor.lastrowid,
                                    affected_rows=cursor.rowcount,
                                    row_count=cursor.rowcount,
                                    execution_time_ms=elapsed_ms,
                                    query=v_sql,
                                )
                            )
                return results
            except SQLGuardError:
                raise
            except sqlite3.Error as e:
                if isinstance(e, sqlite3.OperationalError) and "interrupted" in str(e):
                    raise SQLQueryTimeoutError(
                        f"La transacción por lotes excedió el tiempo máximo de {self.query_timeout_ms} ms"
                    ) from e
                raise SQLExecutionError(f"Fallo en transacción por lotes: {e}") from e

    def close(self) -> None:
        """Cierra la conexión a la base de datos."""
        with self._lock:
            if not self._is_closed:
                try:
                    self._conn.close()
                finally:
                    self._is_closed = True

    def __enter__(self) -> "SQLExecutor":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
