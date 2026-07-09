"""Pluggable audit logging for the ABAC/PBAC Policy Decision Point.

The Policy Decision Point (:mod:`navigator_auth.abac.pdp`) records every access
decision through :class:`AuditLog`. The destination is selected with the
``AUDIT_BACKEND`` setting and can be one of three families:

============  ==========================================  =========================
Family        ``AUDIT_BACKEND`` values                    Write mechanism
============  ==========================================  =========================
logger        ``log``                                     Python ``logger.info``
time-series   ``influx``                                  asyncdb point ``write``
document      ``mongo``                                   asyncdb ``insert``
SQL           any other asyncdb driver (``pg``,           parameterised ``INSERT``
              ``postgres``, ``mysql``, ``mssql``,         via ``execute``
              ``sqlite``, ``oracle``, ...)
============  ==========================================  =========================

SQL drivers differ only in their parameter placeholder dialect. That mapping is
resolved by :func:`resolve_paramstyle` and the statement is assembled by the
pure helpers :func:`build_placeholders` / :func:`build_insert`, which are unit
tested independently of any live database.
"""
from datetime import datetime, timezone
import socket
from navconfig.logging import logger
from navigator_auth.exceptions import ConfigError
from navigator_auth.conf import (
    ENVIRONMENT,
    DOMAIN,
    AUDIT_BACKEND,
    AUDIT_CREDENTIALS,
    AUDIT_DSN,
    AUDIT_TABLE,
    AUDIT_PARAMSTYLE,
    ENABLE_AUDIT_LOG,
)

# ---------------------------------------------------------------------------
# Backend families
# ---------------------------------------------------------------------------
#: Logger-only backend (no external dependency).
LOG_BACKEND = "log"

#: Time-series backends (point/measurement write API).
TIMESERIES_BACKENDS = frozenset({"influx"})

#: Document/NoSQL backends (collection ``insert`` API).
DOCUMENT_BACKENDS = frozenset({"mongo", "documentdb"})

#: SQL parameter placeholder dialects per asyncdb driver name. Any driver not
#: listed here is still treated as SQL and falls back to ``AUDIT_PARAMSTYLE``.
SQL_PARAMSTYLES = {
    "pg": "numeric",        # asyncpg    -> $1, $2
    "postgres": "numeric",
    "mysql": "format",      # aiomysql   -> %s
    "mysqlclient": "format",
    "mariadb": "format",
    "mssql": "qmark",       # aioodbc    -> ?
    "sqlite": "qmark",
    "duckdb": "qmark",
    "oracle": "named",      # oracledb   -> :1, :2
}

#: Supported placeholder dialects and how each renders the *n*-th (1-based)
#: bind parameter.
_PARAMSTYLE_RENDERERS = {
    "numeric": lambda n: f"${n}",
    "format": lambda _n: "%s",
    "qmark": lambda _n: "?",
    "named": lambda n: f":{n}",
}


def resolve_paramstyle(backend: str, default: str = "format") -> str:
    """Return the SQL placeholder dialect for an asyncdb ``backend`` driver.

    Known drivers are resolved from :data:`SQL_PARAMSTYLES`; unmapped drivers
    fall back to ``default`` (configurable via ``AUDIT_PARAMSTYLE``).
    """
    return SQL_PARAMSTYLES.get(backend, default)


def build_placeholders(paramstyle: str, count: int) -> list[str]:
    """Build a list of ``count`` bind placeholders for a given ``paramstyle``.

    Raises:
        ValueError: if ``paramstyle`` is not a supported dialect.
    """
    try:
        render = _PARAMSTYLE_RENDERERS[paramstyle]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported SQL paramstyle '{paramstyle}'. "
            f"Choose one of {sorted(_PARAMSTYLE_RENDERERS)}."
        ) from exc
    return [render(i + 1) for i in range(count)]


def build_insert(table: str, record: dict, paramstyle: str) -> tuple[str, list]:
    """Assemble a parameterised ``INSERT`` statement for ``record``.

    Returns a ``(sql, values)`` tuple where ``values`` preserves the column
    order used in the statement.
    """
    columns = ", ".join(record.keys())
    values = list(record.values())
    placeholders = ", ".join(build_placeholders(paramstyle, len(values)))
    sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
    return sql, values


def _build_record(answer, status, user, host: str) -> dict:
    """Build a flat audit record usable by db and influx backends."""
    return {
        "timestamp": datetime.now(timezone.utc),
        "environment": ENVIRONMENT,
        "domain": DOMAIN,
        "host": host,
        "status": status,
        "message": answer.response,
        "rule": getattr(answer, "rule", None),
        "username": user.username if hasattr(user, "username") else str(user),
        "user_id": user.id if hasattr(user, "id") else None,
    }


class AuditLog:
    """Pluggable audit logger.

    Supported AUDIT_BACKEND values
    ──────────────────────────────
    "log"     — Python logger only (no external dependency).
    "influx"  — InfluxDB via asyncdb influx driver (time-series point write).
    "mongo"   — MongoDB via asyncdb mongo driver (document insert).
    <driver>  — Any asyncdb SQL driver (e.g. "pg", "postgres", "mysql",
                "mssql", "sqlite", "oracle"). Requires AUDIT_DSN to be set.
                The placeholder dialect is auto-detected (see SQL_PARAMSTYLES)
                and can be overridden with AUDIT_PARAMSTYLE for unlisted drivers.
    """

    _backend: str
    _family: str
    _driver = None
    _paramstyle: str = None

    def __init__(self):
        self.host = socket.gethostbyname(socket.gethostname())
        if ENABLE_AUDIT_LOG:
            # Automatic fallback for non-production environments to avoid noise
            if ENVIRONMENT in ('development', 'testing') and AUDIT_BACKEND == 'influx':
                self._backend = LOG_BACKEND
            else:
                self._backend = AUDIT_BACKEND
        else:
            self._backend = LOG_BACKEND

        self._family = self._resolve_family(self._backend)

        if self._family == "log":
            return
        if self._family == "timeseries":
            self._init_influx()
        elif self._family == "document":
            self._init_driver()
        else:  # sql
            self._paramstyle = resolve_paramstyle(self._backend, AUDIT_PARAMSTYLE)
            self._init_driver()

    @staticmethod
    def _resolve_family(backend: str) -> str:
        """Classify a backend name into a write family."""
        if backend == LOG_BACKEND:
            return "log"
        if backend in TIMESERIES_BACKENDS:
            return "timeseries"
        if backend in DOCUMENT_BACKENDS:
            return "document"
        return "sql"

    # ------------------------------------------------------------------
    # Backend initialisers
    # ------------------------------------------------------------------

    def _init_influx(self):
        from asyncdb import AsyncDB
        from asyncdb.exceptions import DriverError

        try:
            self._driver = AsyncDB("influx", params=AUDIT_CREDENTIALS)
        except DriverError as ex:
            raise ConfigError(
                f"Unable to start Audit Backend (influx): {ex}"
            ) from ex

    def _init_driver(self):
        """Initialise any DSN-based asyncdb driver (SQL or document)."""
        from asyncdb import AsyncDB
        from asyncdb.exceptions import DriverError

        if not AUDIT_DSN:
            raise ConfigError(
                f"AUDIT_DSN is required when AUDIT_BACKEND='{self._backend}'"
            )
        try:
            self._driver = AsyncDB(self._backend, dsn=AUDIT_DSN)
        except DriverError as ex:
            raise ConfigError(
                f"Unable to start Audit Backend ({self._backend}): {ex}"
            ) from ex

    # ------------------------------------------------------------------
    # Logging methods
    # ------------------------------------------------------------------

    async def log(self, answer, status, user):
        if self._family == "log":
            self._log_to_logger(answer, status, user)
            return
        if self._family == "timeseries":
            await self._log_to_influx(answer, status, user)
        elif self._family == "document":
            await self._log_to_document(answer, status, user)
        else:  # sql
            await self._log_to_db(answer, status, user)

    def _log_to_logger(self, answer, status, user):
        username = user.username if hasattr(user, "username") else user
        logger.info(
            f"Access {status} by: {answer.response} to user {username}"
        )

    async def _log_to_influx(self, answer, status, user):
        from asyncdb.exceptions import DriverError

        async with await self._driver.connection() as conn:
            try:
                data = {
                    "measurement": "audit",
                    "location": ENVIRONMENT,
                    "domain": DOMAIN,
                    "timestamp": datetime.now(timezone.utc),
                    "fields": {"status": status},
                    "tags": {
                        "host": self.host,
                        "region": ENVIRONMENT,
                        "message": answer.response,
                        "answer": str(answer),
                        "username": user.username if hasattr(user, "username") else str(user),
                        "user": user.id if hasattr(user, "id") else None,
                    },
                }
                await conn.write(data, bucket=AUDIT_CREDENTIALS["bucket"])
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"InfluxDB: Error saving Audit Log: {ex}")

    async def _log_to_document(self, answer, status, user):
        """Insert the audit record as a document (e.g. MongoDB)."""
        from asyncdb.exceptions import DriverError

        record = _build_record(answer, status, user, self.host)
        async with await self._driver.connection() as conn:
            try:
                await conn.insert(AUDIT_TABLE, record)
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"{self._backend}: Error saving Audit Log: {ex}")

    async def _log_to_db(self, answer, status, user):
        from asyncdb.exceptions import DriverError

        record = _build_record(answer, status, user, self.host)
        sql, values = build_insert(AUDIT_TABLE, record, self._paramstyle)
        async with await self._driver.connection() as conn:
            try:
                await conn.execute(sql, *values)
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"{self._backend}: Error saving Audit Log: {ex}")
