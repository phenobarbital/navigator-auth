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
pure helpers :func:`build_placeholders` / :func:`build_insert` / :func:`build_select`,
which are unit tested independently of any live database.

Tenant scoping
--------------
Every record carries an optional ``tenant`` so a multi-tenant deployment can
attribute — and, crucially, *read back* — audit entries per tenant.
:meth:`AuditLog.log` accepts a keyword-only ``tenant`` and threads it to every
write family (SQL column, document field, influx tag, logger message).
:meth:`AuditLog.query` reads entries back and **always** constrains by tenant to
prevent cross-tenant leakage. Structured ``query()`` is currently implemented
for SQL backends only; other families remain write-only and ``query()`` returns
an empty list with a warning (query the backing store directly).
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


def build_select(
    table: str,
    conditions: list,
    paramstyle: str,
    *,
    order_by: str = None,
    descending: bool = True,
    limit: int = None,
    offset: int = None,
) -> tuple[str, list]:
    """Assemble a parameterised ``SELECT`` from equality/range conditions.

    Args:
        table: Fully-qualified table name.
        conditions: A list of ``(column, operator, value)`` triples, ANDed
            together — e.g. ``[("tenant", "=", t), ("timestamp", ">=", since)]``.
            The operator is a literal SQL comparison (``=``, ``>=``, ``<=``);
            the value is always bound as a placeholder.
        paramstyle: Placeholder dialect (see :func:`build_placeholders`).
        order_by: Optional column to sort by.
        descending: Sort direction when ``order_by`` is set.
        limit: Optional ``LIMIT``. Coerced to ``int`` (defence against injection
            since it is inlined, not bound).
        offset: Optional ``OFFSET``. Coerced to ``int``.

    Returns:
        A ``(sql, values)`` tuple; ``values`` preserves condition order.
    """
    values = [value for (_col, _op, value) in conditions]
    placeholders = build_placeholders(paramstyle, len(values))
    where_parts = [
        f"{col} {op} {ph}"
        for (col, op, _value), ph in zip(conditions, placeholders)
    ]
    sql = f"SELECT * FROM {table}"
    if where_parts:
        sql += " WHERE " + " AND ".join(where_parts)
    if order_by:
        sql += f" ORDER BY {order_by} {'DESC' if descending else 'ASC'}"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    if offset:
        sql += f" OFFSET {int(offset)}"
    return sql, values


def _build_record(answer, status, user, host: str, *, tenant: str = None) -> dict:
    """Build a flat audit record usable by db and influx backends.

    ``tenant`` is optional so existing PDP callers are unaffected; when
    provided it is persisted as a first-class column/field for per-tenant reads.
    """
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
        "tenant": tenant,
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

    async def log(self, answer, status, user, *, tenant: str = None):
        """Record an access decision.

        Args:
            answer: The PDP decision object (exposes ``response`` and ``rule``).
            status: Decision status (e.g. ``"ALLOW"`` / ``"DENY"``).
            user: The subject; ``username`` and ``id`` are read if present.
            tenant: Optional tenant identifier persisted with the record so the
                entry can later be read back per tenant via :meth:`query`.
                Backwards-compatible: existing callers omit it.
        """
        if self._family == "log":
            self._log_to_logger(answer, status, user, tenant=tenant)
            return
        if self._family == "timeseries":
            await self._log_to_influx(answer, status, user, tenant=tenant)
        elif self._family == "document":
            await self._log_to_document(answer, status, user, tenant=tenant)
        else:  # sql
            await self._log_to_db(answer, status, user, tenant=tenant)

    def _log_to_logger(self, answer, status, user, *, tenant: str = None):
        username = user.username if hasattr(user, "username") else user
        scope = f" [tenant={tenant}]" if tenant else ""
        logger.info(
            f"Access {status} by: {answer.response} to user {username}{scope}"
        )

    async def _log_to_influx(self, answer, status, user, *, tenant: str = None):
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
                        "tenant": tenant,
                    },
                }
                await conn.write(data, bucket=AUDIT_CREDENTIALS["bucket"])
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"InfluxDB: Error saving Audit Log: {ex}")

    async def _log_to_document(self, answer, status, user, *, tenant: str = None):
        """Insert the audit record as a document (e.g. MongoDB)."""
        from asyncdb.exceptions import DriverError

        record = _build_record(answer, status, user, self.host, tenant=tenant)
        async with await self._driver.connection() as conn:
            try:
                await conn.insert(AUDIT_TABLE, record)
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"{self._backend}: Error saving Audit Log: {ex}")

    async def _log_to_db(self, answer, status, user, *, tenant: str = None):
        from asyncdb.exceptions import DriverError

        record = _build_record(answer, status, user, self.host, tenant=tenant)
        sql, values = build_insert(AUDIT_TABLE, record, self._paramstyle)
        async with await self._driver.connection() as conn:
            try:
                await conn.execute(sql, *values)
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"{self._backend}: Error saving Audit Log: {ex}")

    # ------------------------------------------------------------------
    # Read / query API
    # ------------------------------------------------------------------

    async def query(
        self,
        *,
        tenant: str,
        user_id=None,
        username: str = None,
        status: str = None,
        rule: str = None,
        since: datetime = None,
        until: datetime = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Read audit entries back, **always** constrained to one ``tenant``.

        Structured querying is implemented for SQL backends. For the
        ``timeseries`` (influx), ``document`` and ``log`` families this returns
        an empty list and logs a warning — query those stores directly.

        Args:
            tenant: Required tenant scope. Every returned row belongs to it.
            user_id / username / status / rule: Optional equality filters.
            since / until: Optional inclusive ``timestamp`` range bounds.
            limit / offset: Pagination (``LIMIT``/``OFFSET``).

        Returns:
            A list of record dicts (newest first), or ``[]`` on any driver error
            or unsupported backend (best-effort, consistent with the write side).
        """
        if tenant is None:
            raise ValueError("AuditLog.query() requires a 'tenant' scope.")
        if self._family != "sql":
            logger.warning(
                f"AuditLog.query() is only supported for SQL backends; "
                f"backend '{self._backend}' ({self._family}) is write-only. "
                f"Query the backing store directly."
            )
            return []
        return await self._query_db(
            tenant=tenant,
            user_id=user_id,
            username=username,
            status=status,
            rule=rule,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    @staticmethod
    def _build_conditions(
        *, tenant, user_id, username, status, rule, since, until
    ) -> list:
        """Assemble the WHERE conditions for :meth:`query` (tenant always first)."""
        conditions = [("tenant", "=", tenant)]
        if user_id is not None:
            conditions.append(("user_id", "=", user_id))
        if username is not None:
            conditions.append(("username", "=", username))
        if status is not None:
            conditions.append(("status", "=", status))
        if rule is not None:
            conditions.append(("rule", "=", rule))
        if since is not None:
            conditions.append(("timestamp", ">=", since))
        if until is not None:
            conditions.append(("timestamp", "<=", until))
        return conditions

    async def _query_db(
        self, *, tenant, user_id, username, status, rule, since, until, limit, offset
    ) -> list[dict]:
        from asyncdb.exceptions import DriverError

        conditions = self._build_conditions(
            tenant=tenant,
            user_id=user_id,
            username=username,
            status=status,
            rule=rule,
            since=since,
            until=until,
        )
        sql, values = build_select(
            AUDIT_TABLE,
            conditions,
            self._paramstyle,
            order_by="timestamp",
            descending=True,
            limit=limit,
            offset=offset,
        )
        async with await self._driver.connection() as conn:
            try:
                result = await conn.fetch_all(sql, *values)
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"{self._backend}: Error querying Audit Log: {ex}")
                return []
        if not result:
            return []
        return [dict(row) for row in result]
