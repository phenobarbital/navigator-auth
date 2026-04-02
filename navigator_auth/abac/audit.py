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
    ENABLE_AUDIT_LOG,
)


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
    "log"    — Python logger only (no external dependency).
    "influx" — InfluxDB via asyncdb influx driver.
    <driver> — Any asyncdb-compatible driver (e.g. "mongo", "pg").
               Requires AUDIT_DSN to be set.
    """

    _backend: str
    _driver = None

    def __init__(self):
        self.host = socket.gethostbyname(socket.gethostname())
        self._backend = AUDIT_BACKEND if ENABLE_AUDIT_LOG else "log"

        if self._backend == "log":
            return

        if self._backend == "influx":
            self._init_influx()
        else:
            self._init_db()

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

    def _init_db(self):
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
        if self._backend == "log":
            self._log_to_logger(answer, status, user)
            return
        if self._backend == "influx":
            await self._log_to_influx(answer, status, user)
        else:
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

    async def _log_to_db(self, answer, status, user):
        from asyncdb.exceptions import DriverError

        record = _build_record(answer, status, user, self.host)
        async with await self._driver.connection() as conn:
            try:
                table = AUDIT_TABLE
                columns = ", ".join(record.keys())
                values = list(record.values())
                placeholders = ", ".join(f"${i + 1}" for i in range(len(values)))
                await conn.execute(
                    f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
                    *values,
                )
            except (TypeError, AttributeError, ValueError, DriverError) as ex:
                logger.error(f"{self._backend}: Error saving Audit Log: {ex}")
