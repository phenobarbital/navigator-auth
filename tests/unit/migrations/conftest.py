"""Shared fixtures for the FEAT-110 migration tests."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from navigator_auth.migrations import catalog


@pytest.fixture
def tmp_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``catalog.SQL_ROOT`` at a temporary tree with two sets and three files.

    Layout: ``vault/001_first.sql``, ``vault/002_second.sql``, ``identity/001_third.sql``.
    """
    vault_dir = tmp_path / "vault"
    identity_dir = tmp_path / "identity"
    vault_dir.mkdir()
    identity_dir.mkdir()
    (vault_dir / "001_first.sql").write_text("SELECT 1;")
    (vault_dir / "002_second.sql").write_text("SELECT 2;")
    (identity_dir / "001_third.sql").write_text("SELECT '{schema}';")
    monkeypatch.setattr(catalog, "SQL_ROOT", tmp_path)
    return tmp_path


class FakeConnection:
    """In-memory stand-in for an asyncpg connection.

    Records every call in ``statements`` as ``(method, sql, args)``. Rules, first match wins:

    - ``execute``: raises the exception registered with ``fail_on(marker, exc)`` when the
      SQL contains ``marker``; ``CREATE TABLE IF NOT EXISTS`` on ``schema_migrations`` sets
      ``ledger_present``; ``INSERT INTO`` on ``schema_migrations`` upserts
      ``ledger[(args[0], args[1])]`` from args[0..4]; returns ``"OK"``.
    - ``fetch`` / ``fetchval`` / ``fetchrow``: a value registered with ``respond(marker, value)``
      (``value`` may be ``callable(sql, args)``); else ``to_regclass`` with an arg ending in
      ``schema_migrations`` (quotes stripped) → ``ledger_present``; else ``to_regclass`` → arg
      (quotes stripped) in ``relations``; ``pg_namespace`` → ``not schema_missing``;
      ``FROM`` … ``schema_migrations`` → list of ledger rows (dicts); else ``None``.
    - ``transaction()``: async context manager; snapshots ``ledger``/``ledger_present`` and
      restores them when the block raises; appends ``("transaction", "BEGIN"/"COMMIT"/"ROLLBACK", ())``.
    - ``close()``: sets ``closed``.
    """

    def __init__(self) -> None:
        self.statements: list[tuple[str, str, tuple[Any, ...]]] = []
        self.ledger: dict[tuple[str, str], dict[str, Any]] = {}
        self.ledger_present = False
        self.schema_missing = False
        self.relations: set[str] = set()
        self.closed = False
        self._responses: list[tuple[str, object]] = []
        self._failures: list[tuple[str, BaseException]] = []
        self._missing_response = object()

    def respond(self, marker: str, value: object) -> None:
        """Register the first matching response for a query marker."""
        self._responses.append((marker, value))

    def fail_on(self, marker: str, exc: BaseException) -> None:
        """Register an exception raised by matching executed SQL."""
        self._failures.append((marker, exc))

    def _response(self, sql: str, args: tuple[Any, ...]) -> object:
        for marker, value in self._responses:
            if marker in sql:
                return value(sql, args) if callable(value) else value
        return self._missing_response

    def _default_query(self, sql: str, args: tuple[Any, ...]) -> object | None:
        if "to_regclass" in sql:
            relation = str(args[0]).replace('"', "")
            if relation.endswith("schema_migrations"):
                return self.ledger_present
            return relation in self.relations
        if "pg_namespace" in sql:
            return not self.schema_missing
        if "FROM" in sql and "schema_migrations" in sql:
            return list(self.ledger.values())
        return None

    async def execute(self, sql: str, *args: Any) -> str:
        """Record and execute the configured in-memory SQL behavior."""
        self.statements.append(("execute", sql, args))
        for marker, exc in self._failures:
            if marker in sql:
                raise exc
        if "CREATE TABLE IF NOT EXISTS" in sql and "schema_migrations" in sql:
            self.ledger_present = True
        if "INSERT INTO" in sql and "schema_migrations" in sql:
            applied_at = datetime.now(timezone.utc)
            self.ledger[(args[0], args[1])] = {
                "migration_set": args[0],
                "filename": args[1],
                "checksum": args[2],
                "applied_at": applied_at,
                "package_version": args[3],
                "execution_ms": args[4],
            }
        return "OK"

    async def fetch(self, sql: str, *args: Any) -> object:
        """Record a query and return configured or ledger-backed rows."""
        self.statements.append(("fetch", sql, args))
        response = self._response(sql, args)
        if response is not self._missing_response:
            return response
        return self._default_query(sql, args)

    async def fetchval(self, sql: str, *args: Any) -> object:
        """Record a query and return configured or inferred scalar results."""
        self.statements.append(("fetchval", sql, args))
        response = self._response(sql, args)
        if response is not self._missing_response:
            return response
        return self._default_query(sql, args)

    async def fetchrow(self, sql: str, *args: Any) -> object:
        """Record a query and return its configured or first row result."""
        self.statements.append(("fetchrow", sql, args))
        response = self._response(sql, args)
        if response is not self._missing_response:
            return response
        rows = self._default_query(sql, args)
        return rows[0] if isinstance(rows, list) and rows else None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Provide rollback-on-error ledger transaction behavior."""
        ledger = self.ledger.copy()
        ledger_present = self.ledger_present
        self.statements.append(("transaction", "BEGIN", ()))
        try:
            yield
        except BaseException:
            self.ledger = ledger
            self.ledger_present = ledger_present
            self.statements.append(("transaction", "ROLLBACK", ()))
            raise
        else:
            self.statements.append(("transaction", "COMMIT", ()))

    async def close(self) -> None:
        """Mark this in-memory connection as closed."""
        self.closed = True

    def writes(self) -> list[tuple[str, str, tuple[Any, ...]]]:
        """Return recorded SQL calls other than read-only SELECT statements."""
        return [
            statement
            for statement in self.statements
            if statement[0] == "execute" and not statement[1].lstrip().upper().startswith("SELECT")
        ]


@pytest.fixture
def fake_conn() -> FakeConnection:
    """Return a fresh ``FakeConnection``."""
    return FakeConnection()
