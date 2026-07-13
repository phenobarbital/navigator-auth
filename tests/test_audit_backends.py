"""Unit tests for the audit-log backend SQL generation and dialect resolution.

These cover the pure, driver-agnostic helpers used by
``navigator_auth.abac.audit.AuditLog`` to build INSERT statements for the
various asyncdb SQL drivers. Driver I/O itself needs a live database and is
exercised in integration tests, not here.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from navigator_auth.abac.audit import (
    build_placeholders,
    build_insert,
    build_select,
    resolve_paramstyle,
    _build_record,
    AuditLog,
)


@pytest.mark.parametrize(
    "paramstyle,expected",
    [
        ("numeric", ["$1", "$2", "$3"]),
        ("format", ["%s", "%s", "%s"]),
        ("qmark", ["?", "?", "?"]),
        ("named", [":1", ":2", ":3"]),
    ],
)
def test_build_placeholders(paramstyle, expected):
    assert build_placeholders(paramstyle, 3) == expected


def test_build_placeholders_zero():
    assert build_placeholders("numeric", 0) == []


def test_build_placeholders_unknown_style():
    with pytest.raises(ValueError):
        build_placeholders("does-not-exist", 2)


def test_build_insert_numeric():
    sql, values = build_insert("audit_log", {"a": 1, "b": "x"}, "numeric")
    assert sql == "INSERT INTO audit_log (a, b) VALUES ($1, $2)"
    assert values == [1, "x"]


def test_build_insert_format():
    sql, values = build_insert("audit_log", {"a": 1, "b": "x"}, "format")
    assert sql == "INSERT INTO audit_log (a, b) VALUES (%s, %s)"
    assert values == [1, "x"]


def test_build_insert_qmark():
    sql, _ = build_insert("audit_log", {"a": 1, "b": "x"}, "qmark")
    assert sql == "INSERT INTO audit_log (a, b) VALUES (?, ?)"


def test_build_insert_named():
    sql, _ = build_insert("audit_log", {"a": 1, "b": "x"}, "named")
    assert sql == "INSERT INTO audit_log (a, b) VALUES (:1, :2)"


@pytest.mark.parametrize(
    "backend,expected",
    [
        ("pg", "numeric"),
        ("postgres", "numeric"),
        ("mysql", "format"),
        ("mysqlclient", "format"),
        ("mariadb", "format"),
        ("mssql", "qmark"),
        ("sqlite", "qmark"),
        ("duckdb", "qmark"),
        ("oracle", "named"),
    ],
)
def test_resolve_paramstyle_known(backend, expected):
    assert resolve_paramstyle(backend) == expected


def test_resolve_paramstyle_unknown_uses_default():
    assert resolve_paramstyle("brand_new_driver", default="qmark") == "qmark"
    assert resolve_paramstyle("brand_new_driver", default="format") == "format"


# ---------------------------------------------------------------------------
# build_select (tenant-scoped read helper)
# ---------------------------------------------------------------------------

def test_build_select_numeric_with_conditions_and_pagination():
    conditions = [("tenant", "=", "acme"), ("status", "=", "DENY")]
    sql, values = build_select(
        "audit_log", conditions, "numeric",
        order_by="timestamp", descending=True, limit=50, offset=10,
    )
    assert sql == (
        "SELECT * FROM audit_log WHERE tenant = $1 AND status = $2 "
        "ORDER BY timestamp DESC LIMIT 50 OFFSET 10"
    )
    assert values == ["acme", "DENY"]


def test_build_select_range_conditions_format():
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    conditions = [("tenant", "=", "acme"), ("timestamp", ">=", since)]
    sql, values = build_select("audit_log", conditions, "format", order_by="timestamp")
    assert sql == (
        "SELECT * FROM audit_log WHERE tenant = %s AND timestamp >= %s "
        "ORDER BY timestamp DESC"
    )
    assert values == ["acme", since]


def test_build_select_no_conditions_omits_where():
    sql, values = build_select("audit_log", [], "numeric")
    assert sql == "SELECT * FROM audit_log"
    assert values == []


def test_build_select_offset_zero_omitted_and_limit_coerced():
    sql, _ = build_select(
        "audit_log", [("tenant", "=", "acme")], "numeric",
        order_by="timestamp", limit="25", offset=0,
    )
    # limit is coerced to int; offset=0 is falsy -> no OFFSET clause
    assert sql.endswith("LIMIT 25")
    assert "OFFSET" not in sql


def test_build_select_ascending():
    sql, _ = build_select(
        "audit_log", [("tenant", "=", "acme")], "qmark",
        order_by="timestamp", descending=False,
    )
    assert "ORDER BY timestamp ASC" in sql


# ---------------------------------------------------------------------------
# _build_record — tenant column
# ---------------------------------------------------------------------------

def _fake_answer(response="policy-x", rule="rule-1"):
    return SimpleNamespace(response=response, rule=rule)


def _fake_user(username="alice", user_id=42):
    return SimpleNamespace(username=username, id=user_id)


def test_build_record_includes_tenant_when_provided():
    record = _build_record(
        _fake_answer(), "ALLOW", _fake_user(), "127.0.0.1", tenant="acme"
    )
    assert record["tenant"] == "acme"
    assert record["status"] == "ALLOW"
    assert record["username"] == "alice"
    assert record["user_id"] == 42


def test_build_record_tenant_defaults_to_none():
    record = _build_record(_fake_answer(), "DENY", _fake_user(), "127.0.0.1")
    assert record["tenant"] is None


# ---------------------------------------------------------------------------
# AuditLog.query — tenant-scoped reads (fake driver, no live DB)
# ---------------------------------------------------------------------------

class _FakeConn:
    def __init__(self, captured, rows):
        self._captured = captured
        self._rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def fetch_all(self, sql, *values):
        self._captured["sql"] = sql
        self._captured["values"] = list(values)
        return self._rows


class _FakeDriver:
    def __init__(self, captured, rows):
        self._captured = captured
        self._rows = rows

    async def connection(self):
        return _FakeConn(self._captured, self._rows)


def _sql_audit_log(rows=None, captured=None):
    """Build an AuditLog bypassing conf-driven __init__, wired to a fake SQL driver."""
    captured = captured if captured is not None else {}
    audit = AuditLog.__new__(AuditLog)
    audit.host = "127.0.0.1"
    audit._backend = "pg"
    audit._family = "sql"
    audit._paramstyle = "numeric"
    audit._driver = _FakeDriver(captured, rows or [])
    return audit, captured


@pytest.mark.asyncio
async def test_query_always_scopes_by_tenant():
    rows = [{"tenant": "acme", "status": "ALLOW", "username": "alice"}]
    audit, captured = _sql_audit_log(rows=rows)
    result = await audit.query(tenant="acme")
    # tenant is always the first WHERE predicate and its bound value
    assert "WHERE tenant = $1" in captured["sql"]
    assert captured["values"][0] == "acme"
    assert result == rows


@pytest.mark.asyncio
async def test_query_appends_optional_filters():
    audit, captured = _sql_audit_log()
    await audit.query(tenant="acme", user_id=42, status="DENY")
    assert captured["sql"].startswith(
        "SELECT * FROM audit_log WHERE tenant = $1 AND user_id = $2 AND status = $3"
    )
    assert captured["values"] == ["acme", 42, "DENY"]


@pytest.mark.asyncio
async def test_query_pagination():
    audit, captured = _sql_audit_log()
    await audit.query(tenant="acme", limit=25, offset=50)
    assert captured["sql"].endswith("ORDER BY timestamp DESC LIMIT 25 OFFSET 50")


@pytest.mark.asyncio
async def test_query_requires_tenant():
    audit, _ = _sql_audit_log()
    with pytest.raises(ValueError):
        await audit.query(tenant=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["log", "document", "timeseries"])
async def test_query_unsupported_backend_returns_empty(family):
    audit = AuditLog.__new__(AuditLog)
    audit._backend = family
    audit._family = family
    result = await audit.query(tenant="acme")
    assert result == []
