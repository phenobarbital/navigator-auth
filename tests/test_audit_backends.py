"""Unit tests for the audit-log backend SQL generation and dialect resolution.

These cover the pure, driver-agnostic helpers used by
``navigator_auth.abac.audit.AuditLog`` to build INSERT statements for the
various asyncdb SQL drivers. Driver I/O itself needs a live database and is
exercised in integration tests, not here.
"""
import pytest

from navigator_auth.abac.audit import (
    build_placeholders,
    build_insert,
    resolve_paramstyle,
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
