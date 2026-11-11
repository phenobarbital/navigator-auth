"""Unit tests for the ``navauth self upgrade`` command."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from navigator_auth import conf
from navigator_auth.migrations import cli
from navigator_auth.migrations.runner import MigrationError


ROOT = Path(__file__).parents[3]


def _args(**overrides: object) -> SimpleNamespace:
    """Return command arguments suitable for direct ``run`` calls."""
    values: dict[str, object] = {
        "check": False,
        "dsn": None,
        "user": None,
        "sets": None,
        "runtime_role": "runtime",
        "reapply_changed": False,
        "fail_fast": False,
        "verbose": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_resolve_dsn_precedence(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Resolve flags, configuration users, and runtime fallback in precedence order."""
    monkeypatch.setattr(conf, "AUTH_ADMIN_DSN", "postgres://admin:secret@db/admin")
    assert cli.resolve_dsn(_args(dsn="postgres://flag:secret@db/flag")) == (
        "postgres://flag:secret@db/flag",
        "--dsn",
    )
    assert cli.resolve_dsn(_args()) == ("postgres://admin:secret@db/admin", "AUTH_ADMIN_DSN")

    monkeypatch.setattr(conf, "AUTH_ADMIN_DSN", None)
    monkeypatch.setattr(conf, "AUTH_ADMIN_PWD", "password")
    dsn, label = cli.resolve_dsn(_args(user="user name"))
    assert dsn == f"postgres://user%20name:password@{conf.DBHOST}:{conf.DBPORT}/{conf.DBNAME}"
    assert label == "--user"

    monkeypatch.setattr(conf, "AUTH_ADMIN_USER", None)
    monkeypatch.setattr(conf, "DBUSER", "runtime")
    monkeypatch.setattr(conf, "default_dsn", "postgres://runtime:runtime-secret@db/runtime")
    monkeypatch.setattr(conf, "AUTH_ADMIN_PWD", None)
    assert cli.resolve_dsn(_args()) == (conf.default_dsn, "default_dsn")
    assert "runtime credentials" in capsys.readouterr().err


def test_resolve_dsn_requires_password_off_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject an admin user without configured password in a non-interactive shell."""
    monkeypatch.setattr(conf, "AUTH_ADMIN_DSN", None)
    monkeypatch.setattr(conf, "AUTH_ADMIN_USER", "admin")
    monkeypatch.setattr(conf, "AUTH_ADMIN_PWD", None)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(MigrationError, match="not a TTY"):
        cli.resolve_dsn(_args())


def test_cli_never_prints_dsn_or_password(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Redact credentials echoed by a connection failure."""
    dsn = "postgres://admin:s3cr3t-pw@db/navigator"

    async def fail_connect(_: str) -> None:
        raise RuntimeError(f"could not connect to {dsn}")

    monkeypatch.setattr(conf, "AUTH_ADMIN_PWD", "s3cr3t-pw")
    assert cli.main(["self", "upgrade", "--dsn", dsn], connect=fail_connect) == cli.EXIT_CONFIG
    output = capsys.readouterr()
    assert dsn not in output.out + output.err + caplog.text
    assert "s3cr3t-pw" not in output.out + output.err + caplog.text


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("nothing_pending", cli.EXIT_OK),
        ("check_pending", cli.EXIT_PENDING),
        ("failed_file", cli.EXIT_FAILED),
        ("bad_set", cli.EXIT_CONFIG),
        ("connect_error", cli.EXIT_CONFIG),
        ("invalid_runtime_role", cli.EXIT_CONFIG),
    ],
)
def test_cli_exit_codes(
    fake_conn: object, tmp_catalog: Path, monkeypatch: pytest.MonkeyPatch, scenario: str, expected: int
) -> None:
    """Map normal, check, connection, and invalid-role paths to specified exits."""
    from navigator_auth.migrations import cli as cli_module

    async def connect(_: str) -> object:
        return fake_conn

    async def bad_connect(_: str) -> object:
        raise OSError("unavailable")

    async def valid_role(conn: object, role: str | None) -> str:
        return role or "runtime"

    monkeypatch.setattr(cli_module, "validate_runtime_role", valid_role)
    if scenario == "nothing_pending":
        monkeypatch.setattr(cli_module, "upgrade", lambda *args, **kwargs: _report())
        argv = ["self", "upgrade", "--dsn", "postgres://a:b@db/x"]
        connector = connect
    elif scenario == "check_pending":
        argv = ["self", "upgrade", "--check", "--dsn", "postgres://a:b@db/x"]
        connector = connect
    elif scenario == "failed_file":
        monkeypatch.setattr(cli_module, "upgrade", lambda *args, **kwargs: _failed_report(tmp_catalog))
        argv = ["self", "upgrade", "--dsn", "postgres://a:b@db/x"]
        connector = connect
    elif scenario == "bad_set":
        argv = ["self", "upgrade", "--set", "unknown", "--dsn", "postgres://a:b@db/x"]
        connector = connect
    elif scenario == "connect_error":
        argv = ["self", "upgrade", "--dsn", "postgres://a:b@db/x"]
        connector = bad_connect
    else:
        async def invalid_role(conn: object, role: str | None) -> str:
            raise MigrationError("invalid runtime role")

        monkeypatch.setattr(cli_module, "validate_runtime_role", invalid_role)
        argv = ["self", "upgrade", "--dsn", "postgres://a:b@db/x"]
        connector = connect
    assert cli.main(argv, connect=connector) == expected


async def _report() -> object:
    """Return an empty report from an async replacement for ``upgrade``."""
    from navigator_auth.migrations.runner import UpgradeReport

    return UpgradeReport()


async def _failed_report(tmp_catalog: Path) -> object:
    """Return a report containing one failed result."""
    from navigator_auth.migrations.catalog import discover
    from navigator_auth.migrations.runner import MigrationResult, UpgradeReport

    return UpgradeReport(failed=[MigrationResult(file=discover()[0], ok=False, error="failed")])


def test_cli_check_does_not_write(fake_conn: object, tmp_catalog: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ``--check`` uses only read-only status and access operations."""
    from navigator_auth.migrations import cli as cli_module

    async def valid_role(conn: object, role: str | None) -> str:
        return role or "runtime"

    async def connect(_: str) -> object:
        return fake_conn

    monkeypatch.setattr(cli_module, "validate_runtime_role", valid_role)
    assert cli.main(
        ["self", "upgrade", "--check", "--runtime-role", "runtime", "--dsn", "postgres://a:b@db/x"],
        connect=connect,
    ) == 1
    assert fake_conn.writes() == []


def test_check_reports_missing_runtime_access_without_writes(
    fake_conn: object, tmp_catalog: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Report missing privileges during a read-only check and reject invalid roles."""
    from navigator_auth.migrations import cli as cli_module

    async def valid_role(conn: object, role: str | None) -> str:
        return role or "runtime"

    async def connect(_: str) -> object:
        return fake_conn

    fake_conn.relations.add("auth.user_vault_secrets")
    fake_conn.respond("has_table_privilege", False)
    fake_conn.respond("FROM pg_depend", [])
    monkeypatch.setattr(cli_module, "validate_runtime_role", valid_role)
    assert cli.main(
        ["self", "upgrade", "--check", "--runtime-role", "runtime", "--dsn", "postgres://a:b@db/x"],
        connect=connect,
    ) == 1
    assert "missing access: runtime lacks SELECT on auth.user_vault_secrets" in capsys.readouterr().out
    assert fake_conn.writes() == []
    assert all("runtime" not in sql for _, sql, _ in fake_conn.statements)


def test_console_script_declared() -> None:
    """Declare the ``navauth`` console entry point in project metadata."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["navauth"] == "navigator_auth.migrations.cli:console_entry"


def test_wheel_contains_sql(tmp_path: Path) -> None:
    """Verify built distributions preserve the SQL package data and entry point when build is available."""
    build = pytest.importorskip("build")
    try:
        builder = build.ProjectBuilder(str(ROOT))
        wheel_path = Path(builder.build("wheel", str(tmp_path)))
    except Exception as error:  # pylint: disable=W0718
        pytest.skip(f"wheel toolchain unavailable: {error}")

    import zipfile

    with zipfile.ZipFile(wheel_path) as wheel:
        names = wheel.namelist()
        assert "navigator_auth/migrations/sql/identity/004_identity_base_columns.sql" in names
        entry_points = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
        assert "navauth = navigator_auth.migrations.cli:console_entry" in wheel.read(entry_points).decode()
