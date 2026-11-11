"""``navauth`` console script — ``navauth self upgrade`` (FEAT-110, spec M5)."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from collections.abc import Awaitable, Callable, Sequence
from typing import Any
from urllib.parse import quote, urlsplit

from .. import conf
from .access import missing_runtime_access, validate_runtime_role
from .catalog import MIGRATION_SETS, MigrationCatalogError
from .runner import MigrationError, MigrationState, UpgradeReport, get_status, upgrade

logger = logging.getLogger("navigator.migrations")

EXIT_OK, EXIT_PENDING, EXIT_FAILED, EXIT_CONFIG = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    """Build the ``navauth self upgrade`` command parser."""
    parser = argparse.ArgumentParser(prog="navauth", description="navigator-auth administration")
    groups = parser.add_subparsers(dest="group", required=True)
    self_cmd = groups.add_parser("self", help="manage this navigator-auth installation")
    commands = self_cmd.add_subparsers(dest="command", required=True)
    up = commands.add_parser("upgrade", help="apply pending database migrations")
    up.add_argument("--check", action="store_true", help="report applied/pending/changed; change nothing")
    up.add_argument("--dsn", help="admin DSN (highest precedence)")
    up.add_argument("--user", help="admin user; password from AUTH_ADMIN_PWD or a prompt")
    up.add_argument(
        "--set", dest="sets", action="append", choices=MIGRATION_SETS, help="restrict to one set; repeatable"
    )
    up.add_argument("--runtime-role", help="application database role; defaults to DBUSER")
    up.add_argument("--reapply-changed", action="store_true", help="also re-run files whose checksum changed")
    up.add_argument("--fail-fast", action="store_true", help="stop at the first failed file")
    up.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def resolve_dsn(args: argparse.Namespace, *, getpass_fn: Callable[[str], str] = getpass.getpass) -> tuple[str, str]:
    """Return the admin DSN and a non-sensitive source label.

    Raises:
        MigrationError: If no usable admin or runtime credentials are configured.
    """
    if args.dsn:
        return args.dsn, "--dsn"
    if conf.AUTH_ADMIN_DSN:
        return conf.AUTH_ADMIN_DSN, "AUTH_ADMIN_DSN"

    user = args.user or conf.AUTH_ADMIN_USER
    if user:
        password = conf.AUTH_ADMIN_PWD
        if password is None:
            if not sys.stdin.isatty():
                raise MigrationError("admin password is not configured and stdin is not a TTY")
            password = getpass_fn(f"Password for {user}: ")
        if not password:
            raise MigrationError("admin password is empty")
        label = "--user" if args.user else "AUTH_ADMIN_USER"
        return (
            f"postgres://{quote(user, safe='')}:{quote(password, safe='')}@{conf.DBHOST}:{conf.DBPORT}/{conf.DBNAME}",
            label,
        )

    if not conf.DBUSER:
        raise MigrationError("no admin credentials are configured and DBUSER is empty")
    print("navauth: using runtime credentials from default_dsn", file=sys.stderr)
    return conf.default_dsn, "default_dsn"


def _describe(dsn: str) -> str:
    """Return ``user@host:port/database`` without the password."""
    parts = urlsplit(dsn)
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{parts.username or '?'}@{parts.hostname or '?'}:{port or ''}/{parts.path.lstrip('/')}"


def _sanitized_error(error: BaseException, dsn: str) -> str:
    """Return a connection error description without credentials or a DSN."""
    message = str(error).replace(dsn, "[redacted DSN]")
    password = urlsplit(dsn).password
    if password:
        message = message.replace(password, "[redacted password]")
        message = message.replace(quote(password, safe=""), "[redacted password]")
    return message or "connection failed"


async def _default_connect(dsn: str) -> Any:
    """Open the raw asyncpg connection required for the advisory lock."""
    import asyncpg  # pylint: disable=C0415

    return await asyncpg.connect(dsn)


def _print_status(statuses: Sequence[Any]) -> None:
    """Print one state line per migration file and a summary."""
    counts = {state: 0 for state in MigrationState}
    for status in statuses:
        counts[status.state] += 1
        print(f"{status.state.value:<9} {status.file.migration_set}/{status.file.filename}")
    print(
        "summary: "
        f"{counts[MigrationState.APPLIED]} applied, "
        f"{counts[MigrationState.PENDING]} pending, "
        f"{counts[MigrationState.CHANGED]} changed"
    )


def _print_report(report: UpgradeReport) -> None:
    """Print upgrade results, including failures and skipped changed files."""
    for result in report.applied:
        print(f"applied   {result.file.migration_set}/{result.file.filename}")
    for result in report.failed:
        print(f"failed    {result.file.migration_set}/{result.file.filename}: {result.error}")
    for status in report.skipped_changed:
        print(f"changed   {status.file.migration_set}/{status.file.filename} (use --reapply-changed)")
    for error in report.access_errors:
        print(f"access error: {error}")
    print(
        "summary: "
        f"{len(report.applied)} applied, {len(report.failed)} failed, "
        f"{len(report.skipped_changed)} changed skipped, {len(report.access_errors)} access errors"
    )


async def run(args: argparse.Namespace, *, connect: Callable[[str], Awaitable[Any]] | None = None) -> int:
    """Connect, execute the requested operation, print its report, and return its exit code."""
    try:
        dsn, label = resolve_dsn(args)
    except MigrationError as error:
        print(f"navauth: configuration error: {error}", file=sys.stderr)
        return EXIT_CONFIG

    print(f"navauth: {label} → {_describe(dsn)}")
    connector = connect or _default_connect
    try:
        conn = await connector(dsn)
    except Exception as error:  # pylint: disable=W0718
        print(f"navauth: connection error ({type(error).__name__}): {_sanitized_error(error, dsn)}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        runtime_role = await validate_runtime_role(conn, args.runtime_role or conf.DBUSER)
        if args.check:
            statuses = await get_status(conn, args.sets)
            _print_status(statuses)
            missing: list[str] = []
            for migration_set in args.sets or MIGRATION_SETS:
                missing.extend(await missing_runtime_access(conn, migration_set, runtime_role))
            for error in missing:
                print(f"missing access: {error}")
            return (
                EXIT_PENDING
                if missing or any(status.state is not MigrationState.APPLIED for status in statuses)
                else EXIT_OK
            )

        report = await upgrade(
            conn,
            args.sets,
            runtime_role=runtime_role,
            reapply_changed=args.reapply_changed,
            fail_fast=args.fail_fast,
        )
        _print_report(report)
        return EXIT_FAILED if report.failed or report.access_errors else EXIT_OK
    except (MigrationError, MigrationCatalogError) as error:
        print(f"navauth: configuration error: {error}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as error:  # pylint: disable=W0718
        # Unexpected database failures must never surface as a traceback (exit 1 == "pending").
        print(f"navauth: unexpected error ({type(error).__name__}): {_sanitized_error(error, dsn)}", file=sys.stderr)
        return EXIT_FAILED
    finally:
        await conn.close()


def main(argv: Sequence[str] | None = None, *, connect: Callable[[str], Awaitable[Any]] | None = None) -> int:
    """Parse ``argv`` and run the command; ``connect`` is injectable for tests."""
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as error:
        return EXIT_OK if error.code in (0, None) else EXIT_CONFIG
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    return asyncio.run(run(args, connect=connect))


def console_entry() -> None:
    """Run the console command and return its result to the operating system."""
    sys.exit(main())
