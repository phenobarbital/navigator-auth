"""MFA enforcement pre-flight for one tenant (FEAT-106, spec §3 Module 12).

    python -m scripts.preflight_mfa --org-id N [--dsn DSN]

Exit 0 only when the tenant can be switched to ``enforced`` without locking
anyone out. Exit 1, listing offenders, on either blocking condition:

  B1  active members with no usable e-mail address (they would have NO factor)
  B2  active superusers with no strong factor (no confirmed TOTP, no passkey)

Exit 2 on an operational error. It cannot detect an address that is merely
WRONG: there is no e-mail verification state (spec R4).
"""
import argparse
import asyncio
import logging
import sys
from typing import Any, Optional, Sequence

from asyncdb import AsyncPool
from pydantic import BaseModel, ConfigDict

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, default_dsn
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.migrations import mfa_tables_present
from navigator_auth.mfa.state import MfaStateMachine, usable_email

logger = logging.getLogger("navigator.mfa.preflight")

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2

_MEMBERSHIP = f"{AUTH_DB_SCHEMA}.organization_users"
_USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"
_MEMBERS_SQL = (
    f"SELECT u.user_id, u.username, u.email, u.is_superuser, u.is_active "
    f"FROM {_MEMBERSHIP} ou JOIN {_USERS} u ON u.user_id = ou.user_id "
    "WHERE ou.org_id = $1 AND u.is_active ORDER BY u.user_id"
)


class PreflightError(Exception):
    """Operational failure: the pre-flight could not decide (exit 2)."""


class Offender(BaseModel):
    """A member that blocks enforcement."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    user_id: int
    username: str


class PreflightReport(BaseModel):
    """Result of the pre-flight for one tenant."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    org_id: int
    members: int
    missing_email: tuple[Offender, ...]  # B1
    superusers_without_strong_factor: tuple[Offender, ...]  # B2

    @property
    def ok(self) -> bool:
        """True only when neither blocking condition has an offender."""
        return not self.missing_email and not self.superusers_without_strong_factor


async def run_preflight(
    db_pool: Any, org_id: int, *, state: Optional[MfaStateMachine] = None
) -> PreflightReport:
    """Evaluate B1/B2 for every ACTIVE member of ``org_id``.

    Args:
        db_pool: connected asyncdb pool.
        org_id: tenant to check (> 0).
        state: injectable state machine (tests); defaults to MfaStateMachine(db_pool).

    Returns:
        The report with both offender lists.

    Raises:
        PreflightError: MFA tables missing, organization_users missing, or a storage error.
    """
    if org_id <= 0:
        raise PreflightError("org_id must be a positive integer")
    try:
        if not await mfa_tables_present(db_pool):
            raise PreflightError(
                "MFA tables missing — start the service once with AUTH_BASIC_2FA_ENABLED=true"
            )
        async with await db_pool.acquire() as conn:
            if await conn.fetchval("SELECT to_regclass($1)", _MEMBERSHIP) is None:
                raise PreflightError("organization_users not found")
            rows = await conn.fetch_all(_MEMBERS_SQL, org_id) or []
            state = state or MfaStateMachine(db_pool)
            missing: list[Offender] = []
            weak: list[Offender] = []
            for raw in rows:
                row = dict(raw)
                offender = Offender(user_id=int(row["user_id"]), username=str(row["username"]))
                if usable_email(row) is None:
                    missing.append(offender)
                if row.get("is_superuser") and not await state.has_strong_factor(row):
                    weak.append(offender)
    except PreflightError:
        raise
    except MfaStorageError as err:
        raise PreflightError(f"storage error: {err}") from err
    except Exception as err:  # pylint: disable=W0703
        raise PreflightError(f"storage error: {type(err).__name__}") from err
    return PreflightReport(
        org_id=org_id,
        members=len(rows),
        missing_email=tuple(sorted(missing, key=lambda o: o.user_id)),
        superusers_without_strong_factor=tuple(sorted(weak, key=lambda o: o.user_id)),
    )


def _emit(line: str = "") -> None:
    """The report is the CLI's product: write it to stdout."""
    sys.stdout.write(f"{line}\n")


def render_report(report: PreflightReport) -> None:
    """Human-readable report; offenders listed per blocking condition."""
    _emit(f"MFA pre-flight for org_id={report.org_id}: {report.members} active member(s)")
    _emit("(inactive users cannot log in and are excluded)")
    sections = (
        ("B1 — no usable e-mail address (no factor under enforcement)", report.missing_email),
        (
            "B2 — superuser without a strong factor (enrol TOTP or register a passkey first)",
            report.superusers_without_strong_factor,
        ),
    )
    for title, offenders in sections:
        _emit(f"{title}: {len(offenders)}")
        for off in offenders:
            _emit(f"  - user_id={off.user_id} username={off.username}")
    _emit("RESULT: OK — tenant can be enforced" if report.ok else "RESULT: BLOCKED")
    _emit("Note: addresses are not verified; a wrong address cannot be detected (R4).")


def _parse(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.preflight_mfa",
        description="Refuse MFA enforcement for a tenant that would lock users out.",
    )
    parser.add_argument("--org-id", type=int, required=True, help="Tenant (organization) id")
    parser.add_argument(
        "--dsn", default=None, help="Postgres DSN (default: navigator_auth.conf.default_dsn)"
    )
    return parser.parse_args(argv)


async def _amain(args: argparse.Namespace) -> int:
    pool = AsyncPool("pg", dsn=args.dsn or default_dsn, timeout=10)
    connected = False
    try:
        await pool.connect()
        connected = True
        report = await run_preflight(pool, args.org_id)
    except PreflightError as err:
        logger.error("MFA pre-flight could not run: %s", err)
        _emit(f"ERROR: {err}")
        return EXIT_ERROR
    except Exception as err:  # pylint: disable=W0703
        logger.error("MFA pre-flight failed: %s", type(err).__name__)
        _emit(f"ERROR: {type(err).__name__}")
        return EXIT_ERROR
    finally:
        if connected:
            try:
                await pool.wait_close(gracefully=True, timeout=2)
            except Exception as err:  # pylint: disable=W0703
                logger.warning("Could not close pool: %s", type(err).__name__)
    render_report(report)
    return EXIT_OK if report.ok else EXIT_BLOCKED


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns the process exit code (0 ok, 1 blocked, 2 error)."""
    return asyncio.run(_amain(_parse(argv)))


if __name__ == "__main__":
    sys.exit(main())
