"""Pre-flight — FEAT-106 spec §3 Module 12 (TASK-146). No live DB: fakes only."""
import pytest

import scripts.preflight_mfa as preflight
from scripts.preflight_mfa import (
    EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, Offender, PreflightError, PreflightReport, run_preflight,
)


class _Conn:
    def __init__(self, rows, membership_table="auth.organization_users"):
        self.rows, self.membership_table = rows, membership_table

    async def fetchval(self, sql, *args):
        assert "to_regclass" in sql
        return self.membership_table

    async def fetch_all(self, sql, *args):
        return self.rows or None  # asyncdb returns None on no rows


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    async def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _State:
    """Stands in for MfaStateMachine: strong users by id."""

    def __init__(self, strong_ids=()):
        self.strong_ids = set(strong_ids)

    async def has_strong_factor(self, user, *, conn=None):
        return int(user["user_id"]) in self.strong_ids


def _row(uid, email="u@example.com", su=False):
    return {"user_id": uid, "username": f"user{uid}", "email": email,
            "is_superuser": su, "is_active": True}


@pytest.fixture(autouse=True)
def _tables_present(monkeypatch):
    async def _present(_pool):
        return True
    monkeypatch.setattr(preflight, "mfa_tables_present", _present)


@pytest.mark.asyncio
async def test_preflight_blocks_users_without_email():
    """B1: a member with no address is listed; report.ok is False."""
    rows = [_row(1), _row(2, email=None), _row(3, email="  ")]
    report = await run_preflight(_Pool(_Conn(rows)), 5, state=_State())
    assert [o.user_id for o in report.missing_email] == [2, 3]
    assert report.members == 3
    assert not report.ok


@pytest.mark.asyncio
async def test_preflight_blocks_superuser_without_strong_factor():
    """B2: a superuser without TOTP/passkey is listed; one with a passkey is not."""
    rows = [_row(10, su=True), _row(11, su=True)]
    report = await run_preflight(_Pool(_Conn(rows)), 5, state=_State(strong_ids={11}))
    assert [o.user_id for o in report.superusers_without_strong_factor] == [10]
    assert not report.ok


@pytest.mark.asyncio
async def test_preflight_passes_clean_tenant():
    rows = [_row(1), _row(2, su=True)]
    report = await run_preflight(_Pool(_Conn(rows)), 5, state=_State(strong_ids={2}))
    assert report.ok


@pytest.mark.asyncio
async def test_preflight_missing_membership_table_is_error():
    with pytest.raises(PreflightError):
        await run_preflight(_Pool(_Conn([_row(1)], membership_table=None)), 5, state=_State())


@pytest.mark.asyncio
async def test_preflight_missing_mfa_tables_is_error(monkeypatch):
    async def _absent(_pool):
        return False
    monkeypatch.setattr(preflight, "mfa_tables_present", _absent)
    with pytest.raises(PreflightError):
        await run_preflight(_Pool(_Conn([])), 5, state=_State())


class _StubAsyncPool:
    def __init__(self, *a, **kw):
        pass

    async def connect(self):
        return None

    async def wait_close(self, **kw):
        return None


def _report(missing=(), weak=()):
    return PreflightReport(
        org_id=5, members=3,
        missing_email=tuple(Offender(user_id=i, username=f"user{i}") for i in missing),
        superusers_without_strong_factor=tuple(
            Offender(user_id=i, username=f"user{i}") for i in weak),
    )


def test_main_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(preflight, "AsyncPool", _StubAsyncPool)

    async def _blocked(*a, **kw):
        return _report(missing=[2], weak=[10])
    monkeypatch.setattr(preflight, "run_preflight", _blocked)
    assert preflight.main(["--org-id", "5"]) == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "user_id=2 username=user2" in out
    assert "user_id=10 username=user10" in out
    assert "@" not in out.replace("(R4)", "")

    async def _clean(*a, **kw):
        return _report()
    monkeypatch.setattr(preflight, "run_preflight", _clean)
    assert preflight.main(["--org-id", "5"]) == EXIT_OK
    capsys.readouterr()

    async def _boom(*a, **kw):
        raise PreflightError("organization_users not found")
    monkeypatch.setattr(preflight, "run_preflight", _boom)
    assert preflight.main(["--org-id", "5"]) == EXIT_ERROR


def test_report_mentions_unverified_addresses(capsys):
    preflight.render_report(_report())
    assert "(R4)" in capsys.readouterr().out
