"""Policy resolver, apply_tenant_policy and MfaStateMachine — FEAT-106 M7 (TASK-135)."""

import inspect
import secrets
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.exceptions import MFARefused
from navigator_auth.mfa import policy as policy_mod
from navigator_auth.mfa import trusted_devices as td_mod
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.policy import (
    MfaPolicyResolver,
    NO_TENANT_POLICY,
    apply_tenant_policy,
    combine_policies,
    is_hardening,
)
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.services import MfaServices
from navigator_auth.mfa.state import MfaStateMachine, usable_email
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.mfa.types import MfaMode, MfaState, TenantMfaPolicy
from tests.fixtures.mfa import (  # noqa: F401
    MFA_TEST_SECRET,
    mfa_db,
    mfa_policy_enforced,
    mfa_user_factory,
)


class _ScriptedConn:
    """Fake asyncdb connection: answers by SQL substring; mutable between calls."""

    def __init__(self, answers: dict, fail: bool = False):
        self.answers, self.fail, self.calls = answers, fail, []

    async def _answer(self, sql, *args):
        self.calls.append((sql, args))
        if self.fail:
            raise ConnectionError("db down")
        for needle, value in self.answers.items():
            if needle in sql:
                return value(*args) if callable(value) else value
        raise AssertionError(f"unscripted SQL: {sql}")

    fetchval = fetch_one = fetch_all = _answer


class _ScriptedPool:
    def __init__(self, conn):
        self.conn = conn

    async def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


def _p(org, mode, days=0):
    return TenantMfaPolicy(org_id=org, mode=mode, remember_days=days, enforced_at=None, enforced_by=None)


def _row(org, mode, days=0):
    return {"org_id": org, "mode": mode, "remember_days": days, "enforced_at": None, "enforced_by": None}


def _machine(totp=False, passkeys=0, passkey_table=True, fail_count=False):
    def _count(*_a):
        if fail_count:
            raise ConnectionError("boom")
        return passkeys

    answers = {
        "FROM auth.user_mfa ": totp,
        "to_regclass": "auth.user_credentials" if passkey_table else None,
        "count(*)": _count,
    }
    conn = _ScriptedConn(answers)
    return MfaStateMachine(_ScriptedPool(conn)), conn


USER = {"user_id": 7, "is_superuser": False, "email": "u@example.com"}
SUPER = {"user_id": 8, "is_superuser": True, "email": "s@example.com"}


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", list(MfaMode))
@pytest.mark.parametrize("totp,passkeys", [(True, 0), (False, 1), (False, 0)])
@pytest.mark.parametrize("superuser", [False, True])
async def test_evaluation_reads_factor_facts_once(mode: MfaMode, totp: bool, passkeys: int, superuser: bool) -> None:
    """Real state methods share DB reads while preserving the policy matrix."""
    machine, conn = _machine(totp=totp, passkeys=passkeys)
    backup = SimpleNamespace(remaining=AsyncMock(return_value=2))
    machine._backup = backup
    policy = _p(5, mode)
    security = SimpleNamespace(current_version=AsyncMock(return_value=1), context_digest=Mock(return_value="digest"))
    services = MfaServices(
        backend=object(),
        available=True,
        state=machine,
        security=security,
        resolver=SimpleNamespace(memberships=AsyncMock(return_value=[5]), effective=AsyncMock(return_value=policy)),
    )
    user = SUPER if superuser else USER
    if superuser and mode == MfaMode.ENFORCED and not (totp or passkeys):
        with pytest.raises(MFARefused):
            await services.evaluate(user, conn=conn)
        backup.remaining.assert_not_awaited()
    else:
        result = await services.evaluate(user, conn=conn)
        expected_state = MfaState.TOTP if totp else MfaState.EMAIL if mode == MfaMode.ENFORCED else MfaState.NONE
        assert result.state == expected_state
        assert result.has_strong_factor is bool(totp or passkeys)
        expected = (["totp"] if totp else ["email"] if mode == MfaMode.ENFORCED and not passkeys else []) + ["backup"]
        assert result.providers == tuple(expected)
        backup.remaining.assert_awaited_once_with(user["user_id"], conn=conn)
        assert security.context_digest.call_args.kwargs["state"] == expected_state
    assert sum("FROM auth.user_mfa " in sql for sql, _ in conn.calls) == 1
    assert sum("to_regclass" in sql for sql, _ in conn.calls) == (0 if totp else 1)
    assert sum("count(*)" in sql for sql, _ in conn.calls) == (0 if totp else 1)


@pytest.mark.asyncio
async def test_factor_facts_are_not_cached_between_evaluations() -> None:
    """A removed passkey is observed in the very next facts read."""
    machine, conn = _machine(totp=False, passkeys=1)
    first = await machine.factor_facts(USER, conn=conn)
    conn.answers["count(*)"] = 0
    second = await machine.factor_facts(USER, conn=conn)
    assert first.has_strong_factor
    assert not second.has_strong_factor
    assert len(conn.calls) == 6


def test_policy_strictest_org_wins():
    """enforced + optional => enforced; smallest remember_days among non-OFF wins (D9)."""
    out = combine_policies([_p(5, MfaMode.OPTIONAL, 30), _p(7, MfaMode.ENFORCED, 14), _p(9, MfaMode.OFF, 1)])
    assert out.mode == MfaMode.ENFORCED and out.org_id == 7 and out.remember_days == 14
    assert combine_policies([]) == NO_TENANT_POLICY
    tie = combine_policies([_p(9, MfaMode.ENFORCED, 5), _p(3, MfaMode.ENFORCED, 9)])
    assert tie.org_id == 3 and tie.remember_days == 5


def test_is_hardening_directions():
    assert is_hardening(_p(1, MfaMode.OFF), _p(1, MfaMode.ENFORCED))
    assert not is_hardening(_p(1, MfaMode.ENFORCED), _p(1, MfaMode.OPTIONAL))
    assert is_hardening(_p(1, MfaMode.ENFORCED, 30), _p(1, MfaMode.ENFORCED, 14))
    assert not is_hardening(_p(1, MfaMode.ENFORCED, 30), _p(1, MfaMode.OFF, 0))


def test_membership_table_constant_matches_trusted_devices():
    assert policy_mod.ORG_MEMBERSHIP_TABLE == td_mod._ORG_MEMBERSHIP_TABLE


def test_resolver_ignores_tenant_headers():
    """R14/AC22: no request parameter, no _resolve_tenant reference."""
    assert "request" not in inspect.signature(MfaPolicyResolver.effective).parameters
    source = Path(policy_mod.__file__).read_text()
    assert "_resolve_tenant" not in source and "X-Org-Id" not in source


@pytest.mark.asyncio
async def test_policy_read_is_per_login_not_cached():
    """Changing the scripted row between two calls changes the second result."""
    rows = [_row(5, "off")]
    conn = _ScriptedConn(
        {
            "to_regclass": "auth.organization_users",
            "FROM auth.organization_users": [{"org_id": 5}],
            "tenant_mfa_policy": lambda *_a: rows,
        }
    )
    resolver = MfaPolicyResolver(_ScriptedPool(conn))
    assert (await resolver.effective(USER)).mode == MfaMode.OFF
    rows[:] = [_row(5, "enforced", 10)]
    assert (await resolver.effective(USER)).mode == MfaMode.ENFORCED


@pytest.mark.asyncio
async def test_policy_read_failure_fails_closed():
    """A storage error raises MfaStorageError — never returns OFF."""
    resolver = MfaPolicyResolver(_ScriptedPool(_ScriptedConn({}, fail=True)))
    with pytest.raises(MfaStorageError):
        await resolver.effective(USER)


@pytest.mark.asyncio
async def test_missing_membership_table_is_no_tenant():
    conn = _ScriptedConn({"to_regclass": None})
    out = await MfaPolicyResolver(_ScriptedPool(conn)).effective(USER)
    assert out == NO_TENANT_POLICY
    assert not any("tenant_mfa_policy" in sql for sql, _ in conn.calls)


@pytest.mark.asyncio
async def test_enforced_floor_is_email_without_enrolment(mfa_policy_enforced):
    """Ordinary unenrolled user -> EMAIL; providers == ['email'] when an address exists."""
    sm, _ = _machine(totp=False, passkey_table=False)
    assert await sm.state_of(USER, mfa_policy_enforced) == MfaState.EMAIL
    assert await sm.available_providers(USER, mfa_policy_enforced) == (["email"], "email")
    no_mail = dict(USER, email="")
    assert await sm.available_providers(no_mail, mfa_policy_enforced) == ([], None)


@pytest.mark.asyncio
async def test_superuser_without_strong_factor_denied(mfa_policy_enforced):
    """is_superuser + ENFORCED + no strong factor -> MFARefused('strong_factor_required')."""
    sm, _ = _machine(totp=False, passkey_table=False)
    with pytest.raises(MFARefused) as exc:
        await sm.state_of(SUPER, mfa_policy_enforced)
    assert exc.value.payload()["error"] == "strong_factor_required"
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_strong_factor_closes_email(mfa_policy_enforced):
    """Confirmed TOTP => 'email' absent, preferred 'totp' (AC9)."""
    sm, _ = _machine(totp=True)
    assert await sm.state_of(USER, mfa_policy_enforced) == MfaState.TOTP
    assert await sm.available_providers(USER, mfa_policy_enforced) == (["totp"], "totp")


@pytest.mark.asyncio
async def test_registered_passkey_closes_email(mfa_policy_enforced):
    """A passkey credential closes e-mail symmetrically (AC9)."""
    sm, _ = _machine(totp=False, passkeys=1)
    providers, preferred = await sm.available_providers(USER, mfa_policy_enforced)
    assert "email" not in providers and preferred is None
    assert await sm.has_strong_factor(USER)
    # a passkey satisfies the enforced-superuser invariant
    assert await sm.state_of(SUPER, mfa_policy_enforced) == MfaState.EMAIL


@pytest.mark.asyncio
async def test_requires_strong_factor_for_superuser(mfa_policy_enforced):
    sm, _ = _machine()
    assert await sm.requires_strong_factor(SUPER, mfa_policy_enforced)
    assert not await sm.requires_strong_factor(SUPER, _p(5, MfaMode.OPTIONAL))
    assert not await sm.requires_strong_factor(USER, mfa_policy_enforced)


@pytest.mark.asyncio
async def test_deleting_last_passkey_reopens_email(mfa_policy_enforced):
    """Ordinary user, no TOTP: passkey count 1 -> 0 between calls reopens 'email' (AC27 core)."""
    count = [1]
    conn = _ScriptedConn(
        {
            "FROM auth.user_mfa ": False,
            "to_regclass": "auth.user_credentials",
            "count(*)": lambda *_a: count[0],
        }
    )
    sm = MfaStateMachine(_ScriptedPool(conn))
    assert "email" not in (await sm.available_providers(USER, mfa_policy_enforced))[0]
    count[0] = 0
    assert (await sm.available_providers(USER, mfa_policy_enforced))[0] == ["email"]


@pytest.mark.asyncio
async def test_passkey_count_error_is_not_zero():
    """A failing count query raises MfaStorageError instead of reading as 'no passkey'."""
    sm, _ = _machine(fail_count=True)
    with pytest.raises(MfaStorageError):
        await sm.passkey_count(7)


def test_usable_email_rules():
    for bad in ("", None, "nobody", "a@", "@b.c", "a@@b.c"):
        assert usable_email({"user_id": 1, "email": bad}) is None
    assert usable_email({"user_id": 1, "email": " a@b.c "}) == "a@b.c"


async def _org_member(pool, user_id: int) -> int:
    """Create an owned organization before inserting its foreign-key membership."""
    async with await pool.acquire() as conn:
        slug = f"mfa-facts-{secrets.token_hex(8)}"
        org_id = await conn.fetchval(
            f"INSERT INTO {AUTH_DB_SCHEMA}.organizations (organization, org_slug) VALUES ($1, $2) RETURNING org_id",
            slug,
            slug,
        )
        await conn.fetchval(
            f"INSERT INTO {AUTH_DB_SCHEMA}.organization_users (user_id, org_id) VALUES ($1, $2) RETURNING user_id",
            user_id,
            org_id,
        )
        return org_id


async def _cleanup(pool, user_id: int, org_id: int):
    async with await pool.acquire() as conn:
        await conn.fetchval(
            f"WITH d AS (DELETE FROM {AUTH_DB_SCHEMA}.organization_users "
            "WHERE user_id = $1 AND org_id = $2 RETURNING 1) SELECT count(*) FROM d",
            user_id,
            org_id,
        )
        await conn.fetchval(
            f"WITH d AS (DELETE FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE org_id = $1 RETURNING 1) SELECT count(*) FROM d",
            org_id,
        )
        await conn.fetchval(
            f"WITH d AS (DELETE FROM {AUTH_DB_SCHEMA}.tenant_mfa_policy WHERE org_id = $1 RETURNING 1) "
            "SELECT count(*) FROM d",
            org_id,
        )
        await conn.fetchval(
            f"DELETE FROM {AUTH_DB_SCHEMA}.organizations WHERE org_id = $1 RETURNING org_id",
            org_id,
        )


async def _audit_count(pool, org_id: int) -> int:
    async with await pool.acquire() as conn:
        return int(
            await conn.fetchval(
                f"SELECT count(*) FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE org_id = $1 "
                "AND action = 'policy_change'",
                org_id,
            )
        )


@pytest.mark.asyncio
async def test_apply_tenant_policy_hardening_revokes_and_audits(mfa_db, mfa_user_factory):
    """Live PG: OFF->ENFORCED bumps member versions, revokes their devices, writes one audit row."""
    user = await mfa_user_factory()
    org_id = await _org_member(mfa_db, user["user_id"])
    security = MfaSecurity(mfa_db, MFA_TEST_SECRET)
    devices = TrustedDeviceStore(mfa_db)
    try:
        await devices.issue(user["user_id"], 30, "t")
        async with await mfa_db.acquire() as conn:
            before = await security.current_version(conn, user["user_id"])
        try:
            out = await apply_tenant_policy(
                db_pool=mfa_db,
                security=security,
                trusted_devices=devices,
                org_id=org_id,
                mode=MfaMode.ENFORCED,
                remember_days=14,
                actor="test",
            )
            assert out.mode == MfaMode.ENFORCED and out.enforced_at is not None
            async with await mfa_db.acquire() as conn:
                after = await security.current_version(conn, user["user_id"])
            assert after > before
            assert await devices.list_active(user["user_id"]) == []
            assert await _audit_count(mfa_db, org_id) == 1
        finally:
            pass
    finally:
        await _cleanup(mfa_db, user["user_id"], org_id)


@pytest.mark.asyncio
async def test_apply_tenant_policy_relaxing_does_not_revoke(mfa_db, mfa_user_factory):
    """ENFORCED->OPTIONAL: device still live, versions unchanged, one audit row (AC18)."""
    user = await mfa_user_factory()
    org_id = await _org_member(mfa_db, user["user_id"])
    security = MfaSecurity(mfa_db, MFA_TEST_SECRET)
    devices = TrustedDeviceStore(mfa_db)
    try:
        await apply_tenant_policy(
            db_pool=mfa_db,
            security=security,
            trusted_devices=devices,
            org_id=org_id,
            mode=MfaMode.ENFORCED,
            remember_days=14,
            actor="test",
        )
        await devices.issue(user["user_id"], 30, "t")
        async with await mfa_db.acquire() as conn:
            before = await security.current_version(conn, user["user_id"])
        await apply_tenant_policy(
            db_pool=mfa_db,
            security=security,
            trusted_devices=devices,
            org_id=org_id,
            mode=MfaMode.OPTIONAL,
            remember_days=14,
            actor="test",
        )
        async with await mfa_db.acquire() as conn:
            after = await security.current_version(conn, user["user_id"])
        assert after == before
        assert len(await devices.list_active(user["user_id"])) == 1
        assert await _audit_count(mfa_db, org_id) == 2
    finally:
        await _cleanup(mfa_db, user["user_id"], org_id)
