# ruff: noqa: F811
"""FEAT-106 TASK-142 — administrative disenrolment: permission, tenant scope, narrow effect."""

import json
import secrets
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

import navigator_auth.handlers.mfa as mfa_handlers
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_EXCLUDE_LIST_KEY
from navigator_auth.exceptions import MFARefused, UserNotFound
from navigator_auth.handlers.mfa import MFA_PREFIX, MfaHandler, setup_mfa_routes
from navigator_auth.mfa.backup_codes import BackupCodeStore
from navigator_auth.mfa.policy import MfaPolicyResolver
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServicesSlot
from navigator_auth.mfa.state import MfaStateMachine
from navigator_auth.mfa.totp import TOTPProvider
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.mfa.types import PROVIDER_TOTP
from navigator_session import AUTH_SESSION_OBJECT
from tests.fixtures.mfa import (  # noqa: F401
    mfa_db,
    mfa_policy_enforced,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
)

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]

USERS = f"{AUTH_DB_SCHEMA}.users"
USER_MFA = f"{AUTH_DB_SCHEMA}.user_mfa"
AUDIT = f"{AUTH_DB_SCHEMA}.user_mfa_audit"
VAULT = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"  # FEAT-106 review fix #2: seeds moved out of the user vault (spec M7)
ORGS = f"{AUTH_DB_SCHEMA}.organizations"
ORG_USERS = f"{AUTH_DB_SCHEMA}.organization_users"
PASSKEYS = f"{AUTH_DB_SCHEMA}.user_credentials"
DENIED_BODY = {"error": "forbidden"}


class Env:
    """Real MFA stores over the live test database, acting as one authenticated admin."""

    def __init__(self, db, services, monkeypatch) -> None:
        self.db = db
        self.services = services
        self.monkeypatch = monkeypatch
        self.app = web.Application()
        self.app[MFA_APP_KEY] = MfaServicesSlot(services)
        self.handler = MfaHandler()
        self.orgs: list[int] = []
        self.actor_id = 0
        self.notices: list = []

        async def _notify(notice):
            self.notices.append(notice)

        monkeypatch.setattr(mfa_handlers, "notify_security_event", _notify)

    def act_as(self, user: dict) -> None:
        """Authenticate subsequent calls as ``user``."""
        self.actor_id = user["user_id"]

        async def _get_session(request, new=False):
            return {AUTH_SESSION_OBJECT: {"user_id": user["user_id"]}}

        self.monkeypatch.setattr(mfa_handlers, "get_session", _get_session)

    async def delete(self, target_id: int):
        """Call ``DELETE /auth/mfa/{target_id}`` and return ``(response, body, request)``."""
        request = SimpleNamespace(
            app=self.app,
            match_info={"user_id": str(target_id)},
            path=f"{MFA_PREFIX}/{target_id}",
            get=lambda key, default=None: True if key == "authenticated" else default,
            remote="127.0.0.1",
        )
        self.request = request
        response = await self.handler.admin_disenroll(request)
        return response, json.loads(response.body)

    async def one(self, sql: str, *args):
        async with await self.db.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def row(self, sql: str, *args):
        async with await self.db.acquire() as conn:
            row = await conn.fetch_one(sql, *args)
            return dict(row) if row else None

    async def rows(self, sql: str, *args):
        async with await self.db.acquire() as conn:
            return [dict(r) for r in (await conn.fetch_all(sql, *args) or [])]

    async def make_org(self, *members: int) -> int:
        """Create an organization with the given member user ids."""
        slug = f"mfa-t142-{secrets.token_hex(4)}"
        org_id = await self.one(
            f"INSERT INTO {ORGS} (organization, org_slug) VALUES ($1, $2) RETURNING org_id", slug, slug
        )
        self.orgs.append(org_id)
        for user_id in members:
            await self.join(user_id, org_id)
        return org_id

    async def join(self, user_id: int, org_id: int) -> None:
        await self.one(f"INSERT INTO {ORG_USERS} (user_id, org_id) VALUES ($1, $2) RETURNING user_id", user_id, org_id)

    async def enroll_totp(self, user_id: int) -> None:
        """Install a confirmed TOTP row, a vault seed row, backup codes and one trusted device."""
        await self.one(
            f"INSERT INTO {USER_MFA} (user_id, provider, enabled, confirmed_at) "
            "VALUES ($1, 'totp', true, now()) ON CONFLICT (user_id, provider) "
            "DO UPDATE SET enabled = true, confirmed_at = now() RETURNING user_id",
            user_id,
        )
        if await self.one("SELECT to_regclass($1)", VAULT) is not None:
            await self.one(
                f"INSERT INTO {VAULT} (user_id, provider, key, ciphertext_db) VALUES ($1, 'totp', 'mfa:totp', $2) RETURNING 1",
                user_id,
                b"sealed-test-seed",
            )
        await self.services.backup_codes.generate(user_id)

    async def issue_device(self, user_id: int) -> str:
        return await self.services.trusted_devices.issue(user_id, 30, "laptop")

    async def audit_rows(self, target_id: int, outcome: str | None = None) -> list[dict]:
        sql = f"SELECT * FROM {AUDIT} WHERE target_user_id = $1 AND action = 'admin_disenroll'"
        if outcome:
            return await self.rows(sql + " AND outcome = $2 ORDER BY id", target_id, outcome)
        return await self.rows(sql + " ORDER BY id", target_id)

    async def snapshot(self, user_id: int) -> dict:
        user = await self.row(
            f"SELECT password, email, is_superuser, is_active FROM {USERS} WHERE user_id = $1", user_id
        )
        passkeys = 0
        if await self.one("SELECT to_regclass($1)", PASSKEYS) is not None:
            passkeys = await self.one(f"SELECT count(*) FROM {PASSKEYS} WHERE user_id = $1", user_id)
        return {"user": user, "passkeys": passkeys}

    async def totp_enabled(self, user_id: int) -> bool:
        return bool(
            await self.one(
                f"SELECT EXISTS (SELECT 1 FROM {USER_MFA} WHERE user_id = $1 AND provider = 'totp' "
                "AND enabled AND confirmed_at IS NOT NULL)",
                user_id,
            )
        )

    async def cleanup(self, target_ids: list[int]) -> None:
        if target_ids:
            await self.one(
                f"WITH d AS (DELETE FROM {AUDIT} WHERE target_user_id = ANY($1::bigint[]) OR actor_user_id = ANY($1::bigint[]) "
                "RETURNING 1) SELECT count(*) FROM d",
                target_ids,
            )
            if await self.one("SELECT to_regclass($1)", VAULT) is not None:
                await self.one(
                    f"WITH d AS (DELETE FROM {VAULT} WHERE user_id = ANY($1::int[]) AND key = 'mfa:totp' RETURNING 1) "
                    "SELECT count(*) FROM d",
                    target_ids,
                )
        if self.orgs:
            await self.one(
                f"WITH d AS (DELETE FROM {ORGS} WHERE org_id = ANY($1::bigint[]) RETURNING 1) SELECT count(*) FROM d",
                self.orgs,
            )


@pytest_asyncio.fixture
async def env(mfa_db, mfa_redis_pool, mfa_secret, monkeypatch):  # noqa: F811
    """Build real stores over the test database and clean every row afterwards."""

    class Idp:
        async def user_from_id(self, uid):
            async with await mfa_db.acquire() as conn:
                row = await conn.fetch_one(f"SELECT * FROM {USERS} WHERE user_id = $1", int(uid))
            if row is None:
                raise UserNotFound(f"user {uid}")
            return dict(row)

    backup = BackupCodeStore(mfa_db, mfa_secret)
    services = SimpleNamespace(
        available=True,
        backend=SimpleNamespace(_idp=Idp()),
        db_pool=mfa_db,
        security=MfaSecurity(mfa_db, mfa_secret),
        resolver=MfaPolicyResolver(mfa_db),
        backup_codes=backup,
        state=MfaStateMachine(mfa_db, backup_codes=backup),
        trusted_devices=TrustedDeviceStore(mfa_db),
        providers={PROVIDER_TOTP: TOTPProvider(app=None, db_pool=mfa_db, store=None)},
    )
    environment = Env(mfa_db, services, monkeypatch)
    environment.touched = []
    yield environment
    await environment.cleanup(environment.touched)


@pytest.fixture
def allow_abac(monkeypatch):
    """Grant ``mfa:disenroll`` through a stubbed PDP."""
    stub = AsyncMock(return_value=(True, "ok", None))
    monkeypatch.setattr(mfa_handlers, "policy_allows", stub)
    return stub


@pytest.fixture
def deny_abac(monkeypatch):
    """Refuse ``mfa:disenroll`` through a stubbed PDP."""
    stub = AsyncMock(return_value=(False, "denied", None))
    monkeypatch.setattr(mfa_handlers, "policy_allows", stub)
    return stub


async def _pair(env, mfa_user_factory, *, actor_orgs=(), target_orgs=(), enroll=True, target_super=False):
    """Create actor + enrolled target; the orgs are shared by index into ``env.orgs``."""
    actor = await mfa_user_factory(superuser=True)
    target = await mfa_user_factory(superuser=target_super)
    env.touched.extend([actor["user_id"], target["user_id"]])
    env.act_as(actor)
    if enroll:
        await env.enroll_totp(target["user_id"])
    return actor, target


@pytest.mark.asyncio
async def test_admin_disenroll_requires_mfa_action(env, mfa_user_factory, deny_abac):
    """A superuser without ``mfa:disenroll`` is refused and nothing changes (AC16)."""
    actor, target = await _pair(env, mfa_user_factory)
    org = await env.make_org(actor["user_id"], target["user_id"])
    assert org
    response, body = await env.delete(target["user_id"])
    assert response.status == 403
    assert body == {"error": "forbidden"}
    deny_abac.assert_awaited_once_with(
        "mfa_admin_access", env.request, action="mfa:disenroll", resource=f"/auth/mfa/{target['user_id']}"
    )
    assert await env.totp_enabled(target["user_id"])
    assert await env.services.backup_codes.remaining(target["user_id"]) > 0
    denied = await env.audit_rows(target["user_id"], "denied")
    assert len(denied) == 1
    assert denied[0]["actor_user_id"] == actor["user_id"]
    assert await env.audit_rows(target["user_id"], "success") == []
    assert env.notices == []


@pytest.mark.asyncio
async def test_admin_disenroll_rejects_foreign_tenant(env, mfa_user_factory, allow_abac):
    """The target's orgs must be a non-empty subset of the actor's (AC26)."""
    actor, target = await _pair(env, mfa_user_factory)
    org_a = await env.make_org(actor["user_id"])
    org_b = await env.make_org(target["user_id"])
    response, foreign_body = await env.delete(target["user_id"])
    assert response.status == 403
    assert await env.totp_enabled(target["user_id"])

    # Target in A+B, actor in A only: B never consented.
    await env.join(target["user_id"], org_a)
    response, body = await env.delete(target["user_id"])
    assert response.status == 403
    assert body == foreign_body
    assert await env.totp_enabled(target["user_id"])
    assert org_b

    # Target with no organization at all.
    loner = await mfa_user_factory()
    env.touched.append(loner["user_id"])
    await env.enroll_totp(loner["user_id"])
    response, body = await env.delete(loner["user_id"])
    assert response.status == 403
    assert body == foreign_body
    assert await env.totp_enabled(loner["user_id"])

    # Same body as an ABAC denial: no cross-tenant enumeration.
    assert foreign_body == DENIED_BODY
    reasons = [row["detail"] for row in await env.audit_rows(target["user_id"], "denied")]
    assert len(reasons) == 2


@pytest.mark.asyncio
async def test_admin_disenroll_revokes_trusted_devices(env, mfa_user_factory, allow_abac):
    """Disenrolment revokes every trusted device of the target (AC16, AC18)."""
    actor, target = await _pair(env, mfa_user_factory)
    await env.make_org(actor["user_id"], target["user_id"])
    token = await env.issue_device(target["user_id"])
    assert await env.services.trusted_devices.list_active(target["user_id"])
    response, _ = await env.delete(target["user_id"])
    assert response.status == 200
    assert await env.services.trusted_devices.consume_and_rotate(token, target["user_id"]) is None
    assert await env.services.trusted_devices.list_active(target["user_id"]) == []


@pytest.mark.asyncio
async def test_admin_disenroll_changes_nothing_but_otp(env, mfa_user_factory, allow_abac):
    """Only the OTP state changes: password, e-mail, flags and passkeys are untouched (AC16, D21)."""
    actor, target = await _pair(env, mfa_user_factory)
    await env.make_org(actor["user_id"], target["user_id"])
    before = await env.snapshot(target["user_id"])
    async with await env.db.acquire() as conn:
        version_before = await env.services.security.current_version(conn, target["user_id"])
    response, body = await env.delete(target["user_id"])
    assert response.status == 200
    assert body == {"status": "disenrolled", "user_id": target["user_id"]}
    assert await env.snapshot(target["user_id"]) == before
    assert not await env.totp_enabled(target["user_id"])
    if await env.one("SELECT to_regclass($1)", VAULT) is not None:
        live = await env.one(
            f"SELECT count(*) FROM {VAULT} WHERE user_id = $1 AND key = 'mfa:totp' AND deleted_at IS NULL",
            target["user_id"],
        )
        assert live == 0
    assert await env.services.backup_codes.remaining(target["user_id"]) == 0
    version_after = await env.one(
        f"SELECT version FROM {AUTH_DB_SCHEMA}.user_mfa_security WHERE user_id = $1", target["user_id"]
    )
    assert version_after == version_before + 1


@pytest.mark.asyncio
async def test_admin_disenroll_audits_actor_target_org(env, mfa_user_factory, allow_abac):
    """One success row names actor, target, the lowest shared org and the state change (AC23)."""
    actor, target = await _pair(env, mfa_user_factory)
    org_a = await env.make_org(actor["user_id"], target["user_id"])
    org_b = await env.make_org(actor["user_id"], target["user_id"])
    response, _ = await env.delete(target["user_id"])
    assert response.status == 200
    rows = await env.audit_rows(target["user_id"], "success")
    assert len(rows) == 1
    row = rows[0]
    assert row["actor_user_id"] == actor["user_id"]
    assert row["target_user_id"] == target["user_id"]
    assert row["org_id"] == min(org_a, org_b)
    assert (row["old_state"], row["new_state"], row["method"]) == ("totp", "none", "admin")
    detail = row["detail"] if isinstance(row["detail"], dict) else json.loads(row["detail"])
    assert detail["orgs"] == sorted([org_a, org_b])
    assert detail["backup_codes_invalidated"] > 0


@pytest.mark.asyncio
async def test_admin_disenroll_self_target_forbidden(env, mfa_user_factory, allow_abac):
    """An admin cannot strip their own second factor through the admin route."""
    actor, _ = await _pair(env, mfa_user_factory, enroll=False)
    await env.make_org(actor["user_id"])
    await env.enroll_totp(actor["user_id"])
    response, body = await env.delete(actor["user_id"])
    assert response.status == 403
    assert body == {"error": "self_disenroll_forbidden"}
    assert await env.totp_enabled(actor["user_id"])
    assert await env.services.backup_codes.remaining(actor["user_id"]) > 0
    allow_abac.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_disenroll_notifies_target(env, mfa_user_factory, allow_abac):
    """The target is notified exactly once, after the transaction committed (D6)."""
    actor, target = await _pair(env, mfa_user_factory)
    await env.make_org(actor["user_id"], target["user_id"])
    seen: list[tuple] = []

    async def _spy(notice):
        # A separate connection only sees committed rows.
        seen.append((notice, len(await env.audit_rows(target["user_id"], "success"))))

    env.monkeypatch.setattr(mfa_handlers, "notify_security_event", _spy)
    response, _ = await env.delete(target["user_id"])
    assert response.status == 200
    assert len(seen) == 1
    notice, committed_rows = seen[0]
    assert committed_rows == 1
    assert notice.event == "admin_disenrolled"
    assert notice.email == target["email"]
    assert notice.username == target["username"]
    assert notice.actor == actor["username"]


@pytest.mark.asyncio
async def test_admin_disenroll_enforced_superuser_target_blocks_basic_login(
    env, mfa_user_factory, allow_abac, mfa_policy_enforced
):
    """An enforced superuser who lost the only strong factor can no longer log in (AC33)."""
    actor, target = await _pair(env, mfa_user_factory, target_super=True)
    await env.make_org(actor["user_id"], target["user_id"])
    record = await env.services.backend._idp.user_from_id(target["user_id"])
    assert await env.services.state.has_strong_factor(record)
    response, _ = await env.delete(target["user_id"])
    assert response.status == 200
    record = await env.services.backend._idp.user_from_id(target["user_id"])
    if await env.services.state.passkey_count(target["user_id"]) == 0:
        with pytest.raises(MFARefused) as refused:
            await env.services.state.state_of(record, mfa_policy_enforced)
        assert refused.value.code == "strong_factor_required"


@pytest.mark.asyncio
async def test_admin_disenroll_route_does_not_capture_totp():
    """``DELETE /auth/mfa/totp`` keeps reaching ``disenroll_totp``; digits reach ``admin_disenroll``."""
    app = web.Application()
    app[AUTH_EXCLUDE_LIST_KEY] = []
    setup_mfa_routes(app, app.router)
    assert not any("user_id" in path for path in app[AUTH_EXCLUDE_LIST_KEY])

    totp = await app.router.resolve(make_mocked_request("DELETE", f"{MFA_PREFIX}/totp", app=app))
    assert totp.route.handler.__name__ == "disenroll_totp"
    user = await app.router.resolve(make_mocked_request("DELETE", f"{MFA_PREFIX}/42", app=app))
    assert user.route.handler.__name__ == "admin_disenroll"
    assert user["user_id"] == "42"
