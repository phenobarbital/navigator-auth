# ruff: noqa: F811
"""FEAT-106 TASK-141 — TOTP enrolment security (spec "Pending enrollment and replacement").

Every test drives the real ``MfaHandler`` enrolment methods against real stores
on live Postgres + Redis: ``MfaChallengeStore``, ``MfaSecurity``,
``TrustedDeviceStore``, ``BackupCodeStore``, ``MfaPolicyResolver``,
``MfaStateMachine`` and a ``TOTPProvider`` sealing seeds with a test vault
KeyRing. Only the session lookup and the security notification are stubbed.
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
import time
from types import SimpleNamespace

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from aiohttp import web
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from navigator_session import AUTH_SESSION_OBJECT
from navigator_session.vault import KeyRing

import navigator_auth.handlers.mfa as mfa_handlers
from navigator_auth.backends.idp import IdentityProvider
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_OTP_CHALLENGE_TTL
from navigator_auth.exceptions import UserNotFound
from navigator_auth.handlers.mfa import MfaHandler
from navigator_auth.mfa.backup_codes import BackupCodeStore
from navigator_auth.mfa.limiter import StrictRateLimiter
from navigator_auth.mfa.policy import MfaPolicyResolver, apply_tenant_policy
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.state import MfaStateMachine
from navigator_auth.mfa.store import ENROLL_KEY_PREFIX, ENROLLMENT_TTL, MfaChallengeStore
from navigator_auth.mfa.totp import TOTPProvider
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.mfa.types import PROVIDER_EMAIL, PROVIDER_TOTP, MfaMode
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY
from navigator_auth.vault.migrations import ensure_vault_tables
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
)

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]

USERS = f"{AUTH_DB_SCHEMA}.users"
AUDIT = f"{AUTH_DB_SCHEMA}.user_mfa_audit"
SECURITY = f"{AUTH_DB_SCHEMA}.user_mfa_security"
POLICY = f"{AUTH_DB_SCHEMA}.tenant_mfa_policy"
ORGS = f"{AUTH_DB_SCHEMA}.organizations"
ORG_USERS = f"{AUTH_DB_SCHEMA}.organization_users"
VAULT = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"  # FEAT-106 review fix #2: seeds moved out of the user vault (spec M7)
WRONG_CODE = "000000"


class Record(dict):
    """A user row readable both as a mapping and by attribute, like the IdP's model."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as err:
            raise AttributeError(name) from err


class FakeSession(dict):
    """The navigator_session surface the handler reads: id, int epoch, AUTH_SESSION_OBJECT."""

    def __init__(self, user_id: int, *, created: int | None = None, auth_method: str | None = None) -> None:
        data: dict = {"user_id": user_id}
        if auth_method:
            data["auth_method"] = auth_method
        super().__init__({AUTH_SESSION_OBJECT: data})
        self.session_id = secrets.token_hex(16)
        self.created = int(time.time()) if created is None else int(created)


class FakeRequest:
    """Just enough of ``web.Request`` for the enrolment handlers."""

    def __init__(self, app, user_id: int, body: dict, session, authenticated: bool = True) -> None:
        self.app = app
        self.remote = "127.0.0.1"
        self.user = SimpleNamespace(user_id=user_id)
        self.fake_session = session
        self._body = body
        self._state = {"authenticated": authenticated}

    def get(self, key, default=None):
        return self._state.get(key, default)

    async def json(self):
        return self._body


def _seed(secret_b32: str) -> bytes:
    return base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))


class Env:
    """Real MFA services over the live stores, plus helpers to drive the handler."""

    def __init__(self, db, redis_pool, services, clock, monkeypatch, factory) -> None:
        self.db = db
        self.factory = factory
        self.redis_pool = redis_pool
        self.services = services
        self.clock = clock
        self.monkeypatch = monkeypatch
        self.app = web.Application()
        self.app[MFA_APP_KEY] = MfaServicesSlot(services)
        self.handler = MfaHandler()
        self.notices: list = []
        self.users: list[int] = []
        self.orgs: list[int] = []

        async def _get_session(request, new=False):
            return getattr(request, "fake_session", None)

        async def _notify(notice):
            self.notices.append(notice)

        monkeypatch.setattr(mfa_handlers, "get_session", _get_session)
        monkeypatch.setattr(mfa_handlers, "notify_security_event", _notify)

    # -- driving the handler -------------------------------------------------
    async def call(self, method: str, user_id: int, body: dict, session=None, authenticated: bool = True):
        """Invoke ``MfaHandler.<method>`` and return ``(response, decoded_body)``."""
        request = FakeRequest(self.app, user_id, body, session or FakeSession(user_id), authenticated)
        response = await getattr(self.handler, method)(request)
        return response, json.loads(response.body)

    async def new_user(self, **kwargs) -> dict:
        user = await self.factory(**kwargs)
        self.users.append(user["user_id"])
        return user

    def code(self, secret_b32: str) -> tuple[str, int]:
        """Advance one TOTP step (dodging the replay guard) and return ``(code, step)``."""
        self.clock.advance(30)
        code = TOTP(_seed(secret_b32), 6, SHA1(), 30).generate(self.clock.now).decode()
        return code, int(self.clock.now) // 30

    async def enroll(self, user: dict, session, **extra):
        body = {"password": user["password_plain"], **extra}
        return await self.call("enroll_totp", user["user_id"], body, session)

    async def confirm(self, user: dict, session, token: str, code: str):
        body = {"enrollment_token": token, "code": code}
        return await self.call("confirm_totp", user["user_id"], body, session)

    async def enrolled_user(self, **kwargs) -> tuple[dict, FakeSession, str, list[str]]:
        """A user with a confirmed TOTP; returns ``(user, session, secret_b32, backup_codes)``."""
        user = await self.new_user(**kwargs)
        session = FakeSession(user["user_id"])
        response, started = await self.enroll(user, session)
        assert response.status == 201, started
        code, _ = self.code(started["secret_b32"])
        response, confirmed = await self.confirm(user, session, started["enrollment_token"], code)
        assert response.status == 200, confirmed
        return user, session, started["secret_b32"], confirmed["backup_codes"]

    # -- reading state -------------------------------------------------------
    async def one(self, sql: str, *args):
        async with await self.db.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def rows(self, sql: str, *args) -> list[dict]:
        async with await self.db.acquire() as conn:
            return [dict(r) for r in (await conn.fetch_all(sql, *args) or [])]

    async def active_seed_row(self, user_id: int):
        value = await self.one(
            f"SELECT ciphertext_db FROM {VAULT} WHERE user_id = $1 AND key = 'mfa:totp' AND deleted_at IS NULL",
            user_id,
        )
        return None if value is None else bytes(value)

    async def version(self, user_id: int) -> int:
        async with await self.db.acquire() as conn:
            return await self.services.security.current_version(conn, user_id)

    async def bump(self, user_id: int) -> None:
        async with self.services.security.user_lock(user_id) as conn:
            await self.services.security.bump_version(conn, user_id)

    async def audit(self, user_id: int, action: str | None = None) -> list[dict]:
        sql = f"SELECT * FROM {AUDIT} WHERE target_user_id = $1"
        if action:
            return await self.rows(sql + " AND action = $2 ORDER BY id", user_id, action)
        return await self.rows(sql + " ORDER BY id", user_id)

    async def pending_ttl_ms(self, token: str) -> int:
        async with aioredis.Redis(connection_pool=self.redis_pool) as redis:
            return await redis.pttl(f"{ENROLL_KEY_PREFIX}{hashlib.sha256(token.encode()).hexdigest()}")

    async def expire_pending(self, token: str) -> None:
        async with aioredis.Redis(connection_pool=self.redis_pool) as redis:
            await redis.delete(f"{ENROLL_KEY_PREFIX}{hashlib.sha256(token.encode()).hexdigest()}")

    async def enforced_org(self, *members: int) -> int:
        slug = f"mfa-t141-{secrets.token_hex(4)}"
        org_id = await self.one(
            f"INSERT INTO {ORGS} (organization, org_slug) VALUES ($1, $2) RETURNING org_id", slug, slug
        )
        self.orgs.append(org_id)
        for user_id in members:
            await self.one(
                f"INSERT INTO {ORG_USERS} (user_id, org_id) VALUES ($1, $2) RETURNING user_id", user_id, org_id
            )
        await apply_tenant_policy(
            db_pool=self.db,
            security=self.services.security,
            trusted_devices=self.services.trusted_devices,
            org_id=org_id,
            mode=MfaMode.ENFORCED,
            remember_days=0,
            actor="test-t141",
        )
        return org_id

    async def cleanup(self) -> None:
        if self.users:
            await self.one(
                f"WITH d AS (DELETE FROM {AUDIT} WHERE target_user_id = ANY($1::bigint[]) "
                "OR actor_user_id = ANY($1::bigint[]) RETURNING 1) SELECT count(*) FROM d",
                self.users,
            )
            await self.one(
                f"WITH d AS (DELETE FROM {VAULT} WHERE user_id = ANY($1::bigint[]) AND key = 'mfa:totp' "
                "RETURNING 1) SELECT count(*) FROM d",
                self.users,
            )
        if self.orgs:
            await self.one(
                f"WITH d AS (DELETE FROM {POLICY} WHERE org_id = ANY($1::bigint[]) RETURNING 1) SELECT count(*) FROM d",
                self.orgs,
            )
            await self.one(
                f"WITH d AS (DELETE FROM {ORGS} WHERE org_id = ANY($1::bigint[]) RETURNING 1) SELECT count(*) FROM d",
                self.orgs,
            )


@pytest_asyncio.fixture
async def env(mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock, monkeypatch):  # noqa: F811
    """Real services wired exactly like ``build_mfa_services``; every row is removed afterwards."""
    await ensure_vault_tables(mfa_db)

    class Idp:
        """The two IdP calls the handler makes, backed by the live users table."""

        check_password = IdentityProvider.check_password
        set_password = IdentityProvider.set_password

        async def user_from_id(self, uid):
            async with await mfa_db.acquire() as conn:
                row = await conn.fetch_one(f"SELECT * FROM {USERS} WHERE user_id = $1", int(uid))
            if row is None:
                raise UserNotFound(f"user {uid}")
            return Record(dict(row))

    keyring_app = {VAULT_KEYRING_APP_KEY: KeyRing({1: secrets.token_bytes(32)}, 1)}
    store = MfaChallengeStore(mfa_redis_pool, mfa_secret)
    backup = BackupCodeStore(mfa_db, mfa_secret)
    services = MfaServices(
        backend=SimpleNamespace(_idp=Idp()),
        available=True,
        redis_pool=mfa_redis_pool,
        db_pool=mfa_db,
        secret=mfa_secret,
        store=store,
        # Generous budgets: the limiter is not under test here (TASK-131 owns it).
        user_limiter=StrictRateLimiter(mfa_redis_pool, "1000/hour", "user"),
        ip_limiter=StrictRateLimiter(mfa_redis_pool, "1000/hour", "ip"),
        security=MfaSecurity(mfa_db, mfa_secret),
        trusted_devices=TrustedDeviceStore(mfa_db),
        backup_codes=backup,
        resolver=MfaPolicyResolver(mfa_db),
        state=MfaStateMachine(mfa_db, backup_codes=backup),
        providers={PROVIDER_TOTP: TOTPProvider(app=keyring_app, db_pool=mfa_db, store=store, clock=frozen_totp_clock)},
    )
    environment = Env(mfa_db, mfa_redis_pool, services, frozen_totp_clock, monkeypatch, mfa_user_factory)
    yield environment
    await environment.cleanup()


@pytest.mark.asyncio
async def test_totp_enrollment_requires_fresh_auth(env):
    """Fresh password always; replacement also needs TOTP, a backup code or a fresh passkey (AC29, D20)."""
    user = await env.new_user()
    uid = user["user_id"]

    with pytest.raises(web.HTTPUnauthorized):
        await env.call("enroll_totp", uid, {"password": user["password_plain"]}, authenticated=False)

    # A live session alone is not enough: no password, then a wrong password.
    response, body = await env.call("enroll_totp", uid, {})
    assert (response.status, body) == (403, {"error": "invalid_credentials"})
    response, body = await env.call("enroll_totp", uid, {"password": "not-the-password"})
    assert (response.status, body) == (403, {"error": "invalid_credentials"})

    # First enrolment (no strong factor yet): the fresh password is sufficient.
    user, session, secret, backup_codes = await env.enrolled_user()
    uid = user["user_id"]

    # Replacement: right password but no strong-factor proof.
    response, body = await env.enroll(user, session)
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})

    # An e-mail code never qualifies, under any field name.
    response, body = await env.enroll(user, session, provider=PROVIDER_EMAIL, email_code="123456")
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})

    # A trusted-device cookie never qualifies.
    device = await env.services.trusted_devices.issue(uid, 30, "laptop")
    response, body = await env.enroll(user, session, device_token=device, remember_device=True)
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})

    # A stale or wrong TOTP code does not qualify.
    response, _ = await env.enroll(user, session, code=WRONG_CODE)
    assert response.status == 403

    # A current TOTP code does.
    code, _ = env.code(secret)
    response, body = await env.enroll(user, session, code=code)
    assert response.status == 201, body

    # An unused backup code does, and is spent by doing so.
    remaining = await env.services.backup_codes.remaining(uid)
    response, body = await env.enroll(user, session, backup_code=backup_codes[0])
    assert response.status == 201, body
    assert await env.services.backup_codes.remaining(uid) == remaining - 1
    response, _ = await env.enroll(user, session, backup_code=backup_codes[0])
    assert response.status == 403

    # A passkey session qualifies only while it is at most AUTH_OTP_CHALLENGE_TTL old.
    old_passkey = FakeSession(uid, created=int(time.time()) - AUTH_OTP_CHALLENGE_TTL - 5, auth_method="passkey")
    response, body = await env.enroll(user, old_passkey)
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})
    fresh_passkey = FakeSession(uid, auth_method="passkey")
    response, body = await env.enroll(user, fresh_passkey)
    assert response.status == 201, body

    # A fresh BasicAuth session (no auth_method) is not a passkey proof.
    response, _ = await env.enroll(user, FakeSession(uid))
    assert response.status == 403


@pytest.mark.asyncio
async def test_enrollment_authorization_is_server_side(env):
    """Body fields cannot set the pending record's user, session or security version (AC-3)."""
    user = await env.new_user()
    other = await env.new_user()
    uid = user["user_id"]
    session = FakeSession(uid)
    forged = {
        "user_id": other["user_id"],
        "session_id": "attacker-session",
        "security_version": 999,
        "context_digest": "0" * 64,
        "expires_at": "2099-01-01T00:00:00+00:00",
    }
    response, started = await env.enroll(user, session, **forged)
    assert response.status == 201, started
    pending = await env.services.store.peek_enrollment(started["enrollment_token"])
    assert pending.user_id == uid
    assert pending.session_hash == hashlib.sha256(session.session_id.encode()).hexdigest()
    assert pending.security_version == await env.version(uid)
    assert started["expires_in"] == ENROLLMENT_TTL


@pytest.mark.asyncio
async def test_totp_pending_seed_isolated(env):
    """Start, failed confirms, foreign sessions, expiry and version changes never touch the active seed (AC29)."""
    user, session, secret, backup_codes = await env.enrolled_user()
    uid = user["user_id"]
    active = await env.active_seed_row(uid)
    assert active is not None

    code, _ = env.code(secret)
    response, started = await env.enroll(user, session, code=code)
    assert response.status == 201
    token, new_secret = started["enrollment_token"], started["secret_b32"]
    assert new_secret != secret
    assert await env.active_seed_row(uid) == active

    # A wrong code fails and changes nothing.
    response, body = await env.confirm(user, session, token, WRONG_CODE)
    assert (response.status, body["error"]) == (400, "invalid_code")
    assert await env.active_seed_row(uid) == active

    # The right code from a different session of the same user fails.
    code, _ = env.code(new_secret)
    response, _ = await env.confirm(user, FakeSession(uid), token, code)
    assert response.status == 400
    assert await env.active_seed_row(uid) == active

    # Expiry: the pending record is gone, the right code from the right session fails.
    await env.expire_pending(token)
    code, _ = env.code(new_secret)
    response, body = await env.confirm(user, session, token, code)
    assert (response.status, body) == (400, {"error": "invalid_enrollment"})
    assert await env.active_seed_row(uid) == active

    # The old seed is still the one that verifies; the abandoned one does not.
    provider = env.services.providers[PROVIDER_TOTP]
    record = await env.services.backend._idp.user_from_id(uid)
    code, _ = env.code(new_secret)
    assert not await provider.verify(None, record, code)
    code, _ = env.code(secret)
    assert await provider.verify(None, record, code)

    # A security transition between start and confirm kills the pending record.
    response, started = await env.enroll(user, session, backup_code=backup_codes[0])
    assert response.status == 201
    await env.bump(uid)
    code, _ = env.code(started["secret_b32"])
    response, body = await env.confirm(user, session, started["enrollment_token"], code)
    assert (response.status, body) == (400, {"error": "invalid_enrollment"})
    assert await env.services.store.peek_enrollment(started["enrollment_token"]) is None
    assert await env.active_seed_row(uid) == active


@pytest.mark.asyncio
async def test_totp_confirmation_single_use(env):
    """Two concurrent confirmations: exactly one transition, one audit row, one bump (AC23, AC30)."""
    user = await env.new_user()
    uid = user["user_id"]
    session = FakeSession(uid)
    device = await env.services.trusted_devices.issue(uid, 30, "laptop")
    version_before = await env.version(uid)

    response, started = await env.enroll(user, session)
    assert response.status == 201
    code, step = env.code(started["secret_b32"])
    results = await asyncio.gather(
        env.confirm(user, session, started["enrollment_token"], code),
        env.confirm(user, session, started["enrollment_token"], code),
    )
    statuses = sorted(response.status for response, _ in results)
    assert statuses == [200, 400]
    confirmed = next(body for response, body in results if response.status == 200)
    assert confirmed["status"] == "confirmed"

    assert len(await env.audit(uid, "totp_confirm")) == 1
    assert await env.version(uid) == version_before + 1
    assert await env.services.trusted_devices.list_active(uid) == []
    assert await env.services.trusted_devices.consume_and_rotate(device, uid) is None
    # The accepted step is burned for this user (replay guard).
    assert not await env.services.store.mark_totp_step(uid, step, 120)
    assert await env.services.state.totp_confirmed(uid)

    # D21: the user had no backup codes, so the confirmation delivered the initial set once.
    assert len(confirmed["backup_codes"]) == await env.services.backup_codes.remaining(uid) > 0


@pytest.mark.asyncio
async def test_confirm_with_existing_backup_codes_returns_none(env):
    """A replacement confirmation does not re-issue backup codes when the user still has some (D21)."""
    user, session, secret, backup_codes = await env.enrolled_user()
    code, _ = env.code(secret)
    response, started = await env.enroll(user, session, code=code)
    assert response.status == 201
    code, _ = env.code(started["secret_b32"])
    response, body = await env.confirm(user, session, started["enrollment_token"], code)
    assert (response.status, body) == (200, {"status": "confirmed"})
    # The old set is still valid: nothing was regenerated.
    assert await env.services.backup_codes.consume(user["user_id"], backup_codes[1])


@pytest.mark.asyncio
async def test_email_challenge_invalid_after_totp_confirmation(env):
    """Unit form: confirmation bumps the security version, so an e-mail challenge issued before is stale (AC30)."""
    user = await env.new_user()
    uid = user["user_id"]
    services = env.services
    record = await services.backend._idp.user_from_id(uid)
    before = await services.evaluate(record)
    token, challenge = await services.store.issue(
        record,
        [PROVIDER_EMAIL],
        PROVIDER_EMAIL,
        security_version=before.security_version,
        context_digest=before.context_digest,
        email_code_hash="0" * 64,
    )
    # Control: before the transition the challenge revalidates.
    async with services.security.user_lock(uid) as conn:
        assert isinstance(await env.handler._revalidate(None, services, conn, token, challenge), tuple)

    session = FakeSession(uid)
    response, started = await env.enroll(user, session)
    code, _ = env.code(started["secret_b32"])
    response, _ = await env.confirm(user, session, started["enrollment_token"], code)
    assert response.status == 200

    after = await services.evaluate(await services.backend._idp.user_from_id(uid))
    assert after.security_version == before.security_version + 1
    assert PROVIDER_EMAIL not in after.providers
    async with services.security.user_lock(uid) as conn:
        result = await env.handler._revalidate(None, services, conn, token, challenge)
    assert isinstance(result, web.Response)
    assert (result.status, json.loads(result.body)) == (401, {"error": "stale_challenge"})
    assert await services.store.peek(token) is None


@pytest.mark.asyncio
async def test_factor_transitions_write_durable_audit(env):
    """Enrol start, confirm, backup regeneration and disenrolment each leave exactly one row (AC23, AC-8)."""
    user = await env.new_user()
    uid = user["user_id"]
    session = FakeSession(uid)

    response, started = await env.enroll(user, session)
    assert response.status == 201
    code, _ = env.code(started["secret_b32"])
    response, _ = await env.confirm(user, session, started["enrollment_token"], code)
    assert response.status == 200
    response, _ = await env.call("backup_codes", uid, {"password": user["password_plain"]}, session)
    assert response.status == 201

    device = await env.services.trusted_devices.issue(uid, 30, "laptop")
    version_before = await env.version(uid)
    seen: list[tuple] = []

    async def _spy(notice):
        # A separate connection only sees committed rows.
        seen.append((notice, len(await env.audit(uid))))

    env.monkeypatch.setattr(mfa_handlers, "notify_security_event", _spy)
    code, _ = env.code(started["secret_b32"])
    response, body = await env.call("disenroll_totp", uid, {"password": user["password_plain"], "code": code}, session)
    assert (response.status, body) == (200, {"status": "disenrolled"})

    rows = await env.audit(uid)
    summary = [
        (row["action"], row["actor_user_id"], row["target_user_id"], row["outcome"], row["old_state"], row["new_state"])
        for row in rows
    ]
    assert summary == [
        ("totp_enroll_start", uid, uid, "pending", "none", "none"),
        ("totp_confirm", uid, uid, "success", "none", "totp"),
        ("backup_codes_regenerate", uid, uid, "success", "totp", "totp"),
        ("totp_disenroll", uid, uid, "success", "totp", "none"),
    ]
    assert [row["method"] for row in rows] == ["totp", "totp", "backup", "totp"]

    # Disenrolment: notified once, after commit; devices revoked; version bumped; factor gone.
    assert len(seen) == 1
    notice, committed = seen[0]
    assert committed == 4
    assert notice.event == "totp_disenrolled"
    assert notice.email == user["email"]
    assert notice.username == user["username"]
    assert await env.services.trusted_devices.consume_and_rotate(device, uid) is None
    assert await env.version(uid) == version_before + 1
    assert not await env.services.state.totp_confirmed(uid)
    assert await env.active_seed_row(uid) is None


@pytest.mark.asyncio
async def test_disenroll_requires_password_and_proof(env):
    """Self-disenrolment needs a fresh password AND a TOTP or backup code; refusals change nothing (AC-8)."""
    user, session, secret, backup_codes = await env.enrolled_user()
    uid = user["user_id"]

    response, body = await env.call("disenroll_totp", uid, {"code": env.code(secret)[0]}, session)
    assert (response.status, body) == (403, {"error": "invalid_credentials"})
    response, body = await env.call("disenroll_totp", uid, {"password": user["password_plain"]}, session)
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})
    response, body = await env.call(
        "disenroll_totp", uid, {"password": user["password_plain"], "code": WRONG_CODE}, session
    )
    assert response.status == 403
    assert await env.services.state.totp_confirmed(uid)
    assert await env.audit(uid, "totp_disenroll") == []
    assert env.notices == []

    response, body = await env.call(
        "disenroll_totp", uid, {"password": user["password_plain"], "backup_code": backup_codes[0]}, session
    )
    assert (response.status, body) == (200, {"status": "disenrolled"})
    assert not await env.services.state.totp_confirmed(uid)
    assert len(env.notices) == 1

    response, body = await env.call("disenroll_totp", uid, {"password": user["password_plain"]}, session)
    assert (response.status, body) == (404, {"error": "not_enrolled"})


@pytest.mark.asyncio
async def test_confirm_budget_survives_failures(env):
    """max_attempts - 1 wrong codes keep the record, the last burns it; the TTL never grows (AC-6)."""
    user = await env.new_user()
    session = FakeSession(user["user_id"])
    response, started = await env.enroll(user, session)
    token = started["enrollment_token"]
    budget = env.services.store._max_attempts  # AUTH_OTP_MAX_ATTEMPTS, spec default 5
    ttl = await env.pending_ttl_ms(token)

    for _ in range(budget - 1):
        response, body = await env.confirm(user, session, token, WRONG_CODE)
        assert (response.status, body["error"]) == (400, "invalid_code")
        assert await env.services.store.peek_enrollment(token) is not None
        current = await env.pending_ttl_ms(token)
        assert 0 < current <= ttl
        ttl = current

    response, body = await env.confirm(user, session, token, WRONG_CODE)
    assert response.status == 400
    assert await env.services.store.peek_enrollment(token) is None

    code, _ = env.code(started["secret_b32"])
    response, body = await env.confirm(user, session, token, code)
    assert (response.status, body) == (400, {"error": "invalid_enrollment"})
    assert not await env.services.state.totp_confirmed(user["user_id"])


@pytest.mark.asyncio
async def test_disenroll_superuser_last_factor_refused(env):
    """Enforced superuser with TOTP only ⇒ 409 before any submitted code is consumed (AC33)."""
    user, session, secret, backup_codes = await env.enrolled_user(superuser=True)
    uid = user["user_id"]
    await env.enforced_org(uid)
    remaining = await env.services.backup_codes.remaining(uid)
    code, step = env.code(secret)

    body = {"password": user["password_plain"], "code": code, "backup_code": backup_codes[0]}
    response, reply = await env.call("disenroll_totp", uid, body, session)
    assert (response.status, reply) == (409, {"error": "strong_factor_required"})

    assert await env.services.backup_codes.remaining(uid) == remaining
    # The TOTP step was never marked used: the code was not even checked.
    assert await env.services.store.mark_totp_step(uid, step, 120)
    assert await env.services.state.totp_confirmed(uid)
    assert await env.audit(uid, "totp_disenroll") == []
    assert env.notices == []


@pytest.mark.asyncio
async def test_backup_codes_require_strong_factor(env):
    """Regeneration needs a fresh password and a strong factor, and invalidates the previous set (AC-7)."""
    plain = await env.new_user()
    response, body = await env.call("backup_codes", plain["user_id"], {"password": plain["password_plain"]})
    assert (response.status, body) == (403, {"error": "strong_factor_required"})

    user, session, _, old_codes = await env.enrolled_user()
    uid = user["user_id"]
    response, body = await env.call("backup_codes", uid, {"password": "wrong"}, session)
    assert (response.status, body) == (403, {"error": "invalid_credentials"})
    response, body = await env.call("backup_codes", uid, {"password": user["password_plain"]}, session)
    assert response.status == 201
    new_codes = body["backup_codes"]
    assert body["count"] == len(new_codes) == await env.services.backup_codes.remaining(uid)
    assert not set(new_codes) & set(old_codes)
    assert not await env.services.backup_codes.consume(uid, old_codes[0])
    assert await env.services.backup_codes.consume(uid, new_codes[0])


@pytest.mark.asyncio
async def test_enroll_response_is_only_secret_carrier(env, caplog):
    """No URI, seed, token, code or password reaches the logs or any other response (AC14, AC-9)."""
    caplog.set_level(logging.DEBUG)
    user = await env.new_user()
    uid = user["user_id"]
    session = FakeSession(uid)
    response, started = await env.enroll(user, session)
    assert response.status == 201
    assert set(started) == {"enrollment_token", "uri", "secret_b32", "expires_in"}
    assert response.headers["Cache-Control"] == "no-store"
    secrets_seen = [user["password_plain"], started["enrollment_token"], started["uri"], started["secret_b32"]]

    replies = []
    replies.append(await env.confirm(user, session, started["enrollment_token"], WRONG_CODE))
    code, _ = env.code(started["secret_b32"])
    secrets_seen.append(code)
    replies.append(await env.confirm(user, session, started["enrollment_token"], code))
    backup = replies[-1][1]["backup_codes"]
    secrets_seen.extend(backup)
    regenerated = await env.call("backup_codes", uid, {"password": user["password_plain"]}, session)
    secrets_seen.extend(regenerated[1]["backup_codes"])
    code, _ = env.code(started["secret_b32"])
    secrets_seen.append(code)
    replies.append(await env.call("disenroll_totp", uid, {"password": user["password_plain"], "code": code}, session))

    for response, body in replies:
        assert response.headers["Cache-Control"] == "no-store"
        text = json.dumps(body)
        for value in (started["enrollment_token"], started["uri"], started["secret_b32"], user["password_plain"]):
            assert value not in text
    for value in secrets_seen:
        # Token-boundary match: a 6-digit code must not false-match inside a timestamp or an id.
        assert not re.search(rf"(?<![0-9A-Za-z]){re.escape(value)}(?![0-9A-Za-z])", caplog.text), value
