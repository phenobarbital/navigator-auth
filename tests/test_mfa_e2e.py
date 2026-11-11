# ruff: noqa: F811
"""FEAT-106 TASK-147 — end-to-end 2FA over HTTP on live Redis + Postgres (spec §4 Integration).

Every row drives a real ``AuthHandler(BasicAuth)`` application through its HTTP
routes — ``/api/v1/login``, ``/auth/mfa/*``, ``/api/v2/user/*`` and the FEAT-098
password-recovery flow — with the MFA services built by ``on_startup`` from the
real settings. Test-only seams, all installed after startup and none bypassing a
security check:

* the TOTP provider's clock is frozen (``FrozenClock``) so a test can produce
  several codes without waiting for the next 30 s step;
* the e-mail OTP and password-recovery callbacks point at capture functions in
  this module (the e-mail provider binds its callback at import time);
* ``app["abac"]`` is a holder whose policy list is empty (fail-closed, same as
  no PDP) except in row 15, which loads the shipped ``mfa_admin_access`` pack;
* a user-attribute provider adds ``groups`` to the session for users listed in
  ``SESSION_GROUPS`` (BasicAuth sessions carry no groups of their own).
"""

import asyncio
import base64
import logging
import re
import secrets
import tomllib
import warnings
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from navigator_session import AUTH_SESSION_OBJECT, get_session

import navigator_auth.conf as conf
from navigator_auth import AuthHandler
from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,
    AUTH_JWT_ALGORITHM,
    AUTH_OTP_CHALLENGE_TTL,
    REDIS_AUTH_URL,
    SECRET_KEY,
)
from navigator_auth.handlers.recovery import handler as recovery_handler
from navigator_auth.mfa.policy import apply_tenant_policy
from navigator_auth.mfa.services import MFA_APP_KEY, get_mfa_services
from navigator_auth.mfa.store import CHALLENGE_KEY_PREFIX
from navigator_auth.mfa.types import (
    AMR_TRUSTED_DEVICE,
    PROVIDER_BACKUP,
    PROVIDER_EMAIL,
    PROVIDER_TOTP,
    TRUSTED_COOKIE,
    MfaMode,
)
from navigator_auth.responses import JSONResponse
from scripts.preflight_mfa import run_preflight
from tests.fixtures.mfa import (  # noqa: F401
    MFA_TEST_SECRET,
    broken_redis_pool,
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
)

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    # The local test SECRET_KEY is short; production key length is not under test here.
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
]

ROOT = Path(__file__).resolve().parents[1]
MFA_ADMIN_PACK = ROOT / "navigator_auth" / "abac" / "default_policies" / "mfa_admin_access.yaml"
AUDIT = f"{AUTH_DB_SCHEMA}.user_mfa_audit"
POLICY = f"{AUTH_DB_SCHEMA}.tenant_mfa_policy"
ORGS = f"{AUTH_DB_SCHEMA}.organizations"
ORG_USERS = f"{AUTH_DB_SCHEMA}.organization_users"
USERS = f"{AUTH_DB_SCHEMA}.users"
USER_MFA = f"{AUTH_DB_SCHEMA}.user_mfa"
VAULT = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"  # FEAT-106 review fix #2: seeds moved out of the user vault (spec M7)
CHALLENGE_KEYS = {"mfa_required", "challenge", "providers", "preferred", "expires_in"}
FRESH_FACTORS = {"otp", "totp", "backup"}
# The BasicAuth login body with 2FA off (unchanged by FEAT-106; no ``mfa``/``amr``).
BASELINE_LOGIN_KEYS = {
    "auth_method", "created", "email", "expires_at", "expires_in", "id", "last_visit", "name",
    "refresh_token", "session", "session_id", "token", "token_type", "upn", "user_id", "username",
}  # fmt: skip

CAPTURED: list = []
RECOVERY: list = []
SESSION_GROUPS: dict[int, list[str]] = {}


def _capture_otp(payload) -> None:
    """AUTH_OTP_EMAIL_CALLBACK target: keep the payload, never print it."""
    CAPTURED.append(payload)


async def _capture_recovery(payload) -> None:
    """AUTH_RECOVERY_CALLBACK target: keep the recovery token for step 2."""
    RECOVERY.append(payload)


class _SessionGroups:
    """User-attribute provider (``get_userdata`` hook): groups for listed users only."""

    def __call__(self, user, userdata, **kwargs):
        groups = SESSION_GROUPS.get(int(user["user_id"]))
        return ("groups", list(groups)) if groups else (None, None)


def requires_fresh_factor(ctx) -> bool:
    """The documented ABAC check for a fresh second factor (docs/two_factor_auth.rst).

    ``EvalContext`` has no first-class ``amr``; it is read from ``ctx.userinfo``.
    A trusted-device session has ``mfa=True`` but is NOT a fresh factor. Values
    are read by attribute, as ``ResourcePolicy`` does (``ctx[...]`` is the dict
    side of EvalContext and does not see its store).
    """
    userinfo = ctx.userinfo if isinstance(ctx.userinfo, dict) else {}
    amr = set(userinfo.get("amr") or [])
    return bool(ctx.mfa) and AMR_TRUSTED_DEVICE not in amr and bool(amr & FRESH_FACTORS)


async def _evalctx_view(request: web.Request) -> web.Response:
    """Test-only route: the ABAC EvalContext the PDP builds for this live session."""
    session = await get_session(request, new=False)
    userinfo = session[AUTH_SESSION_OBJECT]
    ctx = EvalContext(request, userinfo, userinfo, session)
    return JSONResponse(
        {
            "mfa": ctx.mfa,
            "auth_method": ctx.auth_method,
            "amr": list(userinfo.get("amr") or []),
            "groups": list(userinfo.get("groups") or []),
            "fresh": requires_fresh_factor(ctx),
        }
    )


def _claims(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[AUTH_JWT_ALGORITHM])


def _seed(secret_b32: str) -> bytes:
    return base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))


def _password(tag: str = "") -> str:
    """A fresh password that satisfies the recovery policy (letters + digits, long enough)."""
    return f"Rotated{tag}{secrets.token_hex(4)}9x"


class Live:
    """The running application plus helpers that speak HTTP (and read state for assertions)."""

    def __init__(self, app, auth, client, services, db, clock, factory, abac) -> None:
        self.app = app
        self.auth = auth
        self.client = client
        self.services = services
        self.db = db
        self.clock = clock
        self.factory = factory
        self.abac = abac
        self.users: list[int] = []
        self.orgs: list[int] = []

    # -- data -------------------------------------------------------------------
    async def user(self, **kwargs) -> dict:
        user = await self.factory(**kwargs)
        self.users.append(user["user_id"])
        user["password_current"] = user["password_plain"]
        return user

    async def one(self, sql: str, *args):
        async with await self.db.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def rows(self, sql: str, *args) -> list[dict]:
        async with await self.db.acquire() as conn:
            return [dict(r) for r in (await conn.fetch_all(sql, *args) or [])]

    async def join(self, user_id: int, org_id: int) -> None:
        await self.one(f"INSERT INTO {ORG_USERS} (user_id, org_id) VALUES ($1, $2) RETURNING user_id", user_id, org_id)

    async def org(self, *members: int, mode: MfaMode = MfaMode.OFF, remember_days: int = 0) -> int:
        slug = f"mfa-t147-{secrets.token_hex(4)}"
        org_id = await self.one(
            f"INSERT INTO {ORGS} (organization, org_slug) VALUES ($1, $2) RETURNING org_id", slug, slug
        )
        self.orgs.append(org_id)
        for user_id in members:
            await self.join(user_id, org_id)
        await self.set_policy(org_id, mode, remember_days)
        return org_id

    async def set_policy(self, org_id: int, mode: MfaMode, remember_days: int = 0):
        """The v1 administration recipe (TASK-135) on the app's own services."""
        return await apply_tenant_policy(
            db_pool=self.db,
            security=self.services.security,
            trusted_devices=self.services.trusted_devices,
            org_id=org_id,
            mode=mode,
            remember_days=remember_days,
            actor="e2e",
        )

    async def set_superuser(self, user_id: int, value: bool) -> None:
        await self.one(f"UPDATE {USERS} SET is_superuser = $2 WHERE user_id = $1 RETURNING user_id", user_id, value)

    async def audit(self, action: str, *, target: int | None = None, org: int | None = None) -> list[dict]:
        if target is not None:
            return await self.rows(
                f"SELECT * FROM {AUDIT} WHERE action = $1 AND target_user_id = $2 ORDER BY id", action, target
            )
        return await self.rows(f"SELECT * FROM {AUDIT} WHERE action = $1 AND org_id = $2 ORDER BY id", action, org)

    # -- HTTP -------------------------------------------------------------------
    def _no_jar(self) -> None:
        # Cookies are always passed explicitly; never let the client jar carry one over.
        self.client.session.cookie_jar.clear()

    async def login(self, user: dict, password: str | None = None, *, cookies=None, headers=None):
        """POST /api/v1/login (JSON); returns ``(response, body)``."""
        self._no_jar()
        response = await self.client.post(
            "/api/v1/login",
            json={"username": user["username"], "password": password or user["password_current"]},
            cookies=cookies,
            headers=headers,
        )
        return response, await response.json()

    async def verify(self, challenge: str, provider: str, code: str, *, remember: bool = False):
        """POST /auth/mfa/verify; returns ``(response, body)``."""
        self._no_jar()
        response = await self.client.post(
            "/auth/mfa/verify",
            json={"challenge": challenge, "provider": provider, "code": code, "remember_device": remember},
        )
        return response, await response.json()

    async def call(self, method: str, path: str, token: str, body: dict | None = None):
        """An authenticated (Bearer) request; returns ``(response, body)``."""
        self._no_jar()
        response = await self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})
        try:
            payload = await response.json()
        except Exception:  # pylint: disable=W0718 -- non-JSON error pages
            payload = {"text": await response.text()}
        return response, payload

    async def session_ok(self, token: str) -> bool:
        response, _ = await self.call("GET", "/api/v2/user/session", token)
        return response.status == 200

    def totp(self, secret_b32: str) -> str:
        """A fresh TOTP code: advance one step first so the replay guard never trips."""
        self.clock.advance(30)
        return TOTP(_seed(secret_b32), 6, SHA1(), 30).generate(self.clock.now).decode()

    @staticmethod
    def emails(user: dict) -> list:
        return [p for p in CAPTURED if p.username == user["username"]]

    def email_code(self, user: dict) -> str:
        """The latest e-mail OTP handed to the callback for ``user``."""
        mine = self.emails(user)
        assert mine, f"no e-mail OTP captured for {user['username']}"
        return mine[-1].code

    async def plain_login(self, user: dict) -> str:
        response, body = await self.login(user)
        assert response.status == 200, body
        return body["token"]

    async def email_login(self, user: dict) -> str:
        """Complete an e-mail-OTP login and return the access token."""
        response, body = await self.login(user)
        assert response.status == 401 and body["preferred"] == PROVIDER_EMAIL, body
        response, body = await self.verify(body["challenge"], PROVIDER_EMAIL, self.email_code(user))
        assert response.status == 200, body
        return body["token"]

    async def totp_login(self, user: dict, secret: str, *, remember: bool = False):
        """Complete a TOTP login; returns the verify ``(response, body)``."""
        response, body = await self.login(user)
        assert response.status == 401 and body["preferred"] == PROVIDER_TOTP, body
        return await self.verify(body["challenge"], PROVIDER_TOTP, self.totp(secret), remember=remember)

    async def enrol_totp(self, user: dict, token: str) -> tuple[str, list[str]]:
        """Enrol + confirm TOTP through the HTTP endpoints; returns ``(secret_b32, backup_codes)``."""
        response, started = await self.call(
            "POST", "/auth/mfa/totp/enroll", token, {"password": user["password_current"]}
        )
        assert response.status == 201, started
        response, confirmed = await self.call(
            "POST",
            "/auth/mfa/totp/confirm",
            token,
            {"enrollment_token": started["enrollment_token"], "code": self.totp(started["secret_b32"])},
        )
        assert response.status == 200, confirmed
        return started["secret_b32"], confirmed.get("backup_codes", [])

    async def recovery_token(self, user: dict) -> str:
        """FEAT-098 steps 1 and 2; returns the step-3 confirmation token."""
        RECOVERY.clear()
        response = await self.client.post("/api/v1/password-recovery", json={"email": user["email"]})
        assert response.status == 200, await response.text()
        assert len(RECOVERY) == 1
        response = await self.client.get(f"/api/v1/password-recovery/{RECOVERY[0].token}")
        assert response.status == 200, await response.text()
        return (await response.json())["token"]

    async def confirm_recovery(self, user: dict, confirm_token: str, new_password: str):
        """FEAT-098 step 3."""
        response = await self.client.post(
            "/api/v1/password-recovery/confirm",
            json={"password": new_password, "confirm_password": new_password, "token": confirm_token},
        )
        if response.status == 202:
            user["password_current"] = new_password
        return response

    async def recover(self, user: dict, new_password: str):
        return await self.confirm_recovery(user, await self.recovery_token(user), new_password)

    # -- cleanup ----------------------------------------------------------------
    async def cleanup(self) -> None:
        if self.users or self.orgs:
            await self.one(
                f"WITH d AS (DELETE FROM {AUDIT} WHERE target_user_id = ANY($1::bigint[]) "
                "OR actor_user_id = ANY($1::bigint[]) OR org_id = ANY($2::bigint[]) RETURNING 1) "
                "SELECT count(*) FROM d",
                self.users,
                self.orgs,
            )
        if self.users:
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


def _patch_settings(monkeypatch, *, enabled: bool, secret: bytes) -> None:
    """Every MFA setting is read as ``navigator_auth.conf.<NAME>`` at call time."""
    monkeypatch.setattr(conf, "AUTHENTICATION_BACKENDS", ("navigator_auth.backends.BasicAuth",))
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", enabled)
    monkeypatch.setattr(conf, "AUTH_OTP_SECRET", secret)
    monkeypatch.setattr(conf, "AUTH_OTP_EMAIL_CALLBACK", "tests.test_mfa_e2e._capture_otp")
    # PasswordRecoveryHandler reads these as module globals at call time.
    monkeypatch.setattr(recovery_handler, "AUTH_RECOVERY_CALLBACK", "tests.test_mfa_e2e._capture_recovery")
    monkeypatch.setattr(recovery_handler, "AUTH_RECOVERY_URL_TEMPLATE", "https://app.example/reset?token={token}")
    monkeypatch.setattr(recovery_handler, "AUTH_RECOVERY_RATE_EMAIL", "1000/hour")
    monkeypatch.setattr(recovery_handler, "AUTH_RECOVERY_RATE_IP", "1000/hour")


async def _start(app: web.Application) -> tuple[AuthHandler, TestClient]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Pin BasicAuth only: settings may enable network backends (Azure/ADFS)
        # and a backend-loop login must never reach an external identity provider.
        auth = AuthHandler(secure_cookies=False, backends=("navigator_auth.backends.BasicAuth",))
        auth.setup(app)
        client = TestClient(TestServer(app))
        await client.start_server()
    backend = auth.backends["BasicAuth"]
    # Production AUTH_SUCCESSFUL_CALLBACKS reach services unavailable here (see test_basic_auth.py).
    backend._callbacks = None
    backend._user_attributes = [*list(backend._user_attributes or []), _SessionGroups]
    return auth, client


async def _stop(auth: AuthHandler, client: TestClient) -> None:
    """Close what pytest-asyncio's per-test loop would otherwise hang on (see test_password_recovery.py)."""
    for backend in auth.backends.values():
        storage = getattr(backend, "access_token_storage", None)
        if storage is not None:
            try:
                await storage.redis.aclose()
            except Exception:  # pylint: disable=W0718
                pass
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()
    handler_cls = recovery_handler.PasswordRecoveryHandler
    if handler_cls._pool is not None:
        await handler_cls._pool.disconnect()
        handler_cls._pool = None
        handler_cls._store = None
        handler_cls._policy = None
        handler_cls._email_limiter = None
        handler_cls._ip_limiter = None
        handler_cls._revoker = None


@pytest_asyncio.fixture
async def live(monkeypatch, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock):
    """A real AuthHandler(BasicAuth) app with AUTH_BASIC_2FA_ENABLED, on live Postgres + Redis."""
    _patch_settings(monkeypatch, enabled=True, secret=mfa_secret)
    CAPTURED.clear()
    RECOVERY.clear()
    SESSION_GROUPS.clear()
    app = web.Application()
    abac = SimpleNamespace(policies=[])
    app["abac"] = abac
    app.router.add_get("/_test/mfa/evalctx", _evalctx_view)
    try:
        auth, client = await _start(app)
    except Exception as err:  # pylint: disable=W0718
        pytest.skip(f"MFA live application unavailable: {type(err).__name__}: {err}")
    services = get_mfa_services(app)
    if services is None or not services.available:
        await _stop(auth, client)
        pytest.skip("MFA services unavailable (tables, Redis or AUTH_OTP_SECRET)")
    if app.get("vault_keyring") is None:
        await _stop(auth, client)
        pytest.skip("Vault KeyRing not configured (VAULT_MASTER_KEY_v*): TOTP seeds cannot be sealed")
    services.providers[PROVIDER_TOTP]._clock = frozen_totp_clock  # type: ignore[attr-defined]
    services.providers[PROVIDER_EMAIL]._callback = "tests.test_mfa_e2e._capture_otp"  # type: ignore[attr-defined]
    env = Live(app, auth, client, services, mfa_db, frozen_totp_clock, mfa_user_factory, abac)
    yield env
    await env.cleanup()
    await _stop(auth, client)
    CAPTURED.clear()
    RECOVERY.clear()
    SESSION_GROUPS.clear()


# ---------------------------------------------------------------------------
# Spec §4 Integration rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_email_otp_end_to_end(live):
    """Row 1: enforced tenant, no TOTP ⇒ e-mail challenge without session, then a pwd+otp session (AC1, AC6, D11)."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)

    response, body = await live.login(user)
    assert response.status == 401
    assert set(body) == CHALLENGE_KEYS
    assert body["mfa_required"] is True
    assert (body["providers"], body["preferred"]) == ([PROVIDER_EMAIL], PROVIDER_EMAIL)
    assert body["expires_in"] == AUTH_OTP_CHALLENGE_TTL
    assert "Set-Cookie" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"

    sent = live.emails(user)
    assert len(sent) == 1
    assert sent[0].email == user["email"]
    assert sent[0].code not in repr(sent[0])

    response, verified = await live.verify(body["challenge"], PROVIDER_EMAIL, sent[0].code)
    assert response.status == 200, verified
    claims = _claims(verified["token"])
    assert claims["user_id"] == user["user_id"]
    assert claims["mfa"] is True
    assert claims["amr"] == ["pwd", "otp"]
    assert await live.session_ok(verified["token"])

    # The challenge is single-use.
    response, again = await live.verify(body["challenge"], PROVIDER_EMAIL, sent[0].code)
    assert response.status == 401 and "token" not in again


@pytest.mark.asyncio
async def test_login_totp_end_to_end(live):
    """Row 2: a TOTP user is challenged for TOTP (never e-mail) and gets a pwd+totp session."""
    user = await live.user()
    secret, backup_codes = await live.enrol_totp(user, await live.plain_login(user))
    assert backup_codes  # D21: the first strong factor delivers the initial set

    response, body = await live.login(user)
    assert response.status == 401
    assert body["preferred"] == PROVIDER_TOTP
    assert body["providers"] == [PROVIDER_TOTP, PROVIDER_BACKUP]
    assert live.emails(user) == []

    response, verified = await live.verify(body["challenge"], PROVIDER_TOTP, live.totp(secret))
    assert response.status == 200, verified
    claims = _claims(verified["token"])
    assert claims["mfa"] is True
    assert claims["amr"] == ["pwd", "totp"]


@pytest.mark.asyncio
async def test_enforce_tenant_no_lockout(live):
    """Row 3: a pre-flight-clean tenant switched to ENFORCED locks nobody out (AC8, AC15)."""
    ordinary = [await live.user(), await live.user()]
    superuser = await live.user(superuser=True)
    org = await live.org(*(u["user_id"] for u in ordinary), superuser["user_id"], mode=MfaMode.OFF)
    # B2: the superuser gets a strong factor while the tenant is still OFF.
    secret, _ = await live.enrol_totp(superuser, await live.plain_login(superuser))

    report = await run_preflight(live.db, org)
    assert report.ok, report
    assert report.members == 3

    await live.set_policy(org, MfaMode.ENFORCED)
    for user in ordinary:
        assert await live.session_ok(await live.email_login(user))

    response, body = await live.login(superuser)
    assert response.status == 401
    assert PROVIDER_EMAIL not in body["providers"]
    response, verified = await live.verify(body["challenge"], PROVIDER_TOTP, live.totp(secret))
    assert response.status == 200, verified
    assert live.emails(superuser) == []

    # Control: a superuser without a strong factor would block the pre-flight.
    blocker = await live.user(superuser=True)
    await live.join(blocker["user_id"], org)
    report = await run_preflight(live.db, org)
    assert not report.ok
    assert [o.user_id for o in report.superusers_without_strong_factor] == [blocker["user_id"]]


@pytest.mark.asyncio
async def test_totp_enrolment_closes_email_path(live):
    """Row 4: after TOTP confirmation, e-mail is no longer offered nor accepted (AC9)."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    secret, _ = await live.enrol_totp(user, await live.email_login(user))
    sent_before = len(live.emails(user))

    response, body = await live.login(user)
    assert response.status == 401
    assert PROVIDER_EMAIL not in body["providers"]
    assert body["preferred"] == PROVIDER_TOTP
    assert len(live.emails(user)) == sent_before  # no e-mail code was issued

    response, refused = await live.verify(body["challenge"], PROVIDER_EMAIL, "123456")
    assert response.status == 401 and "token" not in refused
    # One wrong attempt does not burn the challenge: the strong factor still completes it.
    response, verified = await live.verify(body["challenge"], PROVIDER_TOTP, live.totp(secret))
    assert response.status == 200, verified


@pytest.mark.asyncio
async def test_remember_me_skips_otp_not_password(live):
    """Row 5: a trusted device skips the OTP, never the password; it rotates and replay revokes it (AC17, AC19, R8)."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.OPTIONAL, remember_days=30)
    secret, _ = await live.enrol_totp(user, await live.plain_login(user))

    response, verified = await live.totp_login(user, secret, remember=True)
    assert response.status == 200, verified
    morsel = response.cookies[TRUSTED_COOKIE]
    first = morsel.value
    assert morsel["httponly"] and morsel["secure"]
    assert morsel["samesite"] == "Lax"
    assert int(morsel["max-age"]) == 30 * 86400
    assert first not in str(verified)  # the device token travels only in Set-Cookie

    response, body = await live.login(user, cookies={TRUSTED_COOKIE: first})
    assert response.status == 200, body
    claims = _claims(body["token"])
    assert claims["mfa"] is True
    assert claims["amr"] == ["pwd", AMR_TRUSTED_DEVICE]
    second = response.cookies[TRUSTED_COOKIE].value
    assert second != first

    response, body = await live.login(user, "not-the-password", cookies={TRUSTED_COOKIE: second})
    assert response.status in (401, 403)
    assert "token" not in body

    # Replaying the rotated-out cookie revokes the whole family.
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: first})
    assert response.status == 401 and body["mfa_required"] is True
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: second})
    assert response.status == 401 and body["mfa_required"] is True


async def _trusted_user(live, *, mode: MfaMode = MfaMode.OPTIONAL) -> tuple[dict, int, str, str, str]:
    """A TOTP user with a working trusted-device cookie; returns ``(user, org, secret, token, cookie)``."""
    user = await live.user()
    org = await live.org(user["user_id"], mode=mode, remember_days=30)
    secret, _ = await live.enrol_totp(user, await live.plain_login(user))
    response, verified = await live.totp_login(user, secret, remember=True)
    assert response.status == 200, verified
    cookie = response.cookies[TRUSTED_COOKIE].value
    # Control: the cookie skips the OTP before the transition under test (and rotates).
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: cookie})
    assert response.status == 200, body
    return user, org, secret, body["token"], response.cookies[TRUSTED_COOKIE].value


@pytest.mark.asyncio
async def test_password_change_revokes_trusted_devices(live):
    """Row 6: POST /api/v2/user/set_password revokes every trusted device (AC18)."""
    user, _, _, token, cookie = await _trusted_user(live)
    new_password = _password("pc")
    response, body = await live.call(
        "POST", "/api/v2/user/set_password", token, {"password": new_password, "old_password": user["password_current"]}
    )
    assert response.status == 202, body
    user["password_current"] = new_password

    assert await live.services.trusted_devices.list_active(user["user_id"]) == []
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: cookie})
    assert response.status == 401 and body["mfa_required"] is True
    assert len(await live.audit("password_change", target=user["user_id"])) == 1


@pytest.mark.asyncio
async def test_recovery_completion_revokes_trusted_devices(live):
    """Row 7: completing FEAT-098 password recovery revokes every trusted device (AC18)."""
    user, _, _, token, cookie = await _trusted_user(live)
    response = await live.recover(user, _password("rc"))
    assert response.status == 202, await response.text()

    assert await live.services.trusted_devices.list_active(user["user_id"]) == []
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: cookie})
    assert response.status == 401 and body["mfa_required"] is True
    assert not await live.session_ok(token)  # FEAT-098 also revokes live sessions
    assert len(await live.audit("recovery_completion", target=user["user_id"])) == 1


@pytest.mark.asyncio
async def test_tenant_hardening_revokes_devices_relaxing_does_not(live):
    """Row 8: OPTIONAL→ENFORCED revokes trusted devices; ENFORCED→OPTIONAL keeps them (AC18, D18, AC23)."""
    user, org, secret, _, cookie = await _trusted_user(live)

    await live.set_policy(org, MfaMode.ENFORCED, 30)
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: cookie})
    assert response.status == 401 and body["mfa_required"] is True
    response, verified = await live.verify(body["challenge"], PROVIDER_TOTP, live.totp(secret), remember=True)
    assert response.status == 200, verified
    cookie = response.cookies[TRUSTED_COOKIE].value

    await live.set_policy(org, MfaMode.OPTIONAL, 30)
    response, body = await live.login(user, cookies={TRUSTED_COOKIE: cookie})
    assert response.status == 200, body
    assert _claims(body["token"])["amr"] == ["pwd", AMR_TRUSTED_DEVICE]

    rows = await live.audit("policy_change", org=org)
    changes = [(r["old_state"], r["new_state"], r["detail"]["hardening"], r["detail"]["revoked_devices"]) for r in rows]
    assert changes[-2][:3] == ("optional", "enforced", True)
    assert changes[-2][3] >= 1
    assert changes[-1] == ("enforced", "optional", False, 0)


@pytest.mark.asyncio
async def test_abac_policy_can_require_fresh_factor(live):
    """Row 9: a trusted-device session has mfa=True but fails the documented fresh-factor check.

    The PDP's declarative conditions cannot read ``amr`` (EvalContext has no first-class
    ``amr``), so the fresh-factor requirement is expressed as the documented Python check
    over ``ctx["userinfo"]["amr"]`` (``requires_fresh_factor``).
    """
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.OPTIONAL, remember_days=30)
    secret, _ = await live.enrol_totp(user, await live.plain_login(user))
    response, verified = await live.totp_login(user, secret, remember=True)
    assert response.status == 200, verified
    cookie = response.cookies[TRUSTED_COOKIE].value

    response, otp_ctx = await live.call("GET", "/_test/mfa/evalctx", verified["token"])
    assert response.status == 200, otp_ctx
    assert otp_ctx["mfa"] is True
    assert otp_ctx["amr"] == ["pwd", "totp"]
    assert otp_ctx["fresh"] is True

    response, body = await live.login(user, cookies={TRUSTED_COOKIE: cookie})
    assert response.status == 200, body
    response, device_ctx = await live.call("GET", "/_test/mfa/evalctx", body["token"])
    assert device_ctx["mfa"] is True
    assert AMR_TRUSTED_DEVICE in device_ctx["amr"]
    assert not set(device_ctx["amr"]) & {"otp", "totp"}
    assert device_ctx["fresh"] is False


@pytest.mark.asyncio
async def test_cross_tenant_isolation(live):
    """Row 10: policy follows the user's own memberships, not headers; seeds are bound to their user (AC22, AC25, R14)."""
    user = await live.user()
    bystander = await live.user()
    await live.org(user["user_id"], mode=MfaMode.OFF)
    enforced = await live.org(bystander["user_id"], mode=MfaMode.ENFORCED)

    response, body = await live.login(user)
    assert response.status == 200, body
    headers = {"X-Org-Id": str(enforced), "X-Client-Id": str(enforced)}
    response, body = await live.login(user, headers=headers)
    assert response.status == 200, body
    assert live.emails(user) == []

    # A sealed seed copied to another user does not open for that user (AAD binds user_id).
    secret, _ = await live.enrol_totp(user, body["token"])
    other = await live.user()
    copied = await live.one(
        f"INSERT INTO {VAULT} (user_id, provider, key, ciphertext_db, key_version) "
        f"SELECT $2, provider, key, ciphertext_db, key_version FROM {VAULT} "
        "WHERE user_id = $1 AND key = 'mfa:totp' AND deleted_at IS NULL RETURNING 1",
        user["user_id"],
        other["user_id"],
    )
    assert copied == 1
    await live.one(
        f"INSERT INTO {USER_MFA} (user_id, provider, enabled, confirmed_at) VALUES ($1, 'totp', true, now()) "
        "RETURNING user_id",
        other["user_id"],
    )
    response, body = await live.login(other)
    assert response.status == 401 and body["preferred"] == PROVIDER_TOTP
    response, refused = await live.verify(body["challenge"], PROVIDER_TOTP, live.totp(secret))
    assert response.status in (401, 503)
    assert "token" not in refused


@pytest.mark.asyncio
async def test_pending_challenge_invalid_after_recovery(live):
    """Row 11: password recovery kills an outstanding challenge, even with a valid code (AC30)."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    response, body = await live.login(user)
    assert response.status == 401
    code = live.email_code(user)

    response = await live.recover(user, _password("pr"))
    assert response.status == 202, await response.text()

    response, refused = await live.verify(body["challenge"], PROVIDER_EMAIL, code)
    assert (response.status, refused) == (401, {"error": "stale_challenge"})


@pytest.mark.asyncio
async def test_email_challenge_invalid_after_totp_confirmation(live):
    """Row 12: an e-mail challenge issued before TOTP confirmation in another session is stale (AC30)."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    response, pending = await live.login(user)
    assert response.status == 401
    pending_code = live.email_code(user)

    await live.enrol_totp(user, await live.email_login(user))

    response, refused = await live.verify(pending["challenge"], PROVIDER_EMAIL, pending_code)
    assert (response.status, refused) == (401, {"error": "stale_challenge"})


@pytest.mark.asyncio
async def test_verify_security_transition_races(live):
    """Row 13: verify racing recovery never leaves a usable session after recovery commits (AC30, AC31)."""
    org = await live.org(mode=MfaMode.ENFORCED)
    # Jitter the verify start so both orderings occur; ``None`` = strictly after recovery committed.
    delays = (0, 0, 0.002, 0.005, 0.01, 0.02, 0.04, 0.08, 0.15, None)
    outcomes = []
    for attempt, delay in enumerate(delays):
        user = await live.user()
        await live.join(user["user_id"], org)
        response, body = await live.login(user)
        assert response.status == 401
        code = live.email_code(user)
        confirm_token = await live.recovery_token(user)
        new_password = _password(str(attempt))

        async def _verify_later(challenge=body["challenge"], code=code, delay=delay):
            await asyncio.sleep(delay or 0)
            return await live.verify(challenge, PROVIDER_EMAIL, code)

        if delay is None:
            recovery_response = await live.confirm_recovery(user, confirm_token, new_password)
            verify_response, verified = await _verify_later()
        else:
            (verify_response, verified), recovery_response = await asyncio.gather(
                _verify_later(), live.confirm_recovery(user, confirm_token, new_password)
            )
        assert recovery_response.status == 202, await recovery_response.text()
        if verify_response.status == 200:
            assert not await live.session_ok(verified["token"]), "session survived recovery"
            outcomes.append("verified-then-revoked")
        else:
            assert (verify_response.status, verified) == (401, {"error": "stale_challenge"})
            outcomes.append("refused")
    assert len(outcomes) == len(delays)
    assert "refused" in outcomes  # the post-commit ordering was exercised at least once


@pytest.mark.asyncio
async def test_mfa_verify_finalizes_session(live):
    """Row 14: only a successful verify creates the session and the refresh token (AC32)."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    response, body = await live.login(user)
    assert response.status == 401

    response, failed = await live.verify(body["challenge"], PROVIDER_EMAIL, "000000")
    assert response.status == 401
    assert failed["error"] == "invalid_code" and "token" not in failed and "refresh_token" not in failed
    assert "Set-Cookie" not in response.headers

    response, verified = await live.verify(body["challenge"], PROVIDER_EMAIL, live.email_code(user))
    assert response.status == 200, verified
    response, session = await live.call("GET", "/api/v2/user/session", verified["token"])
    assert response.status == 200
    assert session["user_id"] == user["user_id"]
    assert session["mfa"] is True and session["amr"] == ["pwd", "otp"]
    async with aioredis.from_url(REDIS_AUTH_URL, decode_responses=True) as redis:
        assert await redis.exists(f"auth:refresh_token:{verified['refresh_token']}") == 1


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Pre-existing on dev, not FEAT-106: auth.py calls asyncdb setex(key, 7776000, user_id) but the "
        "asyncdb signature is setex(key, value, timeout), so the stored value is '7776000' and the TTL is "
        "the user id in seconds. Remove this xfail when finalize_login / api_refresh_token are fixed."
    ),
)
@pytest.mark.asyncio
async def test_refresh_token_key_maps_to_user(live):
    """The refresh-token record written by finalize_login must resolve to the logged-in user."""
    user = await live.user()
    response, body = await live.login(user)
    assert response.status == 200, body
    async with aioredis.from_url(REDIS_AUTH_URL, decode_responses=True) as redis:
        key = f"auth:refresh_token:{body['refresh_token']}"
        assert await redis.get(key) == str(user["user_id"])
        assert await redis.ttl(key) > 86400 * 30


@pytest.mark.asyncio
async def test_superuser_last_factor_recovery(live):
    """Row 15: the enforced-superuser last-factor invariant and its audited operator recovery (AC33)."""
    superuser = await live.user(superuser=True)
    admin = await live.user(superuser=True)
    org = await live.org(superuser["user_id"], admin["user_id"], mode=MfaMode.OFF)
    secret, _ = await live.enrol_totp(superuser, await live.plain_login(superuser))
    admin_secret, _ = await live.enrol_totp(admin, await live.plain_login(admin))
    await live.set_policy(org, MfaMode.ENFORCED)
    live.abac.policies, warnings_ = PolicyAdapter.adapt_batch(YAMLStorage._parse_file(MFA_ADMIN_PACK))
    assert not warnings_

    # Self-service: the last strong factor cannot be removed.
    response, verified = await live.totp_login(superuser, secret)
    assert response.status == 200, verified
    response, body = await live.call(
        "DELETE",
        "/auth/mfa/totp",
        verified["token"],
        {"password": superuser["password_current"], "code": live.totp(secret)},
    )
    assert (response.status, body) == (409, {"error": "strong_factor_required"})

    # Admin without the security_admin group: the shipped pack denies.
    response, admin_session = await live.totp_login(admin, admin_secret)
    response, body = await live.call("DELETE", f"/auth/mfa/{superuser['user_id']}", admin_session["token"])
    assert (response.status, body) == (403, {"error": "forbidden"})

    # Admin in security_admin, same tenant: allowed.
    SESSION_GROUPS[admin["user_id"]] = ["security_admin"]
    response, admin_session = await live.totp_login(admin, admin_secret)
    response, ctx = await live.call("GET", "/_test/mfa/evalctx", admin_session["token"])
    assert ctx["groups"] == ["security_admin"]
    response, body = await live.call("DELETE", f"/auth/mfa/{superuser['user_id']}", admin_session["token"])
    assert (response.status, body) == (200, {"status": "disenrolled", "user_id": superuser["user_id"]})

    # The superuser can no longer log in with a password: no challenge, no e-mail.
    response, body = await live.login(superuser)
    assert response.status == 403
    assert body["error"] == "strong_factor_required"
    assert "challenge" not in body
    assert live.emails(superuser) == []

    # Operator procedure: drop is_superuser, e-mail login, enrol TOTP, restore is_superuser.
    await live.set_superuser(superuser["user_id"], False)
    new_secret, _ = await live.enrol_totp(superuser, await live.email_login(superuser))
    await live.set_superuser(superuser["user_id"], True)
    response, body = await live.login(superuser)
    assert response.status == 401
    assert PROVIDER_EMAIL not in body["providers"]
    response, verified = await live.verify(body["challenge"], PROVIDER_TOTP, live.totp(new_secret))
    assert response.status == 200, verified


# ---------------------------------------------------------------------------
# Acceptance sweep
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_2fa_disabled_login_unchanged(monkeypatch, mfa_db, mfa_secret, mfa_user_factory):
    """AC20: with AUTH_BASIC_2FA_ENABLED off the login path carries no MFA surface at all."""
    _patch_settings(monkeypatch, enabled=False, secret=mfa_secret)
    app = web.Application()
    try:
        auth, client = await _start(app)
    except Exception as err:  # pylint: disable=W0718
        pytest.skip(f"live application unavailable: {type(err).__name__}: {err}")
    org_id = None
    try:
        # Even a superuser without any strong factor, in an ENFORCED tenant, is not
        # challenged nor refused: with the flag off the hook does not run at all.
        user = await mfa_user_factory(superuser=True)
        slug = f"mfa-t147-off-{secrets.token_hex(4)}"
        async with await mfa_db.acquire() as conn:
            org_id = await conn.fetchval(
                f"INSERT INTO {ORGS} (organization, org_slug) VALUES ($1, $2) RETURNING org_id", slug, slug
            )
            await conn.fetchval(
                f"INSERT INTO {ORG_USERS} (user_id, org_id) VALUES ($1, $2) RETURNING user_id", user["user_id"], org_id
            )
            await conn.fetchval(
                f"INSERT INTO {POLICY} (org_id, mode, remember_days) VALUES ($1, 'enforced', 0) RETURNING org_id",
                org_id,
            )
        response = await client.post(
            "/api/v1/login", json={"username": user["username"], "password": user["password_plain"]}
        )
        body = await response.json()
        assert response.status == 200, body
        assert set(body) == BASELINE_LOGIN_KEYS
        assert "mfa" not in _claims(body["token"]) and "amr" not in _claims(body["token"])
        assert TRUSTED_COOKIE not in response.cookies
        assert MFA_APP_KEY not in app
        assert not [r for r in app.router.resources() if r.canonical.startswith("/auth/mfa")]
    finally:
        await _stop(auth, client)
        if org_id is not None:
            async with await mfa_db.acquire() as conn:
                await conn.fetchval(f"WITH d AS (DELETE FROM {POLICY} WHERE org_id = $1 RETURNING 1) SELECT 1", org_id)
                await conn.fetchval(f"WITH d AS (DELETE FROM {ORGS} WHERE org_id = $1 RETURNING 1) SELECT 1", org_id)


def test_no_session_minting_reference_in_mfa_package():
    """AC5 (refined by D5): nothing under navigator_auth/mfa mints a session or token itself."""
    package = ROOT / "navigator_auth" / "mfa"
    pattern = re.compile(r"remember\(|create_token|open_session")
    files = [*package.rglob("*.py"), *package.rglob("*.sql")]
    assert files
    matches = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in files
        for number, line in enumerate(path.read_text().splitlines(), 1)
        if pattern.search(line)
    ]
    assert matches == []


def test_no_forbidden_runtime_dependency():
    """AC4: MFA adds no runtime dependency (TOTP via cryptography, no OTP/QR/SMS/fake libraries)."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = " ".join(data.get("project", {}).get("dependencies", [])).lower()
    for forbidden in ("pyotp", "qrcode", "aiosmtplib", "twilio", "sendgrid", "fakeredis"):
        assert forbidden not in dependencies


@pytest.mark.asyncio
async def test_no_secret_in_logs(live, caplog):
    """AC14: across flows 1, 2 and 5 no code, challenge, seed, enrolment token or device cookie is logged."""
    caplog.set_level(logging.DEBUG)
    secrets_seen: list[str] = [MFA_TEST_SECRET.decode()]

    # Flow 1 — e-mail OTP.
    email_user = await live.user()
    await live.org(email_user["user_id"], mode=MfaMode.ENFORCED)
    response, body = await live.login(email_user)
    secrets_seen += [body["challenge"], live.email_code(email_user)]
    response, _ = await live.verify(body["challenge"], PROVIDER_EMAIL, live.email_code(email_user))
    assert response.status == 200

    # Flow 2 — TOTP enrolment and login.
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.OPTIONAL, remember_days=30)
    token = await live.plain_login(user)
    response, started = await live.call("POST", "/auth/mfa/totp/enroll", token, {"password": user["password_current"]})
    code = live.totp(started["secret_b32"])
    response, confirmed = await live.call(
        "POST", "/auth/mfa/totp/confirm", token, {"enrollment_token": started["enrollment_token"], "code": code}
    )
    assert response.status == 200
    secrets_seen += [started["enrollment_token"], started["secret_b32"], started["uri"], code]
    secrets_seen += confirmed["backup_codes"]
    response, body = await live.login(user)
    code = live.totp(started["secret_b32"])
    secrets_seen += [body["challenge"], code]

    # Flow 5 — remember me, then a trusted-device login (rotation).
    response, _ = await live.verify(body["challenge"], PROVIDER_TOTP, code, remember=True)
    first = response.cookies[TRUSTED_COOKIE].value
    response, _ = await live.login(user, cookies={TRUSTED_COOKIE: first})
    assert response.status == 200
    secrets_seen += [first, response.cookies[TRUSTED_COOKIE].value]

    assert caplog.text  # the flows did log
    for value in secrets_seen:
        # Token-boundary match: a 6-digit code must not false-match inside a timestamp or an id.
        assert not re.search(rf"(?<![0-9A-Za-z_-]){re.escape(value)}(?![0-9A-Za-z_-])", caplog.text), value


@pytest.mark.asyncio
async def test_api_login_backend_loop_and_explicit_backend_same_envelope(live):
    """AC32/R2: the backend loop and an explicit X-Auth-Method return the same 401 challenge envelope."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    loop_response, loop_body = await live.login(user)
    explicit_response, explicit_body = await live.login(user, headers={"X-Auth-Method": "BasicAuth"})
    for response, body in ((loop_response, loop_body), (explicit_response, explicit_body)):
        assert response.status == 401
        assert set(body) == CHALLENGE_KEYS
        assert "Set-Cookie" not in response.headers
    assert loop_body["challenge"] != explicit_body["challenge"]
    assert {k: v for k, v in loop_body.items() if k != "challenge"} == {
        k: v for k, v in explicit_body.items() if k != "challenge"
    }


@pytest.mark.asyncio
async def test_redis_outage_refuses_verification(live, broken_redis_pool):
    """AC12: with the challenge store unreachable, a correct code is refused and no session is created."""
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    response, body = await live.login(user)
    assert response.status == 401
    store = live.services.store
    healthy = store._pool
    store._pool = broken_redis_pool
    try:
        response, refused = await live.verify(body["challenge"], PROVIDER_EMAIL, live.email_code(user))
    finally:
        store._pool = healthy
    assert (response.status, refused) == (503, {"error": "mfa_unavailable"})
    # The challenge itself survived the outage (nothing was consumed while refusing).
    async with aioredis.Redis(connection_pool=healthy) as redis:
        keys = [key async for key in redis.scan_iter(match=f"{CHALLENGE_KEY_PREFIX}*")]
    assert len(keys) == 1
