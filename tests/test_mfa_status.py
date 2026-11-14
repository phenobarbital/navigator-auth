# ruff: noqa: F811
"""GET /auth/mfa/status — read-only second-factor summary of the session's own user.

Drives the real ``MfaHandler.status`` over the live stores (Postgres + Redis) through the
``env`` fixture of ``test_mfa_enrollment_security``: real ``MfaServices``, real policy
resolver, real backup-code and trusted-device stores. Only the session lookup is stubbed,
exactly as in the other management-endpoint suites.
"""

import json

import pytest
from aiohttp import web

from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.handlers.mfa import MFA_PREFIX, setup_mfa_routes
from navigator_auth.mfa.exceptions import MfaStorageError
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
)
from tests.test_mfa_enrollment_security import AUDIT, env  # noqa: F401

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]

STATUS_KEYS = {
    "totp",
    "passkeys",
    "has_strong_factor",
    "backup_codes_remaining",
    "trusted_devices",
    "policy",
    "strong_factor_required",
    "login_blocked",
}


async def _status(env, user_id: int, **kwargs):  # noqa: F811
    """Call the handler and return ``(response, decoded_body)``."""
    return await env.call("status", user_id, {}, **kwargs)


@pytest.mark.asyncio
async def test_status_requires_a_session(env):  # noqa: F811
    """Without an authenticated session the endpoint refuses, like every management route."""
    user = await env.new_user()
    with pytest.raises(web.HTTPUnauthorized):
        await _status(env, user["user_id"], authenticated=False)


@pytest.mark.asyncio
async def test_status_of_a_user_without_factors(env):  # noqa: F811
    """A fresh user: nothing enrolled, no organization, so the policy is OFF."""
    user = await env.new_user()
    response, body = await _status(env, user["user_id"])

    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert set(body) == STATUS_KEYS
    assert body["totp"] is False
    assert body["passkeys"] == 0
    assert body["has_strong_factor"] is False
    assert body["backup_codes_remaining"] == 0
    assert body["trusted_devices"] == 0
    assert body["policy"] == {"mode": "off", "remember_days": 0}
    assert body["strong_factor_required"] is False
    assert body["login_blocked"] is False


@pytest.mark.asyncio
async def test_status_after_totp_enrollment(env):  # noqa: F811
    """A confirmed TOTP is a strong factor and the initial backup set is counted."""
    user, _session, _secret, codes = await env.enrolled_user()
    response, body = await _status(env, user["user_id"])

    assert response.status == 200
    assert body["totp"] is True
    assert body["has_strong_factor"] is True
    assert body["backup_codes_remaining"] == len(codes) > 0


@pytest.mark.asyncio
async def test_status_counts_only_unused_backup_codes(env):  # noqa: F811
    """Consuming a backup code lowers the remaining count by exactly one."""
    user, _session, _secret, codes = await env.enrolled_user()
    uid = user["user_id"]
    assert await env.services.backup_codes.consume(uid, codes[0]) is True

    _, body = await _status(env, uid)
    assert body["backup_codes_remaining"] == len(codes) - 1


@pytest.mark.asyncio
async def test_status_reports_enforced_policy_and_superuser_requirement(env):  # noqa: F811
    """Under ENFORCED a superuser owes a strong factor; an ordinary member does not."""
    admin = await env.new_user(superuser=True)
    member = await env.new_user()
    await env.enforced_org(admin["user_id"], member["user_id"])

    admin_response, admin_body = await _status(env, admin["user_id"])
    _, member_body = await _status(env, member["user_id"])

    # The status must still answer for the user the login refuses: they need this page to enrol.
    assert admin_response.status == 200
    assert admin_body["policy"]["mode"] == "enforced"
    assert admin_body["strong_factor_required"] is True
    assert admin_body["login_blocked"] is True
    assert member_body["policy"]["mode"] == "enforced"
    assert member_body["strong_factor_required"] is False
    assert member_body["login_blocked"] is False


@pytest.mark.asyncio
async def test_status_enforced_superuser_with_totp_is_not_blocked(env):  # noqa: F811
    """A strong factor clears the block even though one stays required."""
    admin, _session, _secret, _codes = await env.enrolled_user(superuser=True)
    await env.enforced_org(admin["user_id"])

    _, body = await _status(env, admin["user_id"])
    assert body["strong_factor_required"] is True
    assert body["has_strong_factor"] is True
    assert body["login_blocked"] is False


@pytest.mark.asyncio
async def test_status_never_returns_secrets_or_internal_identifiers(env):  # noqa: F811
    """No seed, backup code, organization id, digest or security version in the body."""
    user, _session, secret_b32, codes = await env.enrolled_user()
    response, body = await _status(env, user["user_id"])
    raw = response.body.decode() if isinstance(response.body, bytes) else str(response.body)

    assert secret_b32 not in raw
    for code in codes:
        assert code not in raw
    for forbidden in ("org_id", "memberships", "context_digest", "security_version", "secret", "uri"):
        assert forbidden not in json.dumps(body)


@pytest.mark.asyncio
async def test_status_is_read_only(env):  # noqa: F811
    """Reading the status bumps no security version and writes no audit row."""
    user, _session, _secret, _codes = await env.enrolled_user()
    uid = user["user_id"]
    version_before = await env.version(uid)
    audit_before = len(await env.audit(uid))

    for _ in range(3):
        response, _ = await _status(env, uid)
        assert response.status == 200

    assert await env.version(uid) == version_before
    assert len(await env.audit(uid)) == audit_before


@pytest.mark.asyncio
async def test_status_storage_failure_is_mfa_unavailable(env, monkeypatch):  # noqa: F811
    """A storage read failure answers 503 mfa_unavailable, never a partial summary."""
    user = await env.new_user()

    async def _broken(*_args, **_kwargs):
        raise MfaStorageError("backup code count failed")

    monkeypatch.setattr(env.services.backup_codes, "remaining", _broken)
    response, body = await _status(env, user["user_id"])
    assert (response.status, body) == (503, {"error": "mfa_unavailable"})


def test_status_route_is_registered_and_requires_a_session():
    """GET /auth/mfa/status is mounted with the MFA routes and is NOT excluded from auth."""
    app = web.Application()
    app[AUTH_EXCLUDE_LIST_KEY] = []
    setup_mfa_routes(app, app.router)

    path = f"{MFA_PREFIX}/status"
    routes = {(route.method, route.resource.canonical) for route in app.router.routes()}
    assert ("GET", path) in routes
    assert app.router["mfa_status"].canonical == path
    assert path not in app[AUTH_EXCLUDE_LIST_KEY]
