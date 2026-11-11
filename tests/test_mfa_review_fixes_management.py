"""FEAT-106 factor-management hardening (spec §3 M8; AC19, AC20, AC10)."""

import asyncio
import secrets
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.handlers.mfa import MfaHandler
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.limiter import StrictRateLimiter
from navigator_auth.mfa.types import MfaState
from navigator_auth.passkey.migrations import ensure_passkey_tables
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
    single_connection_authdb,
)
from tests.test_mfa_enrollment_security import Env, FakeSession, env  # noqa: F401


@pytest.mark.asyncio
async def test_management_context_uses_shared_evaluation() -> None:
    """Management keeps the evaluator's policy/state/digest and the caller's connection."""
    record, conn, policy = object(), object(), object()
    evaluation = SimpleNamespace(policy=policy, state=MfaState.TOTP, has_strong_factor=True, context_digest="digest")
    services = SimpleNamespace(evaluate=AsyncMock(return_value=evaluation))
    assert await MfaHandler()._security_context(services, record, conn) == (policy, MfaState.TOTP, True, "digest")
    services.evaluate.assert_awaited_once_with(record, conn=conn)


@pytest.mark.asyncio
async def test_enforced_superuser_without_factor_cannot_start_enrollment(env) -> None:
    """The shared evaluator's strong-factor refusal survives the HTTP management boundary."""
    user = await env.new_user(superuser=True)
    await env.enforced_org(user["user_id"])
    response, body = await env.enroll(user, FakeSession(user["user_id"]))
    assert response.status == 403
    assert body == {"error": "strong_factor_required", "message": "strong_factor_required"}
    assert response.headers["Cache-Control"] == "no-store"
    assert not await env.services.state.totp_confirmed(user["user_id"])


@pytest.mark.asyncio
async def test_enforced_ordinary_user_can_enroll(env) -> None:
    """Session-authenticated ordinary users retain enrollment access under enforced policy."""
    user = await env.new_user()
    await env.enforced_org(user["user_id"])
    session = FakeSession(user["user_id"])
    response, started = await env.enroll(user, session)
    assert response.status == 201
    response, confirmed = await env.confirm(
        user, session, started["enrollment_token"], env.code(started["secret_b32"])[0]
    )
    assert response.status == 200
    assert confirmed["status"] == "confirmed"


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["enroll_totp", "disenroll_totp", "backup_codes"])
@pytest.mark.parametrize("refused_by", ["user", "ip"])
async def test_management_limits_precede_all_proofs(env, monkeypatch, method: str, refused_by: str) -> None:
    """Both limits reject each route before password checks or consumable proofs."""
    user, session, secret, codes = await env.enrolled_user()
    uid = user["user_id"]
    active = await env.active_seed_row(uid)
    user_check = AsyncMock(return_value=refused_by != "user")
    ip_check = AsyncMock(return_value=refused_by != "ip")
    password, totp, backup = Mock(), AsyncMock(), AsyncMock()
    monkeypatch.setattr(env.services.user_limiter, "check", user_check)
    monkeypatch.setattr(env.services.ip_limiter, "check", ip_check)
    monkeypatch.setattr(env.services.backend._idp, "check_password", password)
    monkeypatch.setattr(env.services.providers["totp"], "verify", totp)
    monkeypatch.setattr(env.services.backup_codes, "consume", backup)
    response, body = await env.call(
        method, uid, {"password": user["password_plain"], "code": env.code(secret)[0], "backup_code": codes[0]}, session
    )
    assert (response.status, body) == (429, {"error": "rate_limited"})
    user_check.assert_awaited_once_with(f"mgmt:{uid}")
    if refused_by == "ip":
        ip_check.assert_awaited_once_with("127.0.0.1")
    password.assert_not_called()
    totp.assert_not_awaited()
    backup.assert_not_awaited()
    assert await env.active_seed_row(uid) == active


@pytest.mark.asyncio
async def test_management_wrong_password_and_proof_share_budget(env, monkeypatch) -> None:
    """Failed password and factor proofs consume the shared budget across management routes."""
    user, session, secret, _ = await env.enrolled_user()
    uid = user["user_id"]
    active = await env.active_seed_row(uid)
    monkeypatch.setattr(env.services, "user_limiter", StrictRateLimiter(env.redis_pool, "2/hour", "management-test"))
    response, body = await env.call("enroll_totp", uid, {"password": "wrong"}, session)
    assert (response.status, body) == (403, {"error": "invalid_credentials"})
    response, body = await env.call(
        "backup_codes", uid, {"password": user["password_plain"], "code": "invalid"}, session
    )
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})
    response, body = await env.call(
        "disenroll_totp", uid, {"password": user["password_plain"], "code": env.code(secret)[0]}, session
    )
    assert (response.status, body) == (429, {"error": "rate_limited"})
    assert await env.active_seed_row(uid) == active


@pytest.mark.asyncio
async def test_backup_regeneration_requires_proof(env):
    """AC19: password-only regeneration fails; TOTP or an unused backup code replaces the old set."""
    user, session, secret, old_codes = await env.enrolled_user()
    uid = user["user_id"]

    response, body = await env.call("backup_codes", uid, {"password": user["password_plain"]}, session)
    assert (response.status, body) == (403, {"error": "strong_factor_proof_required"})

    response, body = await env.call(
        "backup_codes", uid, {"password": user["password_plain"], "code": env.code(secret)[0]}, session
    )
    assert response.status == 201
    assert not await env.services.backup_codes.consume(uid, old_codes[0])

    replacement = body["backup_codes"]
    response, body = await env.call(
        "backup_codes", uid, {"password": user["password_plain"], "backup_code": replacement[0]}, session
    )
    assert response.status == 201
    assert not await env.services.backup_codes.consume(uid, replacement[0])
    assert len(body["backup_codes"]) == body["count"]


@pytest.mark.asyncio
async def test_disenroll_guard_under_lock_race(env):
    """AC20: concurrent TOTP removal and final passkey deletion leave at least one strong factor."""
    await ensure_passkey_tables(env.db)
    user, session, secret, _ = await env.enrolled_user(superuser=True)
    uid = user["user_id"]
    await env.enforced_org(uid)
    credential_id = secrets.token_bytes(32)
    await env.one(
        f"INSERT INTO {AUTH_DB_SCHEMA}.user_credentials "
        "(credential_id, user_id, rp_id, public_key) VALUES ($1, $2, $3, $4) RETURNING 1",
        credential_id,
        uid,
        "example.test",
        b"public-key",
    )

    async def delete_last_passkey() -> int:
        """Mirror the passkey deletion lock guard from ``PasskeyAuth.delete_credential``."""
        try:
            async with env.services.security.user_lock(uid) as conn:
                totp = await env.services.state.totp_confirmed(uid, conn=conn)
                count = await env.services.state.passkey_count(uid, conn=conn)
                if not totp and count <= 1:
                    return 409
                await conn.execute(
                    f"DELETE FROM {AUTH_DB_SCHEMA}.user_credentials WHERE credential_id = $1", credential_id
                )
                return 200
        except MfaStorageError:
            return 503

    response, body = await asyncio.gather(
        env.call("disenroll_totp", uid, {"password": user["password_plain"], "code": env.code(secret)[0]}, session),
        delete_last_passkey(),
    )
    statuses = sorted((response[0].status, body))
    assert statuses == [200, 409]
    assert await env.services.state.has_strong_factor(user)


@pytest.mark.asyncio
async def test_disenroll_prelock_storage_error_is_503(env, monkeypatch):
    """AC20: a storage failure before acquiring the user lock is returned as 503, never a 500."""
    user, session, secret, _ = await env.enrolled_user()

    async def unavailable(_record):
        """Model an unavailable provider store during the pre-lock enrolment check."""
        raise MfaStorageError("test unavailable")

    monkeypatch.setattr(env.services.providers["totp"], "is_enrolled", unavailable)
    response, body = await env.call(
        "disenroll_totp", user["user_id"], {"password": user["password_plain"], "code": env.code(secret)[0]}, session
    )
    assert (response.status, body) == (503, {"error": "mfa_unavailable"})


@pytest.mark.asyncio
async def test_management_single_connection_pool(single_connection_authdb):
    """AC10: the lock-aware one-connection fixture detects no nested acquire attempts in this task's lock guard."""
    single_connection_authdb.strict = True
    assert single_connection_authdb.acquires_inside_lock == []
