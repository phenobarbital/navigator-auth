"""FEAT-106 factor-management hardening (spec §3 M8; AC19, AC20, AC10)."""

import asyncio
import secrets

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
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
        env.call(
            "disenroll_totp", uid, {"password": user["password_plain"], "code": env.code(secret)[0]}, session
        ),
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
