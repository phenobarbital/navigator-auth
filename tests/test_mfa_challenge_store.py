"""Focused contract tests for the MFA Redis state primitives."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.store import MfaChallengeStore, canonical_json, new_opaque_token
from navigator_auth.mfa.types import PendingEnrollment


def test_canonical_json_is_stable():
    """Canonical encoding is independent of mapping insertion order."""
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_opaque_token_is_url_safe_and_unique():
    """Opaque tokens are non-empty and suitable for URL transport."""
    token = new_opaque_token()
    assert token
    assert json.loads(json.dumps(token)) == token


def test_pending_enrollment_digest_is_signed_and_required() -> None:
    """Legacy contextless records and digest tampering cannot authorize enrollment."""
    store = MfaChallengeStore(None, b"test-secret")
    fields = {
        "user_id": 1,
        "session_hash": "session",
        "security_version": 0,
        "context_digest": "context",
        "sealed_seed": "sealed",
        "issued_at": 1.0,
    }
    record = {**fields, "signature": store._sign(fields)}
    assert store._decode(json.dumps(record), PendingEnrollment).context_digest == "context"
    assert store._decode(json.dumps({**record, "context_digest": "other"}), PendingEnrollment) is None
    del fields["context_digest"]
    assert store._decode(json.dumps({**fields, "signature": store._sign(fields)}), PendingEnrollment) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["6.0.20", "6.2.0", "7.4.1", "malformed"])
async def test_redis_capability_check_is_read_only(monkeypatch, version: str) -> None:
    """Startup requires the actual minimum GETDEL version without creating or mutating keys."""
    redis = SimpleNamespace(info=AsyncMock(return_value={"redis_version": version}))
    client = AsyncMock()
    client.__aenter__.return_value = redis
    store = MfaChallengeStore(None, b"secret")
    monkeypatch.setattr(store, "_redis", lambda: client)
    if version in ("6.2.0", "7.4.1"):
        await store.check_capabilities()
    else:
        with pytest.raises(MfaStorageError):
            await store.check_capabilities()
    redis.info.assert_awaited_once_with("server")


@pytest.mark.asyncio
async def test_unsupported_redis_makes_services_unavailable(monkeypatch) -> None:
    """A failed startup capability check never publishes usable MFA services."""
    from navigator_auth.mfa import services

    pool = SimpleNamespace(disconnect=AsyncMock())
    monkeypatch.setattr(services.auth_conf, "AUTH_OTP_SECRET", "test-secret")
    monkeypatch.setattr(services, "setup_mfa_tables", AsyncMock(return_value=True))
    monkeypatch.setattr(services.aioredis.ConnectionPool, "from_url", lambda *args, **kwargs: pool)
    monkeypatch.setattr(MfaChallengeStore, "check_capabilities", AsyncMock(side_effect=MfaStorageError("old Redis")))
    result = await services.build_mfa_services({"authdb": object()}, object())
    assert not result.available
    pool.disconnect.assert_awaited_once()
