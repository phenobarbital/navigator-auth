"""FEAT-106 TASK-140 verify and resend handler tests."""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from navigator_auth import conf as auth_conf
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.exceptions import MFARefused
from navigator_auth.handlers import setup_handlers
from navigator_auth.handlers.mfa import MFA_PREFIX, MfaHandler
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.types import MfaChallenge, MfaMode, MfaState, TenantMfaPolicy

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]

USER = {"user_id": 7, "username": "alice", "email": "alice@example.test", "is_active": True}


def _record(**over) -> MfaChallenge:
    """Build a deterministic signed challenge record for handler tests."""
    return MfaChallenge(
        user_id=7,
        username="alice",
        providers=("email",),
        preferred="email",
        issued_at=1.0,
        security_version=1,
        context_digest="digest",
        email_code_hash="first",
        signature="signature",
        **over,
    )


def _evaluation(**over):
    """Build a current evaluation matching ``_record`` by default."""
    values = {
        "user_id": 7,
        "policy": TenantMfaPolicy(org_id=1, mode=MfaMode.ENFORCED, remember_days=0, enforced_at=None, enforced_by=None),
        "memberships": (1,),
        "state": MfaState.EMAIL,
        "has_strong_factor": False,
        "totp_confirmed": False,
        "providers": ("email",),
        "preferred": "email",
        "security_version": 1,
        "context_digest": "digest",
    }
    values.update(over)
    return SimpleNamespace(**values)


class FakeStore:
    """In-memory challenge store preserving the handler's observable contracts."""

    def __init__(self, record: MfaChallenge | None = None) -> None:
        self.record = record or _record()
        self.remaining = 5
        self.ttl = 60

    async def peek(self, token: str):
        """Return the current record for the single known test token."""
        return self.record if token == "challenge" else None

    async def consume(self, token: str):
        """Atomically remove and return the current record."""
        if token != "challenge" or self.record is None:
            return None
        record, self.record = self.record, None
        return record

    async def discard(self, token: str) -> None:
        """Discard the current challenge."""
        if token == "challenge":
            self.record = None

    async def register_failure(self, token: str) -> int:
        """Decrement the retry budget and burn at zero."""
        if token != "challenge" or self.record is None:
            return -1
        self.remaining -= 1
        if self.remaining == 0:
            self.record = None
        return self.remaining

    async def replace_email_code(self, token: str, new_code_hash: str):
        """Replace only the email code hash without changing TTL or attempts."""
        if token != "challenge" or self.record is None:
            return None
        self.record = self.record.model_copy(update={"email_code_hash": new_code_hash})
        return self.record

    async def remaining_ttl(self, token: str) -> int:
        """Return the fixed test TTL for live records."""
        return self.ttl if token == "challenge" and self.record else 0


class FakeSecurity:
    """Track the single transaction-like lock used by the handler."""

    @asynccontextmanager
    async def user_lock(self, user_id: int):
        """Yield a sentinel connection for the expected user."""
        assert user_id == 7
        yield object()


class FakeProvider:
    """OTP provider with a configurable accepted code."""

    def __init__(self, accepted: str = "correct") -> None:
        self.accepted = accepted
        self.verify = AsyncMock(side_effect=lambda request, user, code, challenge=None: code == self.accepted)
        self.challenge = AsyncMock(return_value={"code_hash": "second"})


@pytest.fixture
def client():
    """Provide an application with in-memory MFA collaborators."""
    store = FakeStore()
    backend = SimpleNamespace(
        _idp=SimpleNamespace(user_from_id=AsyncMock(return_value=USER)),
        open_session=AsyncMock(return_value={"token": "session", "user_id": 7}),
    )
    provider = FakeProvider()
    services = MfaServices(backend=backend, available=True)
    services.store = store
    services.security = FakeSecurity()
    services.user_limiter = SimpleNamespace(check=AsyncMock(return_value=True))
    services.ip_limiter = SimpleNamespace(check=AsyncMock(return_value=True))
    services.providers = {"email": provider}
    services.trusted_devices = SimpleNamespace(issue=AsyncMock(return_value="device"))
    services.evaluate = AsyncMock(return_value=_evaluation())
    app = web.Application()
    app[AUTH_EXCLUDE_LIST_KEY] = []
    app[MFA_APP_KEY] = MfaServicesSlot(services)
    app["auth"] = SimpleNamespace(finalize_login=AsyncMock(return_value=web.json_response({"ok": True})))
    return SimpleNamespace(app=app, handler=MfaHandler(), mfa_services=services)


async def _post(client, path: str, **body):
    """Call a handler directly without requiring a network socket."""
    request = SimpleNamespace(app=client.app, remote="127.0.0.1", json=AsyncMock(return_value=body))
    response = await (client.handler.verify(request) if path.endswith("/verify") else client.handler.challenge(request))
    return response, json.loads(response.body)


@pytest.mark.asyncio
async def test_concurrent_verify_consumes_once(client):
    """Two correct submissions mint exactly one session."""
    first, second = await asyncio.gather(
        _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"),
        _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"),
    )
    assert sorted((first[0].status, second[0].status)) == [200, 401]
    client.mfa_services.backend.open_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_challenge_retry_budget(client):
    """Four failures retain the challenge; the fifth failure burns it."""
    for remaining in range(4, 0, -1):
        response, body = await _post(
            client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="bad"
        )
        assert response.status == 401
        assert body["attempts_remaining"] == remaining
    assert (await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"))[
        0
    ].status == 200
    client.mfa_services.store = FakeStore()
    for _ in range(5):
        response, _ = await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="bad")
    assert response.status == 401
    assert (await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"))[
        0
    ].status == 401


@pytest.mark.asyncio
async def test_verify_rejects_disallowed_provider(client):
    """A closed or unsigned provider counts as an invalid OTP attempt."""
    response, body = await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="totp", code="correct")
    assert response.status == 401
    assert body == {"error": "invalid_code", "attempts_remaining": 4}


@pytest.mark.asyncio
async def test_stale_challenge_rejected(client):
    """Context drift discards the challenge before provider verification."""
    client.mfa_services.evaluate.return_value = _evaluation(context_digest="new-digest")
    response, body = await _post(
        client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"
    )
    assert response.status == 401
    assert body == {"error": "stale_challenge"}
    assert client.mfa_services.store.record is None


@pytest.mark.asyncio
async def test_strong_factor_required_on_verify(client):
    """A fresh strong-factor refusal discards the challenge and opens no session."""
    client.mfa_services.evaluate.side_effect = MFARefused("strong_factor_required", status=403)
    response, body = await _post(
        client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"
    )
    assert response.status == 403
    assert body["error"] == "strong_factor_required"
    assert client.mfa_services.store.record is None
    client.mfa_services.backend.open_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_expiry_during_verification(client):
    """A vanished challenge after verification cannot open a session."""
    original_consume = client.mfa_services.store.consume

    async def vanish(token: str):
        await client.mfa_services.store.discard(token)
        return await original_consume(token)

    client.mfa_services.store.consume = vanish
    response, _ = await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct")
    assert response.status == 401
    client.mfa_services.backend.open_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_resend_preserves_budget_and_expiry(client):
    """Resend rotates only the code while retaining TTL and retry budget."""
    await client.mfa_services.store.register_failure("challenge")
    response, body = await _post(client, f"{MFA_PREFIX}/challenge", challenge="challenge")
    assert response.status == 202
    assert body == {"status": "accepted", "expires_in": 60}
    assert client.mfa_services.store.record.email_code_hash == "second"
    assert client.mfa_services.store.remaining == 4


@pytest.mark.asyncio
async def test_mfa_verify_finalizes_session(client):
    """A verified factor creates a MFA-marked session then finalizes it."""
    response, _ = await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct")
    assert response.status == 200
    assert client.mfa_services.backend.open_session.await_args.kwargs["extra"] == {
        "auth_method": "basic",
        "mfa": True,
        "amr": ["pwd", "otp"],
    }
    client.app["auth"].finalize_login.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_adapter_email_without_conn_totp_with_lock_conn(client):
    """AC33: the handler adapter omits conn for email and forwards it for TOTP."""
    record = _record().model_copy(update={"providers": ("totp",), "preferred": "totp"})
    client.mfa_services.store = FakeStore(record)
    provider = SimpleNamespace(verify=AsyncMock(return_value=True))
    client.mfa_services.providers = {"totp": provider}
    client.mfa_services.evaluate = AsyncMock(
        return_value=_evaluation(state=MfaState.TOTP, providers=("totp",), preferred="totp")
    )

    response, body = await _post(client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="totp", code="correct")

    assert response.status == 200
    assert body == {"ok": True}
    assert provider.verify.await_args.kwargs["conn"] is not None


@pytest.mark.asyncio
async def test_remember_device_only_when_allowed(client):
    """Trusted-device issuance requires a strong factor and a positive lifetime."""
    response, _ = await _post(
        client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct", remember_device=True
    )
    assert response.status == 200
    client.mfa_services.trusted_devices.issue.assert_not_awaited()


@pytest.mark.asyncio
async def test_verify_fails_closed_when_store_fails(client):
    """Store failures return an unavailable MFA response without a session."""
    client.mfa_services.store.peek = AsyncMock(side_effect=RuntimeError("redis"))
    response, body = await _post(
        client, f"{MFA_PREFIX}/verify", challenge="challenge", provider="email", code="correct"
    )
    assert response.status == 503
    assert body == {"error": "mfa_unavailable"}
    client.mfa_services.backend.open_session.assert_not_awaited()


def test_routes_absent_when_disabled(monkeypatch):
    """The global kill switch leaves MFA routes and exclusions absent."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", False)
    app = web.Application()
    app[AUTH_EXCLUDE_LIST_KEY] = []
    setup_handlers(app, app.router)
    assert all(not route.resource.canonical.startswith(MFA_PREFIX) for route in app.router.routes())
    assert app[AUTH_EXCLUDE_LIST_KEY] == []
