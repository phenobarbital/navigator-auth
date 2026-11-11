"""FEAT-106 TASK-138 — BasicAuth second-factor hook unit tests."""

import logging
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth import conf as auth_conf
from navigator_auth.backends.basic import BasicAuth
from navigator_auth.backends.exchange import TokenExchangeAuth
from navigator_auth.backends.passkey import PasskeyAuth
from navigator_auth.exceptions import MFARefused, MFARequired
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot, build_mfa_services
from navigator_auth.mfa.types import (
    MFA_DEVICE_TOKEN_KEY,
    TRUSTED_COOKIE,
    MfaMode,
    MfaState,
    TenantMfaPolicy,
)

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]


def _user(**over):
    """Build an active identity-provider user record."""
    return {
        "user_id": 7,
        "username": "alice",
        "email": "a@x.io",
        "is_active": True,
        "is_superuser": False,
        "password": "pbkdf2_sha256$example",
        **over,
    }


def _backend() -> BasicAuth:
    """Build BasicAuth without its application-wide initialization."""
    backend = BasicAuth.__new__(BasicAuth)
    backend.logger = logging.getLogger("test.mfa")
    backend.userid_attribute = "user_id"
    backend.validate_user = AsyncMock()
    backend.get_payload = AsyncMock(return_value=("alice", "password"))
    backend.open_session = AsyncMock(return_value={"token": "session"})
    return backend


def _policy(days: int = 0) -> TenantMfaPolicy:
    """Return an enforced tenant policy."""
    return TenantMfaPolicy(org_id=1, mode=MfaMode.ENFORCED, remember_days=days, enforced_at=None, enforced_by=None)


def _evaluation(state=MfaState.EMAIL, providers=("email",), preferred="email", strong=False, days=0):
    """Return an evaluation used by hook fakes."""
    return SimpleNamespace(
        user_id=7,
        policy=_policy(days),
        state=state,
        has_strong_factor=strong,
        providers=providers,
        preferred=preferred,
        security_version=1,
        context_digest="digest",
    )


def _services(evaluation=None, available=True) -> MfaServices:
    """Build MFA services with isolated async collaborators."""
    services = MfaServices(backend=None, available=available)
    services.evaluate = AsyncMock(return_value=evaluation or _evaluation())
    services.store = SimpleNamespace(issue=AsyncMock(return_value=("challenge", object())))
    services.trusted_devices = SimpleNamespace(consume_and_rotate=AsyncMock(return_value=None))
    services.providers = {"email": SimpleNamespace(challenge=AsyncMock(return_value={"code_hash": "hash"}))}
    return services


def _request(services, cookie=None):
    """Create a request connected to an application MFA slot."""
    app = web.Application()
    app[MFA_APP_KEY] = MfaServicesSlot(services)
    headers = {"Cookie": f"{TRUSTED_COOKIE}={cookie}"} if cookie else None
    return make_mocked_request("POST", "/auth/basic", headers=headers, app=app)


def test_ownership_rule_excludes_overriding_subclasses():
    """D12: overriding BasicAuth subclasses do not own MFA."""
    assert TokenExchangeAuth.authenticate is not BasicAuth.authenticate
    assert PasskeyAuth.authenticate is not BasicAuth.authenticate


@pytest.mark.asyncio
async def test_disabled_path_is_unchanged(monkeypatch):
    """Flag off leaves the open-session invocation unchanged."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", False)
    backend, user = _backend(), _user()
    backend.validate_user.return_value = user
    result = await backend.authenticate(_request(None))
    assert result == {"token": "session"}
    backend.open_session.assert_awaited_once_with(ANY, user)


@pytest.mark.asyncio
async def test_mfa_required_payload_has_no_token(monkeypatch):
    """An owed factor raises a non-session MFA envelope."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user = _backend(), _user()
    backend.validate_user.return_value = user
    with pytest.raises(MFARequired) as raised:
        await backend.authenticate(_request(_services()))
    assert set(raised.value.payload()) == {"mfa_required", "challenge", "providers", "preferred", "expires_in"}
    backend.open_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_token_exchange_never_challenged(monkeypatch):
    """MFA ownership excludes the token-exchange override."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend = TokenExchangeAuth.__new__(TokenExchangeAuth)
    assert not BasicAuth._owns_mfa(backend)


@pytest.mark.asyncio
async def test_passkey_signin_never_challenged(monkeypatch):
    """MFA ownership excludes the passkey override."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend = PasskeyAuth.__new__(PasskeyAuth)
    assert not BasicAuth._owns_mfa(backend)


@pytest.mark.asyncio
async def test_missing_mfa_tables_refuse_login(monkeypatch):
    """Unavailable services fail closed at the hook."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user = _backend(), _user()
    backend.validate_user.return_value = user
    with pytest.raises(MFARefused) as raised:
        await backend.authenticate(_request(_services(available=False)))
    assert raised.value.status == 503


@pytest.mark.asyncio
async def test_policy_read_is_per_login_not_cached():
    """The hook delegates every login to the service evaluation."""
    services = _services(_evaluation(state=MfaState.NONE, providers=(), preferred=None))
    await services.evaluate(_user())
    await services.evaluate(_user())
    assert services.evaluate.await_count == 2


@pytest.mark.asyncio
async def test_policy_read_failure_fails_closed(monkeypatch):
    """Evaluation failures become unavailable MFA responses."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user, services = _backend(), _user(), _services()
    backend.validate_user.return_value = user
    services.evaluate.side_effect = RuntimeError("db")
    with pytest.raises(MFARefused) as raised:
        await backend.authenticate(_request(services))
    assert raised.value.status == 503
    backend.open_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_enforced_superuser_requires_strong_factor_at_login(monkeypatch):
    """A propagated strong-factor refusal precedes trusted-device handling."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user, services = _backend(), _user(is_superuser=True), _services()
    backend.validate_user.return_value = user
    services.evaluate.side_effect = MFARefused("strong_factor_required", status=403)
    with pytest.raises(MFARefused) as raised:
        await backend.authenticate(_request(services, "raw"))
    assert raised.value.code == "strong_factor_required"
    services.trusted_devices.consume_and_rotate.assert_not_awaited()


@pytest.mark.asyncio
async def test_trusted_device_skips_otp_with_honest_amr(monkeypatch):
    """A valid trusted device returns a rotated, non-persisted raw token."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user = _backend(), _user()
    backend.validate_user.return_value = user
    services = _services(_evaluation(state=MfaState.TOTP, providers=("totp",), preferred="totp", strong=True, days=2))
    services.trusted_devices.consume_and_rotate.return_value = (7, "rotated")
    result = await backend.authenticate(_request(services, "raw"))
    assert result[MFA_DEVICE_TOKEN_KEY] == {"token": "rotated", "max_age": 172800}
    assert backend.open_session.await_args.kwargs["extra"] == {"auth_method": "basic", "mfa": True, "amr": ["pwd", "trusted_device"]}


@pytest.mark.asyncio
async def test_trusted_device_ignored_for_email_state(monkeypatch):
    """Weak email state does not consume a trusted-device cookie."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user = _backend(), _user()
    backend.validate_user.return_value = user
    services = _services(_evaluation(days=3))
    with pytest.raises(MFARequired):
        await backend.authenticate(_request(services, "raw"))
    services.trusted_devices.consume_and_rotate.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_provider_refused(monkeypatch):
    """An owed factor without an available provider is refused."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user = _backend(), _user()
    backend.validate_user.return_value = user
    with pytest.raises(MFARefused) as raised:
        await backend.authenticate(_request(_services(_evaluation(providers=(), preferred=None))))
    assert raised.value.code == "no_factor_available"


@pytest.mark.asyncio
async def test_storage_error_during_issue_fails_closed(monkeypatch):
    """Challenge storage errors never continue to another backend."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user, services = _backend(), _user(), _services()
    backend.validate_user.return_value = user
    services.store.issue.side_effect = RuntimeError("redis")
    with pytest.raises(MFARefused) as raised:
        await backend.authenticate(_request(services))
    assert raised.value.status == 503


@pytest.mark.asyncio
async def test_email_preferred_issues_code_hash(monkeypatch):
    """Email delivery hash is bound into the challenge issue call."""
    monkeypatch.setattr(auth_conf, "AUTH_BASIC_2FA_ENABLED", True)
    backend, user, services = _backend(), _user(), _services()
    backend.validate_user.return_value = user
    with pytest.raises(MFARequired):
        await backend.authenticate(_request(services))
    assert services.store.issue.await_args.kwargs["email_code_hash"] == "hash"


@pytest.mark.asyncio
async def test_builder_without_secret_is_unavailable(monkeypatch):
    """The startup builder returns an unavailable container without a secret."""
    monkeypatch.setattr(auth_conf, "AUTH_OTP_SECRET", None)
    services = await build_mfa_services(web.Application(), object())
    assert not services.available
