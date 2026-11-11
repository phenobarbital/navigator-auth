"""FEAT-106 review fixes — OAuth credential generation primitives.

The endpoint integration coverage lives in the OAuth provider suites.  These
tests retain the durable-wire-format contract for legacy OAuth artifacts.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import navigator_auth.conf as conf
from navigator_auth.backends.oauth2 import backend as oauth_backend
from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthAuthorizationCode,
    OauthRefreshToken,
    is_oauth_user_token,
)
from navigator_auth.security_state.store import GENERATION_CLAIM, generation_of, stamp_generation


def _client() -> OAuthClient:
    """Build the minimum OAuth client used by the carrier models."""
    return OAuthClient(
        client_id="generation-client",
        client_name="Generation test client",
        client_type="public",
        redirect_uris=["https://client.example/callback"],
    )


def test_is_oauth_user_token_shapes() -> None:
    """Generation checks apply only to OAuth access tokens minted for users."""
    assert is_oauth_user_token({"client_id": "client", "user_id": 7, "jti": "token"})
    assert not is_oauth_user_token({"user_id": 7, "jti": "basic-auth"})
    assert not is_oauth_user_token({"client_id": "client", "jti": "machine"})
    assert not is_oauth_user_token({})


def test_models_default_generation_zero_for_legacy_payloads() -> None:
    """OAuth carrier models deserialize legacy records without a generation."""
    client = _client()
    code = OauthAuthorizationCode(
        client=client,
        user_id=7,
        code="authorization-code",
        redirect_uri="https://client.example/callback",
        scope="default",
        state="state",
    )
    refresh = OauthRefreshToken(
        client=client,
        user_id=7,
        refresh_token="refresh-token",
        scope="default",
        expires_at=datetime.now() + timedelta(hours=1),
        absolute_expires_at=datetime.now() + timedelta(hours=2),
    )

    assert code.generation == 0
    assert refresh.generation == 0


def test_models_default_to_no_assurance_for_legacy_payloads() -> None:
    """Stored records without MFA fields remain readable after the schema change."""
    client = _client()
    refresh = OauthRefreshToken(
        client=client,
        user_id=7,
        refresh_token="refresh-token",
        scope="default",
        expires_at=datetime.now() + timedelta(hours=1),
        absolute_expires_at=datetime.now() + timedelta(hours=2),
    )
    legacy = {key: value for key, value in refresh.model_dump().items() if key not in ("mfa", "amr")}
    restored = OauthRefreshToken(**legacy)

    assert restored.mfa is False
    assert restored.amr is None


@pytest.fixture
def event_provider(monkeypatch):
    """Build a provider with a real event-validation method and isolated dependencies."""
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", True)
    provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    provider._load_auth_event = AsyncMock(
        return_value={"session_id": "session-1", "user_id": 7, "mfa": True, "amr": ["pwd", "totp"]}
    )
    monkeypatch.setattr(
        oauth_backend,
        "get_session",
        AsyncMock(
            return_value=SimpleNamespace(
                session_id="session-1",
                **{
                    "get": lambda key, default=None: {
                        "user": '{"__dict__": {"user_id": 7, "username": "alice"}}'
                    }.get(key, default)
                },
            )
        ),
    )
    return provider


@pytest.mark.asyncio
async def test_session_auth_context_returns_event_assurance(event_provider) -> None:
    """An event bound to the current session and user supplies the MFA carrier fields."""
    context = await event_provider._session_auth_context(MagicMock())

    assert context == {"mfa": True, "amr": ["pwd", "totp"]}


@pytest.mark.asyncio
async def test_session_auth_context_rejects_foreign_event(event_provider) -> None:
    """A foreign event cannot lend assurance to the current browser session."""
    event_provider._load_auth_event.return_value["session_id"] = "other-session"

    with pytest.raises(oauth_backend.InvalidAuth):
        await event_provider._session_auth_context(MagicMock())


@pytest.mark.asyncio
async def test_session_auth_context_missing_event_has_no_assurance(event_provider) -> None:
    """Sessions without an OAuth event remain usable without inheriting MFA claims."""
    event_provider._load_auth_event.return_value = None

    assert await event_provider._session_auth_context(MagicMock()) == {}


def test_generation_claim_is_absent_at_zero_and_present_after_increment() -> None:
    """Generation zero keeps historical JWT payload keys while positive values stamp ``gen``."""
    payload = {"user_id": 7, "client_id": "generation-client", "jti": "token"}

    assert GENERATION_CLAIM not in stamp_generation(dict(payload), 0)
    stamped = stamp_generation(dict(payload), 1)
    assert stamped[GENERATION_CLAIM] == 1
    assert generation_of(payload) == 0
    assert generation_of(stamped) == 1
