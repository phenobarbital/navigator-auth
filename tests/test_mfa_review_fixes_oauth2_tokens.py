"""FEAT-106 review fixes — OAuth credential generation primitives.

The endpoint integration coverage lives in the OAuth provider suites.  These
tests retain the durable-wire-format contract for legacy OAuth artifacts.
"""

from datetime import datetime, timedelta

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


def test_generation_claim_is_absent_at_zero_and_present_after_increment() -> None:
    """Generation zero keeps historical JWT payload keys while positive values stamp ``gen``."""
    payload = {"user_id": 7, "client_id": "generation-client", "jti": "token"}

    assert GENERATION_CLAIM not in stamp_generation(dict(payload), 0)
    stamped = stamp_generation(dict(payload), 1)
    assert stamped[GENERATION_CLAIM] == 1
    assert generation_of(payload) == 0
    assert generation_of(stamped) == 1
