"""FEAT-108 M7 — /oauth2/userinfo omits the claims it cannot supply (S4)."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.exceptions import UserNotFound


PAYLOAD = {"user_id": 35, "scope": "default profile email", "jti": "j-1"}


@pytest.fixture
def provider():
    """Build an OAuth2 provider with a deterministic bearer payload."""
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.logger = MagicMock()
    prov.access_token_storage = None
    prov._idp.decode_token = MagicMock(return_value=("Bearer", dict(PAYLOAD)))
    return prov


def _request():
    """Build a request carrying the bearer token consumed by userinfo."""
    request = MagicMock()
    request.headers = {"Authorization": "Bearer tok"}
    return request


@pytest.mark.asyncio
async def test_userinfo_omits_unknown_claims(provider):
    """Omit scope-gated claims when the IdP cannot resolve the user."""
    provider._idp.user_from_id = AsyncMock(side_effect=UserNotFound("gone"))

    body = json.loads((await provider.userinfo(_request())).body)

    assert body == {"sub": "35"}


@pytest.mark.asyncio
async def test_userinfo_full_profile(provider):
    """Return populated profile and email claims for a resolved user."""
    user = SimpleNamespace(username="demo", first_name="Demo", last_name="User", email="demo@example.com")
    provider._idp.user_from_id = AsyncMock(return_value=user)

    body = json.loads((await provider.userinfo(_request())).body)

    assert body["username"] == "demo"
    assert body["given_name"] == "Demo"
    assert body["family_name"] == "User"
    assert body["email"] == "demo@example.com"
