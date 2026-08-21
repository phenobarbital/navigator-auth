"""Regression tests for the 3LO end-to-end path (see examples/oauth2_3lo_server.py).

The Authorization-Code + PKCE flow only becomes usable when the *issued* access
token can actually authenticate a request. These tests lock down the four
defects that broke that path:

1. ``IdentityProvider.decode_token`` rejected every token carrying an ``aud``
   claim — which is every 3LO access token, since ``create_token`` is called
   with ``audience="user"``.
2. ``Oauth2Provider`` minted access tokens with no session linkage, so
   ``auth_middleware`` / ``@user_session()`` could not resolve a user from them.
3. The login and consent templates dropped ``code_challenge``, so PKCE never
   survived the interactive hops and public clients failed the exchange.
4. ``_get_request_user_id`` read ``request["userinfo"]``, a key nothing sets,
   making the grants API answer 401 to authenticated users.
"""

import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.idp import IdentityProvider
from navigator_auth.backends.oauth2.backend import Oauth2Provider


TEMPLATES = Path(__file__).resolve().parent.parent / "templates" / "oauth"


# ---------------------------------------------------------------------------
# 1. decode_token and the `aud` claim
# ---------------------------------------------------------------------------

@pytest.fixture
def idp():
    return IdentityProvider()


class TestDecodeTokenAudience:
    def test_token_with_audience_is_decodable(self, idp):
        """A 3LO access token (aud='user') must decode by default."""
        token, _, _, _ = idp.create_token(
            {"user_id": 7, "client_id": "app", "scope": "default"},
            expiration=300,
            audience="user",
        )
        _, payload = idp.decode_token(token)
        assert payload["user_id"] == 7
        assert payload["aud"] == "user"

    def test_token_without_audience_still_decodable(self, idp):
        token, _, _, _ = idp.create_token({"user_id": 7}, expiration=300)
        _, payload = idp.decode_token(token)
        assert payload["user_id"] == 7
        assert "aud" not in payload

    def test_audience_is_verified_when_requested(self, idp):
        """Opt-in verification still rejects a token minted for another audience."""
        token, _, _, _ = idp.create_token(
            {"user_id": 7}, expiration=300, audience="app"
        )
        assert idp.decode_token(token, audience="app")[1]["user_id"] == 7
        with pytest.raises(Exception):
            idp.decode_token(token, audience="user")


# ---------------------------------------------------------------------------
# 2. Access tokens are bound to a session
# ---------------------------------------------------------------------------

class DummyUser(dict):
    """Minimal stand-in for a navigator-auth User row."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__dict__.update(kwargs)
        self.is_authenticated = False


@pytest.fixture
def provider():
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.logger = MagicMock()
    return prov


def make_request(storage):
    """A request-like mapping carrying an app with an AuthHandler session."""
    auth = MagicMock()
    auth.session.storage = storage
    request = MagicMock()
    store = {}
    request.get = lambda key, default=None: store.get(key, default)
    request.pop = lambda key, default=None: store.pop(key, default)
    request.__setitem__ = lambda self_, key, value: store.__setitem__(key, value)
    request.app = {"auth": auth}
    request.store = store
    return request


class TestTokenSessionBinding:
    @pytest.mark.asyncio
    async def test_claims_carry_session_and_identity(self, provider):
        session = MagicMock()
        session.session_id = "sess-abc"
        storage = MagicMock()
        storage.new_session = AsyncMock(return_value=session)

        provider._idp.user_from_id = AsyncMock(
            return_value=DummyUser(user_id=11, username="demo")
        )
        request = make_request(storage)

        claims = await provider._token_session_claims(request, 11)

        assert claims == {
            provider.session_key_property: "demo",
            provider.session_id_property: "sess-abc",
            provider.username_attribute: "demo",
        }
        # The session must actually hold the encoded user for @user_session().
        _, session_data = storage.new_session.call_args[0]
        assert "user" in session_data
        assert session_data[provider.session_key_property] == "demo"

    @pytest.mark.asyncio
    async def test_unknown_user_degrades_without_raising(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=RuntimeError("no such user"))
        request = make_request(MagicMock())
        assert await provider._token_session_claims(request, 404) == {}


# ---------------------------------------------------------------------------
# 3. PKCE survives the interactive hops
# ---------------------------------------------------------------------------

class TestPkcePropagation:
    @pytest.mark.parametrize("template", ["login.html", "consent.html"])
    def test_template_forwards_the_code_challenge(self, template):
        body = (TEMPLATES / template).read_text()
        for field in ("code_challenge", "code_challenge_method"):
            assert re.search(
                rf'name="{field}"\s+value="{{{{\s*{field}\s*}}}}"', body
            ), f"{template} does not forward {field}"


# ---------------------------------------------------------------------------
# 4. The grants API can identify the caller
# ---------------------------------------------------------------------------

class TestRequestUserId:
    def test_reads_the_token_claims(self, provider):
        request = MagicMock()
        request.get = {"userdata": {"user_id": "31"}}.get
        assert provider._get_request_user_id(request) == 31

    def test_falls_back_to_the_session_user(self, provider):
        request = MagicMock()
        request.get = {}.get
        request.user = DummyUser(user_id=5, username="demo")
        assert provider._get_request_user_id(request) == 5

    def test_returns_none_when_anonymous(self, provider):
        request = MagicMock()
        request.get = {}.get
        request.user = None
        assert provider._get_request_user_id(request) is None
