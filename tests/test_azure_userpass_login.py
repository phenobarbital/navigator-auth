"""Regression tests for the AzureAuth user/password login path.

issue:a3580b2685e9 — the whole login body (profile fetch, user validation,
credential capture, home redirect) used to live inside the
``if not result:`` cache-miss branch, so a successful
``acquire_token_silent`` cache hit fell straight through
``authenticate()`` and returned ``None`` instead of logging the user in.

Mock-based: no MSAL network calls, no Graph, no Postgres.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.azure import AzureAuth

# Same out-of-scope aiohttp deprecation quirk the other backend suites mute.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

GRAPH_PROFILE = {
    "id": "graph-oid-123",
    "userPrincipalName": "user@example.com",
    "displayName": "Test User",
    "mail": "user@example.com",
}
HOME_REDIRECT = object()


def _msal_result(access_token: str) -> dict:
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": "RT.1",
        "id_token": "ID.1",
        "expires_in": 3600,
        "scope": "User.ReadBasic.All",
    }


class FakeMsalApp:
    """ClientApplication double recording which grant was used."""

    def __init__(self, accounts=None, silent_result=None, password_result=None):
        self._accounts = accounts or []
        self._silent_result = silent_result
        self._password_result = password_result
        self.silent_calls = []
        self.password_calls = []

    def get_accounts(self, username=None):
        return self._accounts

    def acquire_token_silent(self, scopes, account=None):
        self.silent_calls.append((scopes, account))
        return self._silent_result

    def acquire_token_by_username_password(self, user, pwd, scopes):
        self.password_calls.append((user, pwd, scopes))
        return self._password_result


def _backend(app: FakeMsalApp) -> AzureAuth:
    be = AzureAuth(user_model=object)
    be.userinfo_uri = "https://graph.microsoft.com/v1.0/me"
    be.user_mapping = {}
    be.get_payload = AsyncMock(return_value=("user@example.com", "secret"))
    be.get_finish_redirect_url = MagicMock(return_value=None)
    be.get_msal_client = MagicMock(return_value=app)
    be.get = AsyncMock(return_value=dict(GRAPH_PROFILE))
    be.build_user_info = MagicMock(return_value=({"email": "user@example.com"}, 35))
    be.validate_user_info = AsyncMock(return_value={"token": "SESSION.TOKEN"})
    be.capture_login_credential = AsyncMock()
    be.home_redirect = MagicMock(return_value=HOME_REDIRECT)
    return be


@pytest.mark.asyncio
async def test_silent_cache_hit_still_completes_login():
    """A cached token must drive the same login body as a fresh grant."""
    app = FakeMsalApp(
        accounts=[{"username": "user@example.com", "home_account_id": "hai-1"}],
        silent_result=_msal_result("AT.cached"),
    )
    be = _backend(app)

    response = await be.authenticate(make_mocked_request("GET", "/login"))

    assert response is HOME_REDIRECT
    assert app.silent_calls, "the account cache should have been consulted"
    assert not app.password_calls, "a cache hit must not re-send the password"
    be.get.assert_awaited_once()
    be.capture_login_credential.assert_awaited_once()
    grant = be.capture_login_credential.await_args.args[1]
    assert grant.access_token == "AT.cached"
    assert grant.provider_user_id == "graph-oid-123"
    be.home_redirect.assert_called_once()
    assert be.home_redirect.call_args.kwargs["token"] == "SESSION.TOKEN"


@pytest.mark.asyncio
async def test_no_cached_account_falls_back_to_username_password():
    """The cache-miss path keeps working after the body moved out of it."""
    app = FakeMsalApp(accounts=[], password_result=_msal_result("AT.fresh"))
    be = _backend(app)

    response = await be.authenticate(make_mocked_request("GET", "/login"))

    assert response is HOME_REDIRECT
    assert not app.silent_calls, "no account means nothing to look up silently"
    assert app.password_calls == [
        ("user@example.com", "secret", ["User.ReadBasic.All"])
    ]
    grant = be.capture_login_credential.await_args.args[1]
    assert grant.access_token == "AT.fresh"


@pytest.mark.asyncio
async def test_silent_miss_with_known_account_falls_back_to_password():
    """acquire_token_silent returning None must not short-circuit the login."""
    app = FakeMsalApp(
        accounts=[{"username": "user@example.com", "home_account_id": "hai-1"}],
        silent_result=None,
        password_result=_msal_result("AT.fresh"),
    )
    be = _backend(app)

    response = await be.authenticate(make_mocked_request("GET", "/login"))

    assert response is HOME_REDIRECT
    assert app.silent_calls and app.password_calls
