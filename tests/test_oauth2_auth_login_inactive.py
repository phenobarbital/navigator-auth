"""FEAT-101 TASK-91 (Q-F1) — OAuth2 login-page password POST rejects disabled users."""
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web


@pytest.fixture
def provider():
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov._create_user_session = AsyncMock()
    prov.get_login_form = AsyncMock(return_value=("bob", "pw", {"client_id": "c"}))
    return prov


def _post_request():
    request = MagicMock()
    request.method = "POST"
    request.query = {}
    request.cookies = {}
    return request


@pytest.mark.asyncio
async def test_oauth2_auth_login_rejects_inactive(provider):
    provider._idp.authenticate_credentials = AsyncMock(
        return_value={"user_id": 1, "is_active": False}
    )
    with pytest.raises(web.HTTPForbidden):
        await provider.auth_login(_post_request())
    provider._create_user_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_oauth2_auth_login_active_passes_check(provider):
    """An active user gets past the check (the flow then proceeds to the redirect)."""
    provider._idp.authenticate_credentials = AsyncMock(
        return_value={"user_id": 1, "is_active": True}
    )
    request = _post_request()
    request.app.router.__getitem__.return_value.url_for.return_value = "/authorize"
    try:
        await provider.auth_login(request)
    except web.HTTPForbidden:
        pytest.fail("active user must not be rejected")
    except Exception:  # noqa: BLE001 - later flow needs a real app; only the gate is under test
        pass
