"""Unit tests for the Odoo OAuth2 backend (OCA oauth_provider)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.odoo import OdooAuth, ODOO_LOGIN_FLOW
from .conftest import make_backend


def _odoo(flow_store=None):
    backend = make_backend(OdooAuth, flow_store=flow_store)
    backend.authorize_uri = "https://erp.example.com/oauth2/auth"
    backend._token_uri = "https://erp.example.com/oauth2/token"
    backend.userinfo_uri = "https://erp.example.com/oauth2/userinfo"
    backend.user_mapping = {"email": "email"}
    backend.login_failed_uri = "/login-failed"
    return backend


class TestOdooConfigure:
    def test_endpoints_composed_from_conf(self):
        backend = make_backend(OdooAuth)
        with patch(
            "navigator_auth.backends.odoo.ODOO_DOMAIN",
            "https://erp.example.com/",
        ):
            parent = MagicMock()
            with patch(
                "navigator_auth.backends.oauth.ExternalAuth.configure", parent
            ):
                backend.configure(MagicMock())
        assert backend.authorize_uri == "https://erp.example.com/oauth2/auth"
        assert backend._token_uri == "https://erp.example.com/oauth2/token"
        assert (
            backend.userinfo_uri == "https://erp.example.com/oauth2/userinfo"
        )


class TestOdooLogin:
    @pytest.mark.asyncio
    async def test_get_credentials_state_stored(self, flow_store):
        backend = _odoo(flow_store)
        request = make_mocked_request("GET", "/api/v1/auth/odoo/")
        with patch("navigator_auth.backends.odoo.ODOO_CLIENT_ID", "ocid"):
            params = await backend.get_credentials(
                request, "https://app/auth/odoo/callback/"
            )
        assert params["client_id"] == "ocid"
        assert params["response_type"] == "code"
        state = params["state"]
        stored = flow_store.storage[ODOO_LOGIN_FLOW.format(state=state)]
        assert stored["redirect_uri"] == "https://app/auth/odoo/callback/"

    @pytest.mark.asyncio
    async def test_callback_unknown_state_rejected(self, flow_store):
        backend = _odoo(flow_store)
        request = make_mocked_request(
            "GET", "/auth/odoo/callback/?code=c&state=bogus"
        )
        response = await backend.auth_callback(request)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_callback_exchanges_code(self, flow_store):
        backend = _odoo(flow_store)
        await flow_store.set(
            ODOO_LOGIN_FLOW.format(state="st"),
            {"redirect_uri": "https://app/cb"},
            ttl=600,
        )
        backend.token_request = AsyncMock(
            return_value={"access_token": "oat", "token_type": "Bearer"}
        )
        backend.get = AsyncMock(
            return_value={"sub": "7", "email": "u@erp", "name": "U"}
        )
        backend.build_user_info = MagicMock(
            return_value=({"email": "u@erp"}, "7")
        )
        backend.validate_user_info = AsyncMock(return_value={"token": "jwt"})
        backend.home_redirect = MagicMock(return_value="REDIRECT")
        with patch(
            "navigator_auth.backends.odoo.ODOO_CLIENT_ID", "ocid"
        ), patch("navigator_auth.backends.odoo.ODOO_CLIENT_SECRET", "osec"):
            request = make_mocked_request(
                "GET", "/auth/odoo/callback/?code=c0de&state=st"
            )
            result = await backend.auth_callback(request)
        assert result == "REDIRECT"
        data = backend.token_request.await_args.kwargs["data"]
        assert data["grant_type"] == "authorization_code"
        assert data["client_id"] == "ocid"
        assert data["client_secret"] == "osec"
        assert data["redirect_uri"] == "https://app/cb"


class TestOdooIdentity:
    def test_identity_client_from_conf(self):
        backend = _odoo()
        with patch(
            "navigator_auth.backends.odoo.ODOO_CLIENT_ID", "ocid"
        ), patch("navigator_auth.backends.odoo.ODOO_CLIENT_SECRET", "osec"):
            assert backend.get_identity_client() == ("ocid", "osec")

    def test_identity_userid_prefers_sub(self):
        backend = _odoo()
        assert backend.get_identity_userid({"sub": "u7", "id": 3}) == "u7"
        assert backend.get_identity_userid({"user_id": 3}) == "3"
        assert backend.get_identity_userid({}) is None

    @pytest.mark.asyncio
    async def test_generic_link_flow_inherited(self, flow_store):
        backend = _odoo(flow_store)
        backend.get_redirect_uri = MagicMock(
            return_value="https://app/auth/odoo/callback/"
        )
        with patch(
            "navigator_auth.backends.odoo.ODOO_CLIENT_ID", "ocid"
        ), patch("navigator_auth.backends.odoo.ODOO_CLIENT_SECRET", "osec"):
            request = make_mocked_request(
                "GET", "/api/v1/user/identities/link/odoo"
            )
            response = await backend.authorize_identity(
                request, user_id=5, finish_redirect="/manage"
            )
        assert response.location.startswith(
            "https://erp.example.com/oauth2/auth"
        )
        key = next(iter(flow_store.storage))
        assert flow_store.storage[key]["provider"] == "odoo"
