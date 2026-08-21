"""Unit tests for the fixed Google login flow."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.google import (
    GoogleAuth,
    GOOGLE_LOGIN_FLOW,
    GOOGLE_MAPPING,
)
from .conftest import make_backend


def _google(flow_store=None):
    backend = make_backend(GoogleAuth, flow_store=flow_store)
    backend._credentials = {
        "client_id": "cid",
        "client_secret": "csecret",
        "scopes": ["email"],
    }
    backend.user_mapping = GOOGLE_MAPPING
    backend.login_failed_uri = "/login-failed"
    backend.finish_redirect_url = None
    return backend


def _patch_aiogoogle(user_creds=None, userinfo=None):
    google = MagicMock()
    google.openid_connect.is_ready = MagicMock(return_value=True)
    google.openid_connect.authorization_url = MagicMock(
        return_value="https://accounts.google.com/o/oauth2/auth?..."
    )
    google.openid_connect.build_user_creds = AsyncMock(
        return_value=user_creds or {}
    )
    google.openid_connect.get_user_info = AsyncMock(
        return_value=userinfo or {}
    )
    return patch(
        "navigator_auth.backends.google.Aiogoogle", return_value=google
    ), google


class TestGoogleAuthenticate:
    @pytest.mark.asyncio
    async def test_no_instance_state_mutation(self, flow_store):
        backend = _google(flow_store)
        backend.get_finish_redirect_url = MagicMock()
        backend.get_redirect_uri = MagicMock(return_value="https://app/cb")
        patcher, _ = _patch_aiogoogle()
        request = make_mocked_request("GET", "/api/v1/auth/google/")
        with patcher:
            await backend.authenticate(request)
        # the singleton must not hold per-login state anymore
        assert not hasattr(backend, "_state")
        assert not hasattr(backend, "_nonce")
        assert not hasattr(backend, "google")
        # flow stored server-side
        assert len(flow_store.storage) == 1

    @pytest.mark.asyncio
    async def test_concurrent_logins_distinct_states(self, flow_store):
        backend = _google(flow_store)
        backend.get_finish_redirect_url = MagicMock()
        backend.get_redirect_uri = MagicMock(return_value="https://app/cb")
        patcher, google = _patch_aiogoogle()
        request = make_mocked_request("GET", "/api/v1/auth/google/")
        with patcher:
            await backend.authenticate(request)
            await backend.authenticate(request)
        states = [
            call.kwargs["state"]
            for call in google.openid_connect.authorization_url.call_args_list
        ]
        assert len(set(states)) == 2
        assert len(flow_store.storage) == 2

    @pytest.mark.asyncio
    async def test_offline_access_requested(self, flow_store):
        backend = _google(flow_store)
        backend.get_finish_redirect_url = MagicMock()
        backend.get_redirect_uri = MagicMock(return_value="https://app/cb")
        patcher, google = _patch_aiogoogle()
        request = make_mocked_request("GET", "/api/v1/auth/google/")
        with patcher:
            await backend.authenticate(request)
        kwargs = google.openid_connect.authorization_url.call_args.kwargs
        assert kwargs["access_type"] == "offline"


class TestGoogleCallback:
    @pytest.mark.asyncio
    async def test_unknown_state_rejected(self, flow_store):
        backend = _google(flow_store)
        request = make_mocked_request(
            "GET", "/auth/google/callback/?code=c&state=bogus"
        )
        response = await backend.auth_callback(request)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_verify_true_and_sub_mapping(self, flow_store):
        backend = _google(flow_store)
        await flow_store.set(
            GOOGLE_LOGIN_FLOW.format(state="st"),
            {"nonce": "the-nonce", "redirect_uri": "https://app/cb"},
            ttl=600,
        )
        patcher, google = _patch_aiogoogle(
            user_creds={"id_token_jwt": "idt"},
            userinfo={
                "sub": "10769150350006150715113082367",
                "email": "g@x.com",
                "given_name": "G",
                "family_name": "X",
                "name": "G X",
            },
        )
        backend.session_key_property = "session_key"
        backend.validate_user_info = AsyncMock(return_value={"token": "jwt"})
        backend.home_redirect = MagicMock(return_value="REDIRECT")
        request = make_mocked_request(
            "GET", "/auth/google/callback/?code=c&state=st"
        )
        with patcher:
            result = await backend.auth_callback(request)
        assert result == "REDIRECT"
        kwargs = google.openid_connect.build_user_creds.await_args.kwargs
        assert kwargs["verify"] is True
        assert kwargs["nonce"] == "the-nonce"
        # sub claim became the user id, auth metadata got stamped
        _, uid, userdata, token = backend.validate_user_info.await_args.args
        assert uid == "10769150350006150715113082367"
        assert userdata["auth_method"] == "google"
        assert userdata["auth_token"] == "idt"

    @pytest.mark.asyncio
    async def test_error_param_rejected(self, flow_store):
        backend = _google(flow_store)
        request = make_mocked_request(
            "GET", "/auth/google/callback/?error=access_denied"
        )
        response = await backend.auth_callback(request)
        assert response.status == 403
