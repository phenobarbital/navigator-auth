"""Unit tests for the Identity Vault HTTP handlers."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.identity.types import TokenResponse


class FakeSession(dict):
    """Session double supporting decode()/get()/mapping access."""

    def decode(self, key):
        return self.get(key)


def _request(method, path, app_map=None, match_info=None, user=None):
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if app_map:
        app.update(app_map)
    request = make_mocked_request(method, path, app=app)
    if match_info:
        request.match_info.update(match_info)
    return request


def _session_with_user(user_id=42):
    session = FakeSession()
    session["user"] = {"user_id": user_id, "username": "jesse"}
    return session


def _patch_session(session):
    """Patch get_session for both the decorator and the handlers module."""
    return (
        patch(
            "navigator_auth.decorators.get_session",
            new=AsyncMock(return_value=session),
        ),
        patch(
            "navigator_auth.handlers.user_identities.get_session",
            new=AsyncMock(return_value=session),
        ),
    )


def _patch_store(store):
    return (
        patch(
            "navigator_auth.handlers.user_identities.IdentityStore",
            return_value=store,
        ),
        patch(
            "navigator_auth.handlers.user_identities.IdentityCipher",
            return_value=MagicMock(),
        ),
    )


def _identity(provider="github", refresh=True):
    identity = MagicMock()
    identity.identity_id = "11111111-1111-1111-1111-111111111111"
    identity.auth_provider = provider
    identity.refresh_token = b"ct" if refresh else None
    return identity


class TestListIdentities:
    @pytest.mark.asyncio
    async def test_list_returns_masked(self):
        from navigator_auth.handlers.user_identities import (
            UserIdentitiesHandler,
        )

        session = _session_with_user()
        store = MagicMock()
        store.list_for_user = AsyncMock(
            return_value=[{"auth_provider": "github", "has_refresh_token": True}]
        )
        p1, p2 = _patch_session(session)
        p3, p4 = _patch_store(store)
        request = _request("GET", "/api/v1/user/identities")
        with p1, p2, p3, p4:
            view = UserIdentitiesHandler(request)
            response = await view.get()
        assert response.status == 200
        assert b"github" in response.body
        assert b"access_token" not in response.body
        store.list_for_user.assert_awaited_once_with(42)

    @pytest.mark.asyncio
    async def test_no_user_in_session_is_401(self):
        from navigator_auth.handlers.user_identities import (
            UserIdentitiesHandler,
        )

        session = FakeSession()
        p1, p2 = _patch_session(session)
        request = _request("GET", "/api/v1/user/identities")
        with p1, p2, pytest.raises(web.HTTPException) as exc:
            view = UserIdentitiesHandler(request)
            await view.get()
        assert exc.value.status == 401


class TestRenewIdentity:
    @pytest.mark.asyncio
    async def test_put_refreshes_and_caches(self):
        from navigator_auth.handlers.user_identities import (
            UserIdentitiesHandler,
        )

        session = _session_with_user()
        identity = _identity()
        new_token = TokenResponse(
            access_token="new_at", refresh_token="new_rt", expires_in=3600
        )
        store = MagicMock()
        store.get_one = AsyncMock(return_value=identity)
        store.decrypt_credential = MagicMock(
            return_value=TokenResponse(access_token="at", refresh_token="rt")
        )
        store.update_tokens = AsyncMock(return_value=identity)
        store.masked = MagicMock(return_value={"auth_provider": "github"})
        backend = MagicMock()
        backend.refresh_identity_tokens = AsyncMock(return_value=new_token)

        p1, p2 = _patch_session(session)
        p3, p4 = _patch_store(store)
        cache = AsyncMock()
        request = _request(
            "PUT",
            "/api/v1/user/identities/11111111-1111-1111-1111-111111111111",
            match_info={
                "identity_id": "11111111-1111-1111-1111-111111111111"
            },
        )
        request.app["auth"].get_external_backend = MagicMock(
            return_value=backend
        )
        with p1, p2, p3, p4, patch(
            "navigator_auth.handlers.user_identities.cache_credential", cache
        ):
            view = UserIdentitiesHandler(request)
            response = await view.put()
        assert response.status == 200
        backend.refresh_identity_tokens.assert_awaited_once_with("rt")
        store.update_tokens.assert_awaited_once()
        cache.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_put_without_refresh_token_is_409(self):
        from navigator_auth.handlers.user_identities import (
            UserIdentitiesHandler,
        )

        session = _session_with_user()
        identity = _identity(refresh=False)
        store = MagicMock()
        store.get_one = AsyncMock(return_value=identity)
        store.decrypt_credential = MagicMock(
            return_value=TokenResponse(access_token="at")
        )
        p1, p2 = _patch_session(session)
        p3, p4 = _patch_store(store)
        request = _request(
            "PUT",
            "/api/v1/user/identities/11111111-1111-1111-1111-111111111111",
            match_info={
                "identity_id": "11111111-1111-1111-1111-111111111111"
            },
        )
        with p1, p2, p3, p4, pytest.raises(web.HTTPException) as exc:
            view = UserIdentitiesHandler(request)
            await view.put()
        assert exc.value.status == 409


class TestDeleteIdentity:
    @pytest.mark.asyncio
    async def test_delete_invalidates_cache(self):
        from navigator_auth.handlers.user_identities import (
            UserIdentitiesHandler,
        )

        session = _session_with_user()
        identity = _identity(provider="okta")
        store = MagicMock()
        store.get_one = AsyncMock(return_value=identity)
        store.delete = AsyncMock(return_value=True)
        p1, p2 = _patch_session(session)
        p3, p4 = _patch_store(store)
        invalidate = AsyncMock()
        request = _request(
            "DELETE",
            "/api/v1/user/identities/11111111-1111-1111-1111-111111111111",
            match_info={
                "identity_id": "11111111-1111-1111-1111-111111111111"
            },
        )
        with p1, p2, p3, p4, patch(
            "navigator_auth.handlers.user_identities.invalidate_cached",
            invalidate,
        ):
            view = UserIdentitiesHandler(request)
            response = await view.delete()
        assert response.status == 200
        store.delete.assert_awaited_once()
        invalidate.assert_awaited_once()
        assert invalidate.await_args.args[1] == "okta"


class TestCredentialEndpoint:
    @pytest.mark.asyncio
    async def test_vault_cache_hit_short_circuits_db(self):
        from navigator_auth.handlers.user_identities import (
            IdentityCredentialHandler,
        )

        session = _session_with_user()
        fresh = TokenResponse(
            access_token="cached_at", expires_in=3600
        ).credential()
        p1, p2 = _patch_session(session)
        store = MagicMock()
        store.get_by_provider = AsyncMock()
        p3, p4 = _patch_store(store)
        request = _request(
            "GET",
            "/api/v1/user/identities/github/credential",
            match_info={"provider": "github"},
        )
        with p1, p2, p3, p4, patch(
            "navigator_auth.handlers.user_identities.cached_credential",
            new=AsyncMock(return_value=fresh),
        ):
            view = IdentityCredentialHandler(request)
            response = await view.get()
        assert response.status == 200
        assert b"cached_at" in response.body
        store.get_by_provider.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_expiring_credential_triggers_refresh(self):
        from navigator_auth.handlers.user_identities import (
            IdentityCredentialHandler,
        )

        session = _session_with_user()
        identity = _identity()
        expiring = TokenResponse(
            access_token="old_at",
            refresh_token="rt",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=10),
        )
        refreshed = TokenResponse(
            access_token="new_at", refresh_token="rt2", expires_in=3600
        )
        store = MagicMock()
        store.get_by_provider = AsyncMock(return_value=identity)
        store.decrypt_credential = MagicMock(return_value=expiring)
        store.update_tokens = AsyncMock(return_value=identity)
        backend = MagicMock()
        backend.refresh_identity_tokens = AsyncMock(return_value=refreshed)
        p1, p2 = _patch_session(session)
        p3, p4 = _patch_store(store)
        request = _request(
            "GET",
            "/api/v1/user/identities/github/credential",
            match_info={"provider": "github"},
        )
        request.app["auth"].get_external_backend = MagicMock(
            return_value=backend
        )
        with p1, p2, p3, p4, patch(
            "navigator_auth.handlers.user_identities.cached_credential",
            new=AsyncMock(return_value=None),
        ), patch(
            "navigator_auth.handlers.user_identities.cache_credential",
            new=AsyncMock(),
        ) as cache:
            view = IdentityCredentialHandler(request)
            response = await view.get()
        assert response.status == 200
        assert b"new_at" in response.body
        backend.refresh_identity_tokens.assert_awaited_once_with("rt")
        cache.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_identity_is_404(self):
        from navigator_auth.handlers.user_identities import (
            IdentityCredentialHandler,
        )

        session = _session_with_user()
        store = MagicMock()
        store.get_by_provider = AsyncMock(return_value=None)
        p1, p2 = _patch_session(session)
        p3, p4 = _patch_store(store)
        request = _request(
            "GET",
            "/api/v1/user/identities/github/credential",
            match_info={"provider": "github"},
        )
        with p1, p2, p3, p4, patch(
            "navigator_auth.handlers.user_identities.cached_credential",
            new=AsyncMock(return_value=None),
        ), pytest.raises(web.HTTPException) as exc:
            view = IdentityCredentialHandler(request)
            await view.get()
        assert exc.value.status == 404


class TestLinkHandler:
    @pytest.mark.asyncio
    async def test_unknown_provider_is_404(self):
        from navigator_auth.handlers.user_identities import (
            IdentityLinkHandler,
        )

        session = _session_with_user()
        p1, p2 = _patch_session(session)
        request = _request(
            "GET",
            "/api/v1/user/identities/link/doesnotexist",
            match_info={"provider": "doesnotexist"},
        )
        request.app["auth"].get_external_backend = MagicMock(return_value=None)
        with p1, p2, pytest.raises(web.HTTPException) as exc:
            view = IdentityLinkHandler(request)
            await view.get()
        assert exc.value.status == 404

    @pytest.mark.asyncio
    async def test_link_starts_authorize_flow(self):
        from navigator_auth.handlers.user_identities import (
            IdentityLinkHandler,
        )

        session = _session_with_user(user_id=7)
        backend = MagicMock()
        backend.authorize_identity = AsyncMock(
            return_value=web.HTTPFound("https://provider/authorize")
        )
        p1, p2 = _patch_session(session)
        request = _request(
            "GET",
            "/api/v1/user/identities/link/github?redirect_uri=/done",
            match_info={"provider": "github"},
        )
        request.app["auth"].get_external_backend = MagicMock(
            return_value=backend
        )
        with p1, p2, patch(
            "navigator_auth.handlers.user_identities.IdentityCipher",
            return_value=MagicMock(),
        ):
            view = IdentityLinkHandler(request)
            response = await view.get()
        assert response.status == 302
        args = backend.authorize_identity.await_args.args
        assert args[1] == 7
        assert args[2] == "/done"
