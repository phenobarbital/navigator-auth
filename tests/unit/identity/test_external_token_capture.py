"""FEAT-103 — provider-credential capture, vaulting, refresh and the
expires_in/expires_at contract.

Provider-agnostic half of the suite; the Azure-specific tests live in
tests/test_azure_token_verifier.py (TASK-112).

Every test here is mock-based, matching the rest of tests/unit/identity/ —
no live Postgres, no live Redis, no real IdentityCipher.
"""
import inspect
import json
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request
from navigator_session import AUTH_SESSION_OBJECT

from navigator_auth.backends.external import ExternalAuth
from navigator_auth.identity.types import TokenResponse
from navigator_auth.libs.expiry import expiry_fields
from navigator_auth.conf import AZURE_FLOW_TTL, AZURE_SESSION_TIMEOUT
from .conftest import make_backend

# aiohttp's HTTP error helpers used by auth_error()/JSONResponse can emit
# DeprecationWarning, which this project's pytest config turns into errors.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


class _Backend(ExternalAuth):
    """Minimal concrete ExternalAuth — the class is abstract."""

    async def authenticate(self, request):
        raise NotImplementedError

    async def auth_callback(self, request):
        raise NotImplementedError

    async def logout(self, request):
        raise NotImplementedError

    async def finish_logout(self, request):
        raise NotImplementedError

    async def check_credentials(self, request):
        raise NotImplementedError


def _make(**attrs):
    """An ExternalAuth instance wired for these tests."""
    defaults = {
        "_service_name": "testprovider",
        "userid_attribute": "id",
        "username_attribute": "email",
        "user_attribute": "email",
        "user_mapping": {},
    }
    defaults.update(attrs)
    return make_backend(_Backend, **defaults)


class FakeSession(dict):
    """Session double: a dict with the .get/[] access external.py uses."""


@pytest.fixture
def session():
    return FakeSession({
        "user_id": 35,
        "auth_method": "testprovider",
        "auth_token": "AT.old",
        "token_type": "Bearer",
        "external_provider_user_id": "acct-A",
    })


@pytest.fixture
def request_with_db():
    request = make_mocked_request("GET", "/auth/testprovider/callback/")
    request.app["authdb"] = MagicMock()
    return request


@pytest.fixture
def full_grant():
    """The captured login grant, shaped like msal 1.38.0's result."""
    return TokenResponse(
        access_token="AT.graph",
        token_type="Bearer",
        refresh_token="RT.secret",
        id_token="ID.jwt",
        expires_in=419,  # the measured lifetime
        scopes=["User.Read", "Mail.Read"],
        provider_user_id="acct-A",
    )


def _store_double(**overrides):
    store = MagicMock()
    store.save_linked_identity = AsyncMock()
    store.update_tokens = AsyncMock()
    store.get_for_provider_account = AsyncMock(return_value=MagicMock())
    store.get_by_provider = AsyncMock()
    store.decrypt_credential = MagicMock()
    for key, value in overrides.items():
        setattr(store, key, value)
    return store


@contextmanager
def _patched(session_obj, store):
    """Patch the lazily-imported get_session and IdentityStore at source."""
    with patch(
        "navigator_session.get_session", AsyncMock(return_value=session_obj)
    ), patch(
        "navigator_auth.identity.store.IdentityStore",
        MagicMock(return_value=store),
    ):
        yield


# ---------------------------------------------------------------------------
# Module 1 — build_user_info
# ---------------------------------------------------------------------------
_NEW_KEYS = {
    "id_token", "external_expires_at", "has_refresh_token",
    "external_provider_user_id",
}


class TestBuildUserInfoCapture:
    def test_build_user_info_without_new_kwargs_is_unchanged(self):
        """The old 3-argument call produces userdata without any new key."""
        backend = _make()
        userdata, uid = backend.build_user_info(
            userdata={"id": "u1", "email": "a@b.c"}, token="AT", mapping={"id": "id", "email": "email"}
        )
        assert uid == "u1"
        assert not (_NEW_KEYS & set(userdata))
        assert set(userdata) == {
            "id", "email", "session_key", "auth_method", "auth_token",
            "token_type",
        }

    def test_build_user_info_sets_id_token_and_expiry(self):
        backend = _make()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=419)
        userdata, _ = backend.build_user_info(
            userdata={"id": "u1", "email": "a@b.c"},
            token="AT",
            mapping={"id": "id", "email": "email"},
            id_token="ID.jwt",
            expires_at=expires_at,
            provider_user_id="acct-A",
        )
        assert userdata["id_token"] == "ID.jwt"
        assert isinstance(userdata["external_expires_at"], str)
        assert datetime.fromisoformat(userdata["external_expires_at"]) == expires_at
        assert userdata["external_provider_user_id"] == "acct-A"

    def test_build_user_info_never_writes_refresh_token(self):
        backend = _make()
        userdata, _ = backend.build_user_info(
            userdata={"id": "u1", "email": "a@b.c"},
            token="AT",
            mapping={"id": "id", "email": "email"},
            refresh_token="secret",
        )
        assert userdata["has_refresh_token"] is True
        assert "refresh_token" not in userdata
        assert all("secret" not in str(v) for v in userdata.values())

    @pytest.mark.asyncio
    async def test_navigator_refresh_token_key_not_clobbered(self):
        """After validate_user_info, ["refresh_token"] is NAVIGATOR's own token
        (auth.py indexes it in Redis as auth:refresh_token:<tok>)."""
        backend = _make(_callbacks=None)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=419)
        userdata, uid = backend.build_user_info(
            userdata={"id": "u1", "email": "a@b.c"},
            token="AT.graph",
            mapping={"id": "id", "email": "email"},
            id_token="ID.jwt",
            refresh_token="RT.provider-secret",
            expires_at=expires_at,
            provider_user_id="acct-A",
        )
        exp = time.time() + 3600
        backend._idp = MagicMock()
        backend._idp.get_user = AsyncMock(return_value=MagicMock())
        backend._idp.create_token = MagicMock(
            return_value=("JWT", "NAV_RT", exp, "Bearer")
        )
        backend.get_userdata = MagicMock(
            return_value={AUTH_SESSION_OBJECT: {"user_id": 35}}
        )
        backend.create_user = AsyncMock(return_value=MagicMock())
        backend.remember = AsyncMock(return_value=SimpleNamespace(session_id="sid"))
        request = make_mocked_request("GET", "/x")
        result = await backend.validate_user_info(request, uid, userdata, "AT.graph")
        assert result["refresh_token"] == "NAV_RT"
        assert "RT.provider-secret" not in json.dumps(result, default=str)
        # the expiry contract rides on the same dict (Module 5)
        assert isinstance(result["expires_in"], int)
        assert result["expires_at"] == int(exp)


# ---------------------------------------------------------------------------
# Module 2 — vaulting
# ---------------------------------------------------------------------------
class TestVaulting:
    @pytest.mark.asyncio
    async def test_vault_upstream_token_uses_passed_tokenresponse(
        self, request_with_db, session, full_grant
    ):
        backend = _make()
        store = _store_double()
        with _patched(session, store):
            await backend._vault_upstream_token(request_with_db, token=full_grant)
        store.save_linked_identity.assert_awaited_once()
        args = store.save_linked_identity.await_args.args
        assert args[0] == 35 and args[1] == "testprovider"
        assert args[2] is full_grant  # identity, not a session-rebuilt partial
        assert args[2].refresh_token == "RT.secret"
        assert args[2].id_token == "ID.jwt"

    @pytest.mark.asyncio
    async def test_vault_upstream_token_failure_does_not_raise(
        self, request_with_db, session, full_grant
    ):
        backend = _make()
        store = _store_double(
            save_linked_identity=AsyncMock(side_effect=RuntimeError("db down"))
        )
        with _patched(session, store):
            result = await backend._vault_upstream_token(
                request_with_db, token=full_grant
            )
        assert result is None
        backend.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_vault_upstream_token_legacy_fallback_rebuilds_from_session(
        self, request_with_db, session
    ):
        """No token argument: the previous session-reconstruction behaviour."""
        backend = _make()
        session["id"] = "acct-A"
        store = _store_double()
        with _patched(session, store):
            await backend._vault_upstream_token(request_with_db)
        saved = store.save_linked_identity.await_args.args[2]
        assert saved.access_token == "AT.old"
        assert saved.provider_user_id == "acct-A"
        assert saved.refresh_token is None

    @pytest.mark.asyncio
    async def test_capture_binds_verified_provider_account(
        self, request_with_db, session, full_grant
    ):
        backend = _make()
        store = _store_double()
        with _patched(session, store):
            await backend.capture_login_credential(request_with_db, full_grant)
        store.save_linked_identity.assert_awaited_once()
        assert store.save_linked_identity.await_args.args[2].provider_user_id == "acct-A"

        # a missing / empty account id creates NO row at all
        for missing in (None, ""):
            store = _store_double()
            backend = _make()
            unbound = TokenResponse(
                access_token="AT.graph", refresh_token="RT.secret",
                provider_user_id=missing,
            )
            with _patched(session, store):
                await backend.capture_login_credential(request_with_db, unbound)
            store.save_linked_identity.assert_not_awaited()
            backend.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_oauth2_resume_preserves_captured_grant(
        self, request_with_db, session, full_grant
    ):
        backend = _make()
        backend.get_domain = MagicMock(return_value="https://app")
        store = _store_double()
        response = MagicMock(status=302)
        response.headers = {}
        with _patched(session, store):
            await backend.capture_login_credential(request_with_db, full_grant)
            await backend._resume_oauth2_authorize(
                request_with_db, "flow-1", response
            )
        # EXACTLY ONE save, and it is the full grant — no partial second save
        store.save_linked_identity.assert_awaited_once()
        assert store.save_linked_identity.await_args.args[2] is full_grant
        assert "flow=flow-1" in response.headers["Location"]

    @pytest.mark.asyncio
    async def test_oauth2_resume_without_capture_keeps_legacy_save(
        self, session
    ):
        """Control: with no captured grant the AS resume still vaults."""
        backend = _make()
        backend.get_domain = MagicMock(return_value="https://app")
        request = make_mocked_request("GET", "/x")
        request.app["authdb"] = MagicMock()
        session["id"] = "acct-A"
        store = _store_double()
        response = MagicMock(status=302)
        response.headers = {}
        with _patched(session, store):
            await backend._resume_oauth2_authorize(request, "flow-2", response)
        store.save_linked_identity.assert_awaited_once()


# ---------------------------------------------------------------------------
# Module 4 — get_live_provider_token
# ---------------------------------------------------------------------------
def _stored(expires_in=None, expires_at=None, refresh_token="RT.secret"):
    return TokenResponse(
        access_token="AT.stored",
        refresh_token=refresh_token,
        expires_in=expires_in,
        expires_at=expires_at,
        scopes=["User.Read", "Mail.Read"],
        provider_user_id="acct-A",
    )


class TestGetLiveProviderToken:
    @pytest.mark.asyncio
    async def test_get_live_provider_token_returns_cached_when_fresh(
        self, request_with_db, session
    ):
        backend = _make()
        backend.refresh_provider_tokens = AsyncMock()
        stored = _stored(expires_in=3600)
        store = _store_double(decrypt_credential=MagicMock(return_value=stored))
        with _patched(session, store):
            token = await backend.get_live_provider_token(
                request_with_db, 35, leeway=120
            )
        assert token is stored
        backend.refresh_provider_tokens.assert_not_awaited()
        store.update_tokens.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_get_live_provider_token_refreshes_when_expiring(
        self, request_with_db, session
    ):
        backend = _make()
        stored = _stored(expires_in=30)
        rotated = TokenResponse(
            access_token="AT.new", refresh_token="RT.rotated", expires_in=3600
        )
        backend.refresh_provider_tokens = AsyncMock(return_value=rotated)
        seen = {}

        async def _update(identity, token):
            # the vault is the system of record: persist BEFORE publishing
            seen["session_token_at_persist"] = session["auth_token"]

        store = _store_double(
            decrypt_credential=MagicMock(return_value=stored),
            update_tokens=AsyncMock(side_effect=_update),
        )
        with _patched(session, store):
            token = await backend.get_live_provider_token(
                request_with_db, 35, leeway=120
            )
        assert token is rotated
        backend.refresh_provider_tokens.assert_awaited_once_with(stored)
        store.update_tokens.assert_awaited_once()
        assert store.update_tokens.await_args.args[1] is rotated
        assert seen["session_token_at_persist"] == "AT.old"
        assert session["auth_token"] == "AT.new"
        assert session["external_expires_at"] == rotated.expires_at.isoformat()
        assert session["has_refresh_token"] is True

    @pytest.mark.asyncio
    async def test_get_live_provider_token_without_refresh_token_returns_none(
        self, request_with_db, session
    ):
        backend = _make()
        # (a) EXPIRED, no refresh token -> None, no exception
        expired = _stored(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            refresh_token=None,
        )
        store = _store_double(decrypt_credential=MagicMock(return_value=expired))
        with _patched(session, store):
            assert await backend.get_live_provider_token(
                request_with_db, 35, leeway=120
            ) is None
        assert session["auth_token"] == "AT.old"
        # (b) FRESH, no refresh token -> still returned
        fresh = _stored(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            refresh_token=None,
        )
        store = _store_double(decrypt_credential=MagicMock(return_value=fresh))
        with _patched(session, store):
            assert await backend.get_live_provider_token(
                request_with_db, 35, leeway=120
            ) is fresh
        # (c) expiring-but-still-valid, no refresh token -> returned
        soon = _stored(
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
            refresh_token=None,
        )
        store = _store_double(decrypt_credential=MagicMock(return_value=soon))
        with _patched(session, store):
            assert await backend.get_live_provider_token(
                request_with_db, 35, leeway=120
            ) is soon

    @pytest.mark.asyncio
    async def test_refresh_uses_login_account_not_newest_link(
        self, request_with_db, session
    ):
        """Logged in as A, B linked more recently: only A is read."""
        backend = _make()
        stored_a = _stored(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        rotated = TokenResponse(access_token="AT.A.new", refresh_token="RT.A2",
                                expires_in=3600)
        backend.refresh_provider_tokens = AsyncMock(return_value=rotated)
        identity_a = MagicMock(name="identity_A")
        store = _store_double(
            get_for_provider_account=AsyncMock(return_value=identity_a),
            get_by_provider=AsyncMock(return_value=MagicMock(name="identity_B")),
            decrypt_credential=MagicMock(return_value=stored_a),
        )
        with _patched(session, store):
            await backend.get_live_provider_token(request_with_db, 35)
        store.get_by_provider.assert_not_awaited()
        store.get_for_provider_account.assert_awaited_once_with(
            35, "testprovider", "acct-A"
        )
        store.decrypt_credential.assert_called_once_with(identity_a)
        assert store.update_tokens.await_args.args[0] is identity_a
        assert session["auth_token"] == "AT.A.new"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "case",
        ["no_binding", "no_account_row", "wrong_user", "wrong_auth_method"],
    )
    async def test_refresh_rejects_missing_or_mismatched_binding(
        self, request_with_db, session, case
    ):
        backend = _make()
        backend.refresh_provider_tokens = AsyncMock()
        store = _store_double(
            decrypt_credential=MagicMock(
                return_value=_stored(
                    expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
                )
            )
        )
        user_id = 35
        if case == "no_binding":
            del session["external_provider_user_id"]
        elif case == "no_account_row":
            store.get_for_provider_account = AsyncMock(return_value=None)
        elif case == "wrong_user":
            user_id = 99
        elif case == "wrong_auth_method":
            session["auth_method"] = "someone-else"
        before = dict(session)
        with _patched(session, store):
            result = await backend.get_live_provider_token(request_with_db, user_id)
        assert result is None
        backend.refresh_provider_tokens.assert_not_awaited()
        store.update_tokens.assert_not_awaited()
        assert dict(session) == before
        if case in ("no_binding", "wrong_user", "wrong_auth_method"):
            # the store is never even consulted for a mismatched caller
            store.get_for_provider_account.assert_not_awaited()


# ---------------------------------------------------------------------------
# Module 5 — expires_in / expires_at
# ---------------------------------------------------------------------------
class TestExpiryContract:
    def test_expires_in_is_seconds_remaining(self):
        from navigator_session import SESSION_TIMEOUT

        fields = expiry_fields(time.time() + 3600)
        assert isinstance(fields["expires_in"], int)
        assert 0 < fields["expires_in"] <= SESSION_TIMEOUT
        # already expired never publishes a negative duration
        assert expiry_fields(time.time() - 10)["expires_in"] == 0

    @pytest.mark.asyncio
    async def test_noauth_publisher_returns_seconds_not_epoch(self):
        """The wiring, not only the helper: a real publisher's output."""
        from navigator_auth.backends.noauth import NoAuth

        backend = make_backend(
            NoAuth, username_attribute="username", _service_name="noauth"
        )
        exp = time.time() + 3600
        backend._idp = MagicMock()
        backend._idp.create_token = MagicMock(return_value=("JWT", "RT", exp, "Bearer"))
        backend.create_user = AsyncMock(return_value=MagicMock())
        backend.remember = AsyncMock()
        result = await backend.authenticate(make_mocked_request("GET", "/x"))
        assert isinstance(result["expires_in"], int)
        assert 0 < result["expires_in"] <= 3600
        assert result["expires_at"] == int(exp)

    def test_expires_at_is_absolute_epoch(self):
        exp = time.time() + 1234
        fields = expiry_fields(exp)
        assert abs(fields["expires_at"] - (time.time() + fields["expires_in"])) <= 2
        assert fields["expires_at"] == int(exp)

    @pytest.mark.asyncio
    async def test_user_object_expires_in_is_seconds(self):
        """usr.expires_in int seconds + usr.expires_at epoch at the four sites.

        EXECUTED: noauth.py (NoAuth.authenticate).
        BY INSPECTION: basic.py, troc.py, token.py — they need a live IdP/user
        store to drive, so their source is asserted to derive both attributes
        from expiry_fields and to no longer assign the raw epoch.
        """
        from navigator_auth.backends import basic, noauth, token, troc

        backend = make_backend(
            noauth.NoAuth, username_attribute="username", _service_name="noauth"
        )
        exp = time.time() + 900
        backend._idp = MagicMock()
        backend._idp.create_token = MagicMock(return_value=("JWT", "RT", exp, "Bearer"))
        user = MagicMock()
        backend.create_user = AsyncMock(return_value=user)
        backend.remember = AsyncMock()
        await backend.authenticate(make_mocked_request("GET", "/x"))
        assert isinstance(user.expires_in, int) and 0 < user.expires_in <= 900
        assert user.expires_at == int(exp)

        for module in (basic, troc, token):
            src = inspect.getsource(module)
            assert "expiry_fields(exp)" in src, module.__name__
            assert 'expires_in"] = _expiry["expires_in"]' in src or (
                'usr.expires_in = _expiry["expires_in"]' in src
            ), module.__name__
            assert 'usr.expires_at = _expiry["expires_at"]' in src, module.__name__
            assert "expires_in = exp" not in src, module.__name__

    def test_expires_in_matches_oauth2_b1_convention(self):
        exp_abs = time.time() + 3600
        # the B1 computation, as in backends/oauth2/backend.py
        b1 = int(exp_abs - datetime.now(timezone.utc).timestamp())
        legacy = expiry_fields(exp_abs)["expires_in"]
        assert isinstance(b1, int) and isinstance(legacy, int)
        assert abs(b1 - legacy) <= 1
        src = inspect.getsource(
            __import__(
                "navigator_auth.backends.oauth2.backend", fromlist=["x"]
            )
        )
        assert "int(exp_abs - now_utc.timestamp())" in src


# ---------------------------------------------------------------------------
# Module 8 — AZURE_FLOW_TTL vs max_age
# ---------------------------------------------------------------------------
class TestAzureFlowTtlSplit:
    @pytest.mark.asyncio
    async def test_azure_flow_ttl_is_independent_of_max_age(self):
        from navigator_auth.backends import azure as azure_mod

        backend = make_backend(
            azure_mod.AzureAuth,
            _service_name="azure",
            _pool=MagicMock(),
        )
        app = MagicMock()
        app.initiate_auth_code_flow = MagicMock(
            return_value={"state": "st-1", "auth_uri": "https://login/x"}
        )
        backend.get_msal_app = MagicMock(return_value=app)
        backend.get_payload = AsyncMock(side_effect=Exception("no payload"))
        backend.get_finish_redirect_url = MagicMock()
        backend.queryparams = MagicMock(return_value={})
        backend.get_redirect_uri = MagicMock(return_value="https://app/cb")
        backend.redirect = MagicMock(return_value="REDIRECT")
        redis = MagicMock()
        redis.setex = AsyncMock()
        redis_cm = MagicMock()
        redis_cm.__aenter__ = AsyncMock(return_value=redis)
        redis_cm.__aexit__ = AsyncMock(return_value=False)
        with patch.object(azure_mod, "AZURE_FLOW_TTL", 777), patch.object(
            azure_mod, "AZURE_SESSION_TIMEOUT", 33
        ), patch.object(azure_mod.aioredis, "Redis", MagicMock(return_value=redis_cm)):
            result = await backend.authenticate(make_mocked_request("GET", "/x"))
        assert result == "REDIRECT"
        assert app.initiate_auth_code_flow.call_args.kwargs["max_age"] == 33
        assert redis.setex.await_args.args[1] == 777
        assert redis.setex.await_args.args[0] == "azure_auth_st-1"

    def test_azure_session_timeout_is_int(self):
        assert isinstance(AZURE_SESSION_TIMEOUT, int)
        assert isinstance(AZURE_FLOW_TTL, int)
        src = inspect.getsource(
            __import__("navigator_auth.backends.azure", fromlist=["x"])
        )
        assert "int(AZURE_SESSION_TIMEOUT)" not in src


# ---------------------------------------------------------------------------
# Module 6 — check_credentials redaction (executed for all three backends)
# ---------------------------------------------------------------------------
def _backend_for(name):
    from navigator_auth.backends.azure import AzureAuth
    from navigator_auth.backends.github import GithubAuth
    from navigator_auth.backends.google import GoogleAuth

    cls = {"azure": AzureAuth, "github": GithubAuth, "google": GoogleAuth}[name]
    return cls, cls.__module__


class TestCheckCredentialsRedaction:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["azure", "github", "google"])
    async def test_check_credentials_redacts_provider_tokens(self, name):
        cls, module = _backend_for(name)
        backend = make_backend(cls, _service_name=name)
        backend.get_auth = MagicMock(return_value=("AT.raw-provider", "Bearer"))
        backend.verify_external_token = AsyncMock(
            return_value=({"id": "u1"}, {"id": "u1"})
        )
        backend.user_mapping = {}
        backend.build_user_info = MagicMock(
            return_value=(
                {
                    "id": "u1",
                    "auth_token": "AT.raw-provider",
                    "id_token": "ID.raw-provider",
                    "has_refresh_token": True,
                },
                "u1",
            )
        )
        backend.validate_user_info = AsyncMock(
            return_value={"token": "NAV_JWT", "refresh_token": "NAV_RT"}
        )
        request = make_mocked_request("GET", "/auth/x/check_credentials")
        with patch(f"{module}.get_session", AsyncMock(return_value={})):
            response = await backend.check_credentials(request)
        assert response.status == 200
        body = json.loads(response.body)
        text = json.dumps(body)
        assert "AT.raw-provider" not in text
        assert "ID.raw-provider" not in text
        # keys retained, masked
        assert body["auth_token"].startswith("***")
        assert body["id_token"].startswith("***")
        # Navigator's own credentials are untouched
        assert body["token"] == "NAV_JWT"
        assert body["refresh_token"] == "NAV_RT"


# ---------------------------------------------------------------------------
# Module 7 — session-write invariant
# ---------------------------------------------------------------------------
class TestSessionWriteInvariant:
    @pytest.mark.asyncio
    async def test_api_login_session_is_written_by_remember_not_load_session(self):
        """remember() (-> new_session) runs BEFORE auth.py's load_session, and
        load_session's return value is not what supplies auth_token."""
        from navigator_auth.auth import AuthHandler

        calls = []
        backend = _make(_callbacks=None)
        userdata, uid = backend.build_user_info(
            userdata={"id": "u1", "email": "a@b.c"},
            token="AT.provider",
            mapping={"id": "id", "email": "email"},
            refresh_token="RT.secret",
        )
        backend._idp = MagicMock()
        backend._idp.get_user = AsyncMock(return_value=MagicMock())
        backend._idp.create_token = MagicMock(
            return_value=("JWT", "NAV_RT", time.time() + 60, "Bearer")
        )
        backend.get_userdata = MagicMock(
            return_value={AUTH_SESSION_OBJECT: {"user_id": 35}}
        )
        backend.create_user = AsyncMock(return_value=MagicMock())

        async def _remember(*args, **kwargs):
            calls.append("remember")
            return SimpleNamespace(session_id="sid")

        backend.remember = _remember

        async def _authenticate(request):
            return await backend.validate_user_info(request, uid, userdata, "AT.provider")

        backend.authenticate = _authenticate

        load_session = AsyncMock(
            side_effect=lambda *a, **k: calls.append("load_session") or MagicMock()
        )
        handler = object.__new__(AuthHandler)
        handler.logger = MagicMock()
        handler._session = SimpleNamespace(
            storage=SimpleNamespace(load_session=load_session)
        )
        handler.get_auth_backend = MagicMock(return_value=backend)
        request = make_mocked_request("POST", "/api/v1/login")
        with patch("navigator_auth.auth.get_session", AsyncMock(return_value=None)):
            response = await handler.api_login(request)
        assert calls == ["remember", "load_session"]
        # the userdata handed to load_session is the backend's own result, and
        # the provider access token is not sourced from load_session's return
        sent = load_session.await_args.args[1]
        assert sent["auth_token"] == "AT.provider"
        assert response.status == 200
