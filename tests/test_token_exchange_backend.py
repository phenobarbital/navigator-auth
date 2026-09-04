"""
Live integration tests for TokenExchangeAuth (FEAT-096 TASK-052).

Mirrors the `live_app` pattern used in tests/test_basic_auth.py: starts a
real aiohttp server with AuthHandler (Basic + Azure + TokenExchangeAuth),
inserts a test user into PostgreSQL auth.users, and exercises
POST /api/v1/login with X-Auth-Method: TokenExchangeAuth. Only the
provider backend's `verify_external_token` is mocked (per test) — no real
network calls to Azure/Google/GitHub. Session storage (Redis) and the
identity vault (Postgres) are real.

Requirements:
  - PostgreSQL running with the `navigator` database and `auth` schema.
  - Redis running for session storage.
"""
import warnings
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import jwt
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    # Pre-existing environment limitation: the dev/test SECRET_KEY is shorter
    # than PyJWT's recommended HMAC key length. Not in scope for FEAT-096.
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]

TEST_EMAIL = "test_exchange@example.com"
# AUTH_USERNAME_ATTRIBUTE defaults to "username" in this environment, and
# `IdentityProvider.get_user(login)` searches by that column — the spec's
# `idp.get_user(email)` fallback assumes (as is typical for navigator_auth
# deployments) that `username` is populated with the e-mail address.
TEST_USERNAME = TEST_EMAIL
TEST_FIRST_NAME = "Exchange"
TEST_LAST_NAME = "User"


def _userinfo(email=TEST_EMAIL, **overrides) -> dict:
    data = {
        "id": "graph-oid-exchange-1",
        "displayName": "Exchange User",
        "mail": email,
    }
    data.update(overrides)
    return data


def _token(
    provider_user_id="graph-oid-exchange-1",
    access_token="raw-access-token",
    refresh_token=None,
    id_token=None,
    expires_at=None,
):
    from navigator_auth.identity.types import TokenResponse

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        expires_at=expires_at,
        provider_user_id=provider_user_id,
        scopes=["User.Read"],
    )


@pytest_asyncio.fixture(scope="module")
async def exchange_app():
    from navigator_auth import AuthHandler
    from navigator_auth.conf import SECRET_KEY, AUTH_JWT_ALGORITHM

    # NOTE: `conf.AUTHENTICATION_BACKENDS = (...)` (the pattern used by
    # tests/test_basic_auth.py) is a no-op here: conftest.py already
    # imports navigator_auth (via abac.policies.adapter) at collection
    # time, so `auth.py`'s `from .conf import AUTHENTICATION_BACKENDS` is
    # already bound to the real default tuple before this fixture runs.
    # Use the explicit `backends=` constructor param instead (documented
    # for exactly this case in AuthHandler.__init__).
    app = web.Application()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(
            secure_cookies=False,
            backends=[
                "navigator_auth.backends.BasicAuth",
                "navigator_auth.backends.AzureAuth",
                "navigator_auth.backends.TokenExchangeAuth",
            ],
        )
        auth.setup(app)

    server = TestServer(app)
    client = TestClient(server)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.start_server()

    db_pool = app.get("authdb")
    assert db_pool is not None, "PostgreSQL pool ('authdb') was not created"

    await db_pool.execute(f"DELETE FROM auth.users WHERE username = '{TEST_USERNAME}'")
    await db_pool.execute(
        f"""
        INSERT INTO auth.users
            (username, password, email, first_name, last_name,
             is_active, is_superuser, is_new, is_staff)
        VALUES (
            '{TEST_USERNAME}', 'unused', '{TEST_EMAIL}',
            '{TEST_FIRST_NAME}', '{TEST_LAST_NAME}',
            true, false, false, true
        )
        """
    )
    from navigator_auth.models import User

    async with await db_pool.acquire() as conn:
        User.Meta.connection = conn
        user_row = await User.get(username=TEST_USERNAME)
    user_id = user_row.user_id

    exchange_backend = auth.backends["TokenExchangeAuth"]
    # Same hang-avoidance as TASK-046: the default AUTH_SUCCESSFUL_CALLBACKS
    # (e.g. resources.auth.saving_troc_user) assume a real callback context
    # this synthetic flow doesn't fully replicate; disabled here (must be
    # after on_startup, which populates `_callbacks`).
    exchange_backend._callbacks = None
    azure_backend = auth.backends["AzureAuth"]

    # Pre-existing environment defect (unrelated to FEAT-096, present since
    # the Identity Vault work): this dev database's physical
    # auth.user_identities table predates navigator_auth.models.UserIdentity
    # and uses a `uid VARCHAR` primary key instead of `identity_id UUID`
    # (see examples/sql/identity_vault_schema.sql for the intended shape).
    # UserIdentity.get()/.insert() fail against it — save_linked_identity's
    # best-effort/non-fatal handling (D3/D7) correctly swallows the error,
    # but it means the vault row is never actually persisted here. Detected
    # once so the vault-content assertions below can be skipped cleanly
    # instead of failing on an unrelated, pre-existing issue.
    async with await db_pool.acquire() as conn:
        cols, _err = await conn.query(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='auth' AND table_name='user_identities' "
            "AND column_name='identity_id'"
        )
    vault_schema_ok = bool(cols)

    yield (
        client, azure_backend, exchange_backend, db_pool, user_id,
        SECRET_KEY, AUTH_JWT_ALGORITHM, vault_schema_ok,
    )

    try:
        await db_pool.execute(
            f"DELETE FROM auth.user_identities WHERE user_id = {user_id}"
        )
    except Exception:
        pass
    try:
        await db_pool.execute(f"DELETE FROM auth.users WHERE username = '{TEST_USERNAME}'")
    except Exception:
        pass

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()


def _decode(token: str, secret, algorithm: str) -> dict:
    return jwt.decode(token, secret, algorithms=[algorithm])


async def _clear_identities(db_pool, user_id):
    await db_pool.execute(
        f"DELETE FROM auth.user_identities WHERE user_id = {user_id}"
    )


# ---------------------------------------------------------------------------
# Payload / provider validation (400s)
# ---------------------------------------------------------------------------
async def test_payload_validation_400(exchange_app):
    client = exchange_app[0]
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure"},  # missing token
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 400, await resp.text()


async def test_unsupported_provider_400(exchange_app):
    """`google` is a recognised TOKEN_EXCHANGE_PROVIDERS entry but is not
    a loaded backend in this app (only Basic/Azure/TokenExchangeAuth)."""
    client = exchange_app[0]
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "google", "token": "sometoken"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 400, await resp.text()


async def test_unknown_provider_400(exchange_app):
    client = exchange_app[0]
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "not-a-provider", "token": "sometoken"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 400, await resp.text()


# ---------------------------------------------------------------------------
# Verifier failure -> 401
# ---------------------------------------------------------------------------
async def test_verifier_invalid_auth_401(exchange_app):
    from navigator_auth.exceptions import InvalidAuth

    client, azure_backend = exchange_app[0], exchange_app[1]
    azure_backend.verify_external_token = AsyncMock(
        side_effect=InvalidAuth("wrong_audience")
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "foreign-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 401, await resp.text()


# ---------------------------------------------------------------------------
# Success path: session claims, both levels + JWT
# ---------------------------------------------------------------------------
async def test_session_claims_both_levels_and_jwt(exchange_app):
    client, azure_backend, _exchange_backend, db_pool, user_id, secret, algorithm, _vault_ok = exchange_app
    await _clear_identities(db_pool, user_id)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token())
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    assert data.get("auth_method") == "basic"
    assert data.get("auth_origin") == "azure"
    claims = _decode(data["token"], secret, algorithm)
    assert claims.get("auth_origin") == "azure"


# ---------------------------------------------------------------------------
# Linked identity precedence over e-mail match
# ---------------------------------------------------------------------------
async def test_linked_identity_precedence(exchange_app):
    from navigator_auth.identity.store import IdentityStore

    client, azure_backend, _exchange_backend, db_pool, user_id, _secret, _alg, vault_schema_ok = exchange_app
    if not vault_schema_ok:
        pytest.skip(
            "Pre-existing environment defect: this DB's auth.user_identities "
            "lacks the identity_id column UserIdentity.get()/.insert() need "
            "(unrelated to FEAT-096) -- can't pre-link an identity here; the "
            "precedence logic itself is unit-tested via find_user_by_provider_account "
            "in tests/test_identity_id_token.py."
        )
    await _clear_identities(db_pool, user_id)
    store = IdentityStore(db_pool)
    # Pre-link a stable provider_user_id to this user (simulating an
    # earlier successful exchange), with a userinfo e-mail that does NOT
    # match any auth.users row -- only the link should resolve the user.
    await store.save_linked_identity(
        user_id, "azure", _token(provider_user_id="stable-oid-42"), _userinfo()
    )
    azure_backend.verify_external_token = AsyncMock(
        return_value=(
            _userinfo(email="no-such-user@example.com"),
            _token(provider_user_id="stable-oid-42"),
        )
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    assert data.get("username") == TEST_USERNAME


# ---------------------------------------------------------------------------
# User must pre-exist, even with AUTH_MISSING_ACCOUNT="create"
# ---------------------------------------------------------------------------
async def test_user_must_exist_even_with_create_policy(exchange_app):
    """AUTH_MISSING_ACCOUNT defaults to "create" in this environment
    (navigator_auth/conf.py) and TokenExchangeAuth never imports or checks
    it — `create_external_user` is simply never called (D4)."""
    from navigator_auth.conf import AUTH_MISSING_ACCOUNT

    assert AUTH_MISSING_ACCOUNT == "create"
    client, azure_backend = exchange_app[0], exchange_app[1]
    azure_backend.verify_external_token = AsyncMock(
        return_value=(
            _userinfo(email="brand-new-unknown-user@example.com"),
            _token(provider_user_id="unknown-oid-999"),
        )
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 401, await resp.text()
    db_pool = exchange_app[3]
    async with await db_pool.acquire() as conn:
        rows, _err = await conn.query(
            "SELECT user_id FROM auth.users WHERE email = "
            "'brand-new-unknown-user@example.com'"
        )
    assert not rows, "TokenExchangeAuth must never create a user"


# ---------------------------------------------------------------------------
# Expiration cap
# ---------------------------------------------------------------------------
async def test_expiration_cap_with_expires_at(exchange_app):
    _exchange_backend = exchange_app[2]
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    cap = _exchange_backend._cap_expiration(_token(expires_at=future))
    assert 0 < cap <= 120


async def test_expiration_cap_fallback_max_ttl(exchange_app):
    from navigator_auth.conf import TOKEN_EXCHANGE_MAX_TTL

    _exchange_backend = exchange_app[2]
    cap = _exchange_backend._cap_expiration(_token(expires_at=None))
    assert cap == TOKEN_EXCHANGE_MAX_TTL


async def test_expiration_cap_too_short_401(exchange_app):
    client, azure_backend = exchange_app[0], exchange_app[1]
    almost_expired = datetime.now(timezone.utc) + timedelta(seconds=10)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token(expires_at=almost_expired))
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 401, await resp.text()


async def test_session_max_age_matches_cap(exchange_app):
    """JWT exp-iat reflects the cap (session.max_age is set from the same
    `cap` value inside open_session — already unit-tested for TASK-046)."""
    client, azure_backend, _exchange_backend, db_pool, user_id, secret, algorithm, _vault_ok = exchange_app
    await _clear_identities(db_pool, user_id)
    future = datetime.now(timezone.utc) + timedelta(seconds=300)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token(expires_at=future))
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    claims = _decode(data["token"], secret, algorithm)
    delta = claims["exp"] - claims["iat"]
    assert abs(delta - 300) <= 3


# ---------------------------------------------------------------------------
# Vault: credential stored, not in the session; failure is non-fatal
# ---------------------------------------------------------------------------
async def test_vaults_credential_not_session(exchange_app):
    from navigator_auth.identity.store import IdentityStore

    client, azure_backend, _exchange_backend, db_pool, user_id, _secret, _alg, vault_schema_ok = exchange_app
    await _clear_identities(db_pool, user_id)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(
            _userinfo(),
            _token(
                access_token="super-secret-raw-token",
                refresh_token="super-secret-refresh",
                id_token="super-secret-id-token",
            ),
        )
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    dumped = str(data)
    assert "super-secret-raw-token" not in dumped
    assert "super-secret-refresh" not in dumped
    assert "super-secret-id-token" not in dumped

    if not vault_schema_ok:
        pytest.skip(
            "Pre-existing environment defect: this DB's auth.user_identities "
            "lacks the identity_id column UserIdentity.get()/.insert() need "
            "(unrelated to FEAT-096) -- vault persistence can't be verified "
            "here, but the not-in-response assertions above still hold."
        )
    store = IdentityStore(db_pool)
    identity = await store.get_by_provider(user_id, "azure")
    assert identity is not None
    token = store.decrypt_credential(identity)
    assert token.access_token == "super-secret-raw-token"
    assert token.refresh_token == "super-secret-refresh"
    assert token.id_token == "super-secret-id-token"


async def test_vault_failure_non_fatal(exchange_app, monkeypatch):
    client, azure_backend, _exchange_backend, db_pool, user_id, _secret, _alg, vault_schema_ok = exchange_app
    await _clear_identities(db_pool, user_id)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token())
    )

    async def _boom(self, *args, **kwargs):
        raise RuntimeError("vault down")

    from navigator_auth.identity.store import IdentityStore

    monkeypatch.setattr(IdentityStore, "save_linked_identity", _boom)
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()


# ---------------------------------------------------------------------------
# Basic success callbacks fire
# ---------------------------------------------------------------------------
async def test_fires_basic_callbacks(exchange_app):
    client, azure_backend, exchange_backend, db_pool, user_id, _secret, _alg, _vault_ok = exchange_app
    await _clear_identities(db_pool, user_id)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token())
    )
    calls = []

    async def _fake_callback(request, user, model, **kwargs):
        calls.append((user, kwargs.get("userdata")))

    exchange_backend._callbacks = [_fake_callback]
    try:
        resp = await client.post(
            "/api/v1/login",
            json={"provider": "azure", "token": "graph-access-token"},
            headers={"X-Auth-Method": "TokenExchangeAuth"},
        )
        assert resp.status == 200, await resp.text()
        import asyncio

        await asyncio.sleep(0.05)
        assert len(calls) == 1
    finally:
        exchange_backend._callbacks = None


# ---------------------------------------------------------------------------
# Re-exchange without a refresh token preserves the vaulted one (D10)
# ---------------------------------------------------------------------------
async def test_reexchange_preserves_refresh_token(exchange_app):
    from navigator_auth.identity.store import IdentityStore

    client, azure_backend, _exchange_backend, db_pool, user_id, _secret, _alg, vault_schema_ok = exchange_app
    if not vault_schema_ok:
        pytest.skip(
            "Pre-existing environment defect: this DB's auth.user_identities "
            "lacks the identity_id column UserIdentity.get()/.insert() need "
            "(unrelated to FEAT-096) -- vault persistence can't be verified "
            "here; the refresh-preservation logic itself is unit-tested in "
            "tests/test_identity_id_token.py."
        )
    await _clear_identities(db_pool, user_id)
    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token(refresh_token="first-refresh-token"))
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()

    azure_backend.verify_external_token = AsyncMock(
        return_value=(_userinfo(), _token(refresh_token=None))
    )
    resp = await client.post(
        "/api/v1/login",
        json={"provider": "azure", "token": "graph-access-token-2"},
        headers={"X-Auth-Method": "TokenExchangeAuth"},
    )
    assert resp.status == 200, await resp.text()

    store = IdentityStore(db_pool)
    identity = await store.get_by_provider(user_id, "azure")
    token = store.decrypt_credential(identity)
    assert token.refresh_token == "first-refresh-token"
    assert token.access_token == "raw-access-token"
