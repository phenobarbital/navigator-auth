"""
Live integration test for BasicAuth backend.

Starts a real aiohttp server with AuthHandler (BasicAuth only),
inserts a test user into PostgreSQL auth.users, and exercises
the /api/v1/login endpoint for success and failure scenarios.

Requirements:
  - PostgreSQL running with the `navigator` database and `auth` schema.
  - Redis running for session storage.
  - Environment configured (env/.env or equivalent).
"""

import hashlib
import base64
import secrets
import warnings
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# All tests share one event loop so the server stays alive across tests.
pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]


# ---------------------------------------------------------------------------
# Password helper – mirrors IdentityProvider.set_password
# ---------------------------------------------------------------------------
def make_password(
    password: str,
    algorithm: str = "pbkdf2_sha256",
    digest: str = "sha256",
    iterations: int = 80000,
    dklen: int = 32,
    salt_length: int = 6,
) -> str:
    salt = secrets.token_hex(salt_length)
    key = hashlib.pbkdf2_hmac(
        digest,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=dklen,
    )
    hst = base64.b64encode(key).decode("utf-8").strip()
    return f"{algorithm}${iterations}${salt}${hst}"


# ---------------------------------------------------------------------------
# Test user constants
# ---------------------------------------------------------------------------
TEST_USERNAME = "test_basicauth_user"
TEST_PASSWORD = "TestP@ss1234"
TEST_EMAIL = "testbasicauth@example.com"
TEST_FIRST_NAME = "Test"
TEST_LAST_NAME = "BasicAuth"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(scope="module")
async def live_app():
    """
    Build and start an aiohttp Application with AuthHandler (BasicAuth only).
    Insert a test user into auth.users, yield the TestClient, then clean up.
    """
    import navigator_auth.conf as conf
    original_backends = conf.AUTHENTICATION_BACKENDS
    conf.AUTHENTICATION_BACKENDS = (
        "navigator_auth.backends.BasicAuth",
    )

    from navigator_auth import AuthHandler

    app = web.Application()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(secure_cookies=False)
        auth.setup(app)

    server = TestServer(app)
    client = TestClient(server)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.start_server()

    db_pool = app.get("authdb")
    assert db_pool is not None, "PostgreSQL pool ('authdb') was not created"

    hashed = make_password(TEST_PASSWORD)

    await db_pool.execute(
        f"DELETE FROM auth.users WHERE username = '{TEST_USERNAME}'"
    )
    await db_pool.execute(
        f"""
        INSERT INTO auth.users
            (username, password, email, first_name, last_name,
             is_active, is_superuser, is_new, is_staff)
        VALUES (
            '{TEST_USERNAME}', '{hashed}', '{TEST_EMAIL}',
            '{TEST_FIRST_NAME}', '{TEST_LAST_NAME}',
            true, false, false, true
        )
        """
    )

    yield client

    # Teardown
    try:
        await db_pool.execute(
            f"DELETE FROM auth.users WHERE username = '{TEST_USERNAME}'"
        )
    except Exception:
        pass

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()

    conf.AUTHENTICATION_BACKENDS = original_backends


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
async def test_successful_login_json(live_app: TestClient):
    """POST JSON credentials returns 200 with token."""
    resp = await live_app.post(
        "/api/v1/login",
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status == 200, f"Expected 200, got {resp.status}: {await resp.text()}"
    data = await resp.json()
    assert "token" in data, f"Response missing 'token': {data}"
    assert data.get("username") == TEST_USERNAME


async def test_successful_login_form(live_app: TestClient):
    """POST form-encoded credentials returns 200 with token."""
    resp = await live_app.post(
        "/api/v1/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status == 200, f"Expected 200, got {resp.status}: {await resp.text()}"
    data = await resp.json()
    assert "token" in data


async def test_successful_login_query_params(live_app: TestClient):
    """GET with query-string credentials returns 200 with token."""
    resp = await live_app.get(
        "/api/v1/login",
        params={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status == 200, f"Expected 200, got {resp.status}: {await resp.text()}"
    data = await resp.json()
    assert "token" in data


async def test_wrong_password(live_app: TestClient):
    """Wrong password returns 403 (FailedAuth)."""
    resp = await live_app.post(
        "/api/v1/login",
        json={"username": TEST_USERNAME, "password": "WrongPassword!"},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (401, 403), (
        f"Expected 401 or 403, got {resp.status}: {await resp.text()}"
    )


async def test_nonexistent_user(live_app: TestClient):
    """Unknown username returns 401/403."""
    resp = await live_app.post(
        "/api/v1/login",
        json={"username": "no_such_user_xyz", "password": "anything"},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (401, 403, 404), (
        f"Expected 401/403/404, got {resp.status}: {await resp.text()}"
    )


async def test_missing_credentials(live_app: TestClient):
    """Empty body returns 401 (InvalidAuth: Missing Credentials)."""
    resp = await live_app.post(
        "/api/v1/login",
        json={},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (400, 401, 403), (
        f"Expected 400/401/403, got {resp.status}: {await resp.text()}"
    )


async def test_missing_password(live_app: TestClient):
    """Username but no password returns 401."""
    resp = await live_app.post(
        "/api/v1/login",
        json={"username": TEST_USERNAME},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (400, 401, 403), (
        f"Expected 400/401/403, got {resp.status}: {await resp.text()}"
    )


async def test_missing_username(live_app: TestClient):
    """Password but no username returns 401."""
    resp = await live_app.post(
        "/api/v1/login",
        json={"password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (400, 401, 403), (
        f"Expected 400/401/403, got {resp.status}: {await resp.text()}"
    )
