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
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# Suppress aiohttp AppKey warnings (raised as errors by pyproject filterwarnings)
pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.asyncio,
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

# Module-level state shared across tests
_client: TestClient = None
_app: web.Application = None


# ---------------------------------------------------------------------------
# Setup / Teardown at module level
# ---------------------------------------------------------------------------
async def _create_app_and_insert_user() -> TestClient:
    """Build app, start server, insert test user."""
    global _client, _app

    import navigator_auth.conf as conf
    conf.AUTHENTICATION_BACKENDS = (
        "navigator_auth.backends.BasicAuth",
    )

    from navigator_auth import AuthHandler

    _app = web.Application()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(secure_cookies=False)
        auth.setup(_app)

    server = TestServer(_app)
    _client = TestClient(server)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await _client.start_server()

    db_pool = _app.get("authdb")
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
    return _client


async def _cleanup():
    """Remove test user and stop server."""
    global _client, _app
    if _app:
        db_pool = _app.get("authdb")
        if db_pool:
            try:
                await db_pool.execute(
                    f"DELETE FROM auth.users WHERE username = '{TEST_USERNAME}'"
                )
            except Exception:
                pass
    if _client:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            await _client.close()
    _client = None
    _app = None


async def _get_client() -> TestClient:
    """Lazily initialize the test client (once per module)."""
    global _client
    if _client is None:
        await _create_app_and_insert_user()
    return _client


@pytest.fixture(autouse=True)
async def _ensure_server():
    """Ensure the server is running before each test and clean up at the end."""
    await _get_client()
    yield
    # Don't clean up between tests – cleanup happens at module end


def teardown_module(module):
    """Synchronous teardown hook; schedules async cleanup."""
    import asyncio
    if _client is not None:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_cleanup())
            else:
                loop.run_until_complete(_cleanup())
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
async def test_successful_login_json():
    """POST JSON credentials returns 200 with token."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status == 200, f"Expected 200, got {resp.status}: {await resp.text()}"
    data = await resp.json()
    assert "token" in data, f"Response missing 'token': {data}"
    assert data.get("username") == TEST_USERNAME


async def test_successful_login_form():
    """POST form-encoded credentials returns 200 with token."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status == 200, f"Expected 200, got {resp.status}: {await resp.text()}"
    data = await resp.json()
    assert "token" in data


async def test_successful_login_query_params():
    """GET with query-string credentials returns 200 with token."""
    client = await _get_client()
    resp = await client.get(
        "/api/v1/login",
        params={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status == 200, f"Expected 200, got {resp.status}: {await resp.text()}"
    data = await resp.json()
    assert "token" in data


async def test_wrong_password():
    """Wrong password returns 403 (FailedAuth)."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        json={"username": TEST_USERNAME, "password": "WrongPassword!"},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (401, 403), (
        f"Expected 401 or 403, got {resp.status}: {await resp.text()}"
    )


async def test_nonexistent_user():
    """Unknown username returns 401/403."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        json={"username": "no_such_user_xyz", "password": "anything"},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (401, 403, 404), (
        f"Expected 401/403/404, got {resp.status}: {await resp.text()}"
    )


async def test_missing_credentials():
    """Empty body returns 401 (InvalidAuth: Missing Credentials)."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        json={},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (400, 401, 403), (
        f"Expected 400/401/403, got {resp.status}: {await resp.text()}"
    )


async def test_missing_password():
    """Username but no password returns 401."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        json={"username": TEST_USERNAME},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (400, 401, 403), (
        f"Expected 400/401/403, got {resp.status}: {await resp.text()}"
    )


async def test_missing_username():
    """Password but no username returns 401."""
    client = await _get_client()
    resp = await client.post(
        "/api/v1/login",
        json={"password": TEST_PASSWORD},
        headers={"X-Auth-Method": "BasicAuth"},
    )
    assert resp.status in (400, 401, 403), (
        f"Expected 400/401/403, got {resp.status}: {await resp.text()}"
    )
