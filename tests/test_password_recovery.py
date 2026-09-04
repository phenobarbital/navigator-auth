from types import SimpleNamespace

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from navigator_auth.conf import REDIS_AUTH_URL
from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.handlers.recovery.policy import PasswordPolicy
from navigator_auth.handlers.recovery.store import (
    RecoveryTokenStore,
    RECOVERY_KEY_PREFIX,
    CONFIRM_KEY_PREFIX,
    _hash_token,
)
from navigator_auth.handlers.recovery.limiter import RateLimiter
from navigator_auth.handlers.recovery.revoke import SessionRevoker
from navigator_auth.libs.json import json_encoder, json_decoder
from navigator_auth.models import User

TEST_SECRET = b"test-secret-key"


class TestRecoveryConfig:
    def test_defaults(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_TTL == 3600
        assert conf.AUTH_RECOVERY_CONFIRM_TTL == 900
        assert conf.AUTH_RECOVERY_RATE_EMAIL == "3/hour"
        assert conf.AUTH_RECOVERY_RATE_IP == "10/hour"
        assert conf.AUTH_RECOVERY_PWD_MIN_LENGTH == 8

    def test_secret_falls_back_to_secret_key(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_SECRET
        assert isinstance(conf.AUTH_RECOVERY_SECRET, bytes)


class TestUserPasswordWidth:
    def test_user_password_column_fits_hash(self):
        """A real PBKDF2 hash (77 chars) must fit the declared max."""
        h = set_basic_password("correct horse battery staple")
        assert len(h) == 77
        col = User.get_columns()["password"]
        assert col.metadata.get("max", 0) >= len(h)

    def test_hash_roundtrips_through_model(self):
        h = set_basic_password("correct horse battery staple")
        u = User(user_id=1, username="t", password=h)
        assert u.password == h
        assert u.is_valid()


class TestPasswordPolicy:
    def test_policy_accepts_valid(self):
        assert PasswordPolicy().validate("abc12345") == []

    def test_policy_min_length(self):
        v = PasswordPolicy().validate("abc1234")      # 7 chars
        assert [x.rule for x in v] == ["min_length"]

    def test_policy_requires_letter_and_digit(self):
        assert "needs_letter" in [x.rule for x in PasswordPolicy().validate("12345678")]
        assert "needs_digit" in [x.rule for x in PasswordPolicy().validate("abcdefgh")]

    def test_policy_returns_all_violations(self):
        rules = {x.rule for x in PasswordPolicy().validate("abc")}
        assert rules == {"min_length", "needs_digit"}

    def test_policy_rejects_current_password(self):
        h = set_basic_password("abc12345")
        v = PasswordPolicy().validate("abc12345", current_hash=h)
        assert [x.rule for x in v] == ["same_as_current"]

    def test_policy_no_current_hash_is_fine(self):
        assert PasswordPolicy().validate("abc12345", current_hash=None) == []

    def test_policy_malformed_current_hash_does_not_raise(self):
        assert PasswordPolicy().validate("abc12345", current_hash="garbage") == []

    def test_policy_message_never_echoes_password(self):
        for v in PasswordPolicy().validate("a"):
            assert "a" not in v.message.replace("at least", "")  # no echo of the input


@pytest_asyncio.fixture
async def redis_pool():
    pool = aioredis.ConnectionPool.from_url(
        REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
    )
    yield pool
    await pool.disconnect()


@pytest_asyncio.fixture
async def redis(redis_pool):
    async with aioredis.Redis(connection_pool=redis_pool) as r:
        yield r


@pytest.fixture
def recovery_user():
    return SimpleNamespace(
        user_id=424242,
        username="recovery_test_user",
        email="recovery_test@example.com",
    )


@pytest_asyncio.fixture
async def broken_redis_pool():
    """A pool pointing nowhere, so every command raises a connection error.

    Used to exercise RateLimiter's fail-open behaviour without mocking.
    """
    pool = aioredis.ConnectionPool.from_url(
        "redis://recovery-test-unreachable-host.invalid:6379/0",
        decode_responses=True,
        encoding="utf-8",
        socket_connect_timeout=1,
    )
    yield pool
    await pool.disconnect()


@pytest.fixture
def recovery_store(redis_pool):
    return RecoveryTokenStore(redis_pool, secret=TEST_SECRET)


class TestRecoveryTokenStore:
    """Module 3 — RecoveryTokenStore, against a real Redis instance."""

    @pytest_asyncio.fixture(autouse=True)
    async def _clean(self, redis_pool):
        async def _purge():
            async with aioredis.Redis(connection_pool=redis_pool) as r:
                keys = await r.keys(f"{RECOVERY_KEY_PREFIX}*")
                if keys:
                    await r.delete(*keys)
        await _purge()
        yield
        await _purge()

    @pytest.mark.asyncio
    async def test_store_key_is_hashed(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        await recovery_store.issue_confirmation(token)
        keys = await redis.keys(f"{RECOVERY_KEY_PREFIX}*")
        assert not any(token in k for k in keys)
        for k in keys:
            value = await redis.get(k)
            assert token not in (value or "")

    @pytest.mark.asyncio
    async def test_store_recovery_survives_validate(self, recovery_store, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        assert await recovery_store.validate_recovery(token) is not None
        assert await recovery_store.validate_recovery(token) is not None   # D4

    @pytest.mark.asyncio
    async def test_store_confirmation_rotates(self, recovery_store, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        c1, _ = await recovery_store.issue_confirmation(token)
        c2, _ = await recovery_store.issue_confirmation(token)
        assert await recovery_store.consume_confirmation(c1) is None
        assert await recovery_store.consume_confirmation(c2) is not None

    @pytest.mark.asyncio
    async def test_rotation_preserves_stage1_ttl(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        before = await redis.ttl(key)
        await recovery_store.issue_confirmation(token)
        after = await redis.ttl(key)
        assert after <= before

    @pytest.mark.asyncio
    async def test_store_confirmation_single_use(self, recovery_store, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        c, _ = await recovery_store.issue_confirmation(token)
        assert await recovery_store.consume_confirmation(c) is not None
        assert await recovery_store.consume_confirmation(c) is None

    @pytest.mark.asyncio
    async def test_store_signature_roundtrip(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        assert await recovery_store.validate_recovery(token) is not None
        # Tamper with the payload directly in Redis.
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        raw = await redis.get(key)
        data = json_decoder(raw)
        data["username"] = "tampered"
        await redis.set(key, json_encoder(data), keepttl=True)
        assert await recovery_store.validate_recovery(token) is None

    @pytest.mark.asyncio
    async def test_store_wrong_secret_rejected(self, redis_pool, recovery_user):
        store_a = RecoveryTokenStore(redis_pool, secret=b"secret-a")
        store_b = RecoveryTokenStore(redis_pool, secret=b"secret-b")
        token, _ = await store_a.issue_recovery(recovery_user)
        assert await store_b.validate_recovery(token) is None

    @pytest.mark.asyncio
    async def test_store_ttls(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        ttl = await redis.ttl(key)
        assert 0 < ttl <= 3600

        c, _ = await recovery_store.issue_confirmation(token)
        ckey = f"{CONFIRM_KEY_PREFIX}{_hash_token(c)}"
        cttl = await redis.ttl(ckey)
        assert 0 < cttl <= 900

    @pytest.mark.asyncio
    async def test_store_expired_returns_none(self, redis_pool, recovery_user):
        store = RecoveryTokenStore(redis_pool, secret=TEST_SECRET)
        token, _ = await store.issue_recovery(recovery_user)
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        async with aioredis.Redis(connection_pool=redis_pool) as r:
            await r.delete(key)  # simulate expiry
        assert await store.validate_recovery(token) is None

    @pytest.mark.asyncio
    async def test_drop_pair_deletes_both_records(
        self, recovery_store, redis, recovery_user
    ):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        c, confirmation = await recovery_store.issue_confirmation(token)
        recovery_key_hash = confirmation.recovery_key
        confirm_key_hash = _hash_token(c)
        await recovery_store.drop_pair(recovery_key_hash, confirm_key_hash)
        assert await redis.get(f"{RECOVERY_KEY_PREFIX}{recovery_key_hash}") is None
        assert await redis.get(f"{CONFIRM_KEY_PREFIX}{confirm_key_hash}") is None


class TestRateLimiter:
    """Module 4 — RateLimiter, against a real Redis instance."""

    @pytest_asyncio.fixture(autouse=True)
    async def _clean(self, redis_pool):
        from navigator_auth.handlers.recovery.limiter import RATE_KEY_PREFIX

        async def _purge():
            async with aioredis.Redis(connection_pool=redis_pool) as r:
                keys = await r.keys(f"{RATE_KEY_PREFIX}*")
                if keys:
                    await r.delete(*keys)
        await _purge()
        yield
        await _purge()

    @pytest.mark.asyncio
    async def test_limiter_allows_under_limit(self, redis_pool):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        assert all([await rl.check("a@b.c") for _ in range(3)])

    @pytest.mark.asyncio
    async def test_limiter_blocks_over_limit(self, redis_pool):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        for _ in range(3):
            await rl.check("a@b.c")
        assert await rl.check("a@b.c") is False

    @pytest.mark.asyncio
    async def test_limiter_fails_open(self, broken_redis_pool, caplog):
        import logging
        caplog.set_level(logging.WARNING)
        rl = RateLimiter(broken_redis_pool, "3/hour", "email")
        assert await rl.check("a@b.c") is True
        assert "WARNING" in caplog.text

    @pytest.mark.asyncio
    async def test_limiter_malformed_spec_disables(self, redis_pool):
        rl = RateLimiter(redis_pool, "garbage", "email")
        assert all([await rl.check("a@b.c") for _ in range(50)])

    @pytest.mark.asyncio
    async def test_limiter_prefixes_independent(self, redis_pool):
        e = RateLimiter(redis_pool, "3/hour", "email")
        i = RateLimiter(redis_pool, "3/hour", "ip")
        for _ in range(3):
            await e.check("x")
        assert await i.check("x") is True

    @pytest.mark.asyncio
    async def test_no_raw_email_in_keys(self, redis_pool, redis):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        await rl.check("user@example.com")
        assert not any("user@example.com" in k for k in await redis.keys("*"))

    @pytest.mark.asyncio
    async def test_window_expires_and_reallows(self, redis_pool):
        rl = RateLimiter(redis_pool, "1/second", "email")
        assert await rl.check("expiring@b.c") is True
        assert await rl.check("expiring@b.c") is False
        import asyncio
        await asyncio.sleep(1.1)
        assert await rl.check("expiring@b.c") is True


@pytest.fixture
def idp():
    from navigator_auth.backends.idp import IdentityProvider

    provider = IdentityProvider()
    # Reset the class-level registry cache between tests (mirrors the
    # pattern in tests/test_oauth2_jwks.py).
    IdentityProvider._key_registry = None
    yield provider
    IdentityProvider._key_registry = None


@pytest.fixture
def revoker(redis_pool):
    return SessionRevoker(redis_pool)


@pytest_asyncio.fixture
async def access_token_storage():
    """A real AccessTokenStorage, closed at teardown.

    AccessTokenStorage opens its own redis.asyncio client independent of
    the `redis_pool` fixture's ConnectionPool; leaving it unclosed hangs
    pytest-asyncio's per-test asyncio.Runner.close() at teardown.
    """
    from navigator_auth.backends.oauth2.code_backend import AccessTokenStorage

    storage = AccessTokenStorage()
    yield storage
    await storage.redis.aclose()


class TestJTI:
    """Module 5 — jti emission on Basic/OAuth2 JWTs."""

    # Pre-existing environment limitation (see tests/test_basic_open_session.py):
    # the dev/test SECRET_KEY is shorter than PyJWT's recommended HMAC key
    # length. Not in scope for FEAT-098.
    pytestmark = pytest.mark.filterwarnings(
        "ignore::jwt.warnings.InsecureKeyLengthWarning"
    )

    def test_create_token_emits_jti(self, idp):
        tok, _, _, _ = idp.create_token(data={"user_id": 1})
        _, payload = idp.decode_token(tok)
        assert "jti" in payload
        tok2, _, _, _ = idp.create_token(data={"user_id": 1})
        assert idp.decode_token(tok2)[1]["jti"] != payload["jti"]

    def test_caller_cannot_inject_jti(self, idp):
        tok, _, _, _ = idp.create_token(data={"user_id": 1, "jti": "attacker"})
        assert idp.decode_token(tok)[1]["jti"] != "attacker"

    @pytest.mark.asyncio
    async def test_jti_absent_token_still_valid(self):
        """A pre-upgrade JWT with no jti must keep working."""
        import logging
        from navigator_auth.auth import AuthHandler

        fake_self = SimpleNamespace(backends={}, logger=logging.getLogger("test"))
        payload = {"user_id": 1}          # minted the old way, no jti
        assert await AuthHandler._token_is_revoked(fake_self, payload) is False


class TestSessionRevoker:
    """Module 5 — SessionRevoker, against a real Redis instance."""

    @pytest.mark.asyncio
    async def test_revoker_kills_session_and_index(self, revoker, redis):
        username = "revoker_test_user"
        session_id = "revoker-test-session-id"
        await redis.set(f"session:{session_id}", "opaque-session-data")
        await redis.set(f"user:{username}", session_id)

        user = SimpleNamespace(user_id=None, username=username)
        count = await revoker.revoke_user(None, user)

        assert count == 2
        assert await redis.get(f"session:{session_id}") is None
        assert await redis.get(f"user:{username}") is None

    @pytest.mark.asyncio
    async def test_revoker_revokes_jwt(self, revoker, redis_pool, access_token_storage):
        from datetime import datetime, timedelta
        from uuid import uuid4
        from navigator_auth.backends.oauth2.models import OauthAccessTokenRecord

        storage = access_token_storage
        user_id = 837465
        jti = str(uuid4())
        record = OauthAccessTokenRecord(
            jti=jti, user_id=user_id, client_id="basic",
            expires_at=datetime.now() + timedelta(hours=1),
        )
        await storage.save(record)

        key = f"auth:user:jti:{user_id}"
        async with aioredis.Redis(connection_pool=redis_pool) as r:
            await r.sadd(key, jti)

        fake_backend = SimpleNamespace(access_token_storage=storage)
        fake_auth = SimpleNamespace(backends={"BasicAuth": fake_backend})
        fake_request = SimpleNamespace(app={"auth": fake_auth})
        user = SimpleNamespace(user_id=user_id, username=None)

        count = await revoker.revoke_user(fake_request, user)
        assert count == 1
        assert await storage.is_revoked(jti) is True

    @pytest.mark.asyncio
    async def test_revocation_marker_outlives_token(self, redis, access_token_storage):
        """TTL comes from the saved record, not the 3600s fallback."""
        from datetime import datetime, timedelta
        from uuid import uuid4
        from navigator_auth.backends.oauth2.models import OauthAccessTokenRecord

        storage = access_token_storage
        jti = str(uuid4())
        record = OauthAccessTokenRecord(
            jti=jti, user_id=1, client_id="basic",
            expires_at=datetime.now() + timedelta(hours=2),
        )
        await storage.save(record)
        await storage.revoke(jti)
        ttl = await redis.ttl(f"oauth2:jti:revoked:{jti}")
        assert ttl > 3600  # not the flat fallback

    @pytest.mark.asyncio
    async def test_revoker_partial_failure(self, revoker, redis_pool, access_token_storage):
        """One failing delete does not abort the rest; count reflects reality."""
        from unittest.mock import AsyncMock

        storage = access_token_storage
        storage.revoke = AsyncMock(side_effect=[Exception("boom"), True])

        user_id = 918273
        jti1, jti2 = "jti-fail-case", "jti-ok-case"
        key = f"auth:user:jti:{user_id}"
        async with aioredis.Redis(connection_pool=redis_pool) as r:
            await r.sadd(key, jti1, jti2)

        fake_backend = SimpleNamespace(access_token_storage=storage)
        fake_auth = SimpleNamespace(backends={"BasicAuth": fake_backend})
        fake_request = SimpleNamespace(app={"auth": fake_auth})
        user = SimpleNamespace(user_id=user_id, username=None)

        count = await revoker.revoke_user(fake_request, user)
        assert count == 1   # only the successful one counted
        assert storage.revoke.call_count == 2


class TestNotificationPayloadSecrecy:
    def test_repr_hides_token(self):
        from navigator_auth.handlers.recovery.types import NotificationPayload
        import datetime
        p = NotificationPayload(
            email="a@b.c", display_name="A", username="a",
            token="SUPERSECRETTOKEN", url="https://x/?token=SUPERSECRETTOKEN",
            expires_at=datetime.datetime.now(), found=True,
        )
        assert "SUPERSECRETTOKEN" not in repr(p)


# ---------------------------------------------------------------------------
# Module 6 — PasswordRecoveryHandler, live integration (real Postgres +
# Redis, real aiohttp server). Mirrors the `live_app` pattern used in
# tests/test_basic_auth.py.
# ---------------------------------------------------------------------------
import warnings  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer, TestClient  # noqa: E402

RECOVERY_TEST_USERNAME = "test_recovery_user"
RECOVERY_TEST_PASSWORD = "OldP@ssw0rd1"
RECOVERY_TEST_EMAIL = "test_recovery_user@example.com"
RECOVERY_UNKNOWN_EMAIL = "no_such_recovery_user@example.com"
RECOVERY_DUP_EMAIL = "dup_recovery_user@example.com"

# Captured NotificationPayloads / failure toggle for the test callback,
# configured onto handler.AUTH_RECOVERY_CALLBACK below.
_CAPTURED_NOTIFICATIONS: list = []
_RAISE_ON_CALLBACK: list = [False]


async def _test_recovery_callback(payload):
    if _RAISE_ON_CALLBACK[0]:
        raise RuntimeError("callback boom (test)")
    _CAPTURED_NOTIFICATIONS.append(payload)


async def _request_and_confirm_token(client, email=RECOVERY_TEST_EMAIL):
    """Drive steps 1 -> 2, return (recovery_token, confirmation_token)."""
    _CAPTURED_NOTIFICATIONS.clear()
    resp = await client.post("/api/v1/password-recovery", json={"email": email})
    assert resp.status == 200, await resp.text()
    assert len(_CAPTURED_NOTIFICATIONS) == 1
    recovery_token = _CAPTURED_NOTIFICATIONS[0].token
    resp2 = await client.get(f"/api/v1/password-recovery/{recovery_token}")
    assert resp2.status == 200, await resp2.text()
    data = await resp2.json()
    return recovery_token, data["token"]


@pytest_asyncio.fixture(scope="module")
async def recovery_app():
    """Real AuthHandler(BasicAuth) app with the FEAT-098 routes wired in."""
    import navigator_auth.conf as conf
    from navigator_auth.handlers.recovery import handler as handler_module

    original_backends = conf.AUTHENTICATION_BACKENDS
    conf.AUTHENTICATION_BACKENDS = ("navigator_auth.backends.BasicAuth",)

    # PasswordRecoveryHandler reads these as module globals at call time,
    # so patching the handler module's attributes (not conf's) before the
    # first request takes effect for every request through this app.
    original_callback = handler_module.AUTH_RECOVERY_CALLBACK
    original_template = handler_module.AUTH_RECOVERY_URL_TEMPLATE
    original_rate_email = handler_module.AUTH_RECOVERY_RATE_EMAIL
    original_rate_ip = handler_module.AUTH_RECOVERY_RATE_IP
    handler_module.AUTH_RECOVERY_CALLBACK = (
        "tests.test_password_recovery._test_recovery_callback"
    )
    handler_module.AUTH_RECOVERY_URL_TEMPLATE = (
        "https://app.example/reset?token={token}"
    )
    # Generous: many tests in this class hit step 1 for the same address.
    handler_module.AUTH_RECOVERY_RATE_EMAIL = "1000/hour"
    handler_module.AUTH_RECOVERY_RATE_IP = "1000/hour"

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

    hashed = set_basic_password(RECOVERY_TEST_PASSWORD)
    usernames = (RECOVERY_TEST_USERNAME, "dup_recovery_a", "dup_recovery_b")

    async def _cleanup():
        for uname in usernames:
            try:
                await db_pool.execute(
                    f"DELETE FROM auth.users WHERE username = '{uname}'"
                )
            except Exception:  # pylint: disable=W0703
                pass

    await _cleanup()
    await db_pool.execute(
        f"""
        INSERT INTO auth.users
            (username, password, email, first_name, last_name,
             is_active, is_superuser, is_new, is_staff)
        VALUES (
            '{RECOVERY_TEST_USERNAME}', '{hashed}', '{RECOVERY_TEST_EMAIL}',
            'Recovery', 'Test', true, false, false, true
        )
        """
    )
    # Two active users sharing one e-mail, for the ambiguous-lookup test.
    await db_pool.execute(
        f"""
        INSERT INTO auth.users
            (username, password, email, first_name, last_name,
             is_active, is_superuser, is_new, is_staff)
        VALUES
            ('dup_recovery_a', '{hashed}', '{RECOVERY_DUP_EMAIL}', 'Dup', 'A',
             true, false, false, true),
            ('dup_recovery_b', '{hashed}', '{RECOVERY_DUP_EMAIL}', 'Dup', 'B',
             true, false, false, true)
        """
    )

    # Same hang-avoidance as FEAT-096 TASK-046 (see test_basic_auth.py):
    # production AUTH_SUCCESSFUL_CALLBACKS reach an external service that
    # is unavailable here.
    auth.backends["BasicAuth"]._callbacks = None

    yield client, db_pool

    await _cleanup()

    # Pre-existing gap (backends/oauth2/backend.py, out of TASK-067's file
    # scope): Oauth2Provider.on_startup gives itself its own
    # AccessTokenStorage (a *second*, separate redis.from_url() client
    # from BasicAuth's) but Oauth2Provider.on_cleanup is a no-op — it
    # never closes it. BasicAuth.on_cleanup (TASK-066) only closes its
    # own. SessionRevoker.revoke_user() (step 3) walks every backend's
    # access_token_storage, including Oauth2Provider's, and is the first
    # thing in this test suite to actually use that particular
    # connection; left open, it hangs pytest-asyncio's per-test
    # asyncio.Runner.close() the same way an unclosed AccessTokenStorage
    # did in TASK-066. Close every backend's access_token_storage here,
    # defensively, rather than widen this task's file list to patch
    # Oauth2Provider.on_cleanup.
    for backend in auth.backends.values():
        storage = getattr(backend, "access_token_storage", None)
        if storage is not None:
            try:
                await storage.redis.aclose()
            except Exception:  # pylint: disable=W0703
                pass

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()

    # PasswordRecoveryHandler's ConnectionPool is a class-level singleton
    # (see handler.py — one pool for the process, never per-request); left
    # open it hangs pytest-asyncio's per-test asyncio.Runner.close() the
    # same way an unclosed AccessTokenStorage did in TASK-066.
    if handler_module.PasswordRecoveryHandler._pool is not None:
        await handler_module.PasswordRecoveryHandler._pool.disconnect()
        handler_module.PasswordRecoveryHandler._pool = None
        handler_module.PasswordRecoveryHandler._store = None
        handler_module.PasswordRecoveryHandler._policy = None
        handler_module.PasswordRecoveryHandler._email_limiter = None
        handler_module.PasswordRecoveryHandler._ip_limiter = None
        handler_module.PasswordRecoveryHandler._revoker = None

    conf.AUTHENTICATION_BACKENDS = original_backends
    handler_module.AUTH_RECOVERY_CALLBACK = original_callback
    handler_module.AUTH_RECOVERY_URL_TEMPLATE = original_template
    handler_module.AUTH_RECOVERY_RATE_EMAIL = original_rate_email
    handler_module.AUTH_RECOVERY_RATE_IP = original_rate_ip


class TestRecoveryEndpoints:
    """Module 6 — the three endpoints, live against Postgres + Redis."""

    pytestmark = [
        pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
        pytest.mark.filterwarnings("ignore::DeprecationWarning"),
        pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
        pytest.mark.asyncio(loop_scope="module"),
    ]

    async def test_step1_never_returns_token(self, recovery_app):
        client, _ = recovery_app
        resp = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_TEST_EMAIL}
        )
        assert resp.status == 200
        body = await resp.json()
        assert "token" not in body
        assert "refresh_token" not in body

    async def test_step1_unknown_email_same_body(self, recovery_app):
        client, _ = recovery_app
        known = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_TEST_EMAIL}
        )
        unknown = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_UNKNOWN_EMAIL}
        )
        assert known.status == unknown.status == 200
        assert await known.json() == await unknown.json()

    async def test_step1_invokes_callback_with_url(self, recovery_app):
        client, _ = recovery_app
        _CAPTURED_NOTIFICATIONS.clear()
        resp = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_TEST_EMAIL}
        )
        assert resp.status == 200
        assert len(_CAPTURED_NOTIFICATIONS) == 1
        notif = _CAPTURED_NOTIFICATIONS[0]
        assert notif.found is True
        assert notif.token in notif.url
        assert notif.url.startswith("https://app.example/reset?token=")

    async def test_callback_failure_does_not_leak(self, recovery_app):
        from navigator_auth.handlers.recovery.handler import _GENERIC_STEP1_BODY

        client, _ = recovery_app
        _RAISE_ON_CALLBACK[0] = True
        try:
            resp = await client.post(
                "/api/v1/password-recovery", json={"email": RECOVERY_TEST_EMAIL}
            )
            assert resp.status == 200
            assert await resp.json() == _GENERIC_STEP1_BODY
        finally:
            _RAISE_ON_CALLBACK[0] = False

    async def test_step2_refresh_is_safe(self, recovery_app):
        client, _ = recovery_app
        _CAPTURED_NOTIFICATIONS.clear()
        resp = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_TEST_EMAIL}
        )
        assert resp.status == 200
        recovery_token = _CAPTURED_NOTIFICATIONS[0].token

        r1 = await client.get(f"/api/v1/password-recovery/{recovery_token}")
        c1 = (await r1.json())["token"]
        r2 = await client.get(f"/api/v1/password-recovery/{recovery_token}")
        c2 = (await r2.json())["token"]
        assert c1 != c2  # rotated

        r3 = await client.get(f"/api/v1/password-recovery/{recovery_token}")
        assert r3.status == 200  # D4 — stage-1 survives repeat validation

    async def test_step3_password_mismatch(self, recovery_app):
        client, _ = recovery_app
        _, confirm_token = await _request_and_confirm_token(client)
        resp = await client.post(
            "/api/v1/password-recovery/confirm",
            json={
                "password": "NewPassw0rd1!",
                "confirm_password": "Different1!",
                "token": confirm_token,
            },
        )
        assert resp.status == 400

    async def test_step3_policy_violation_keeps_tokens(self, recovery_app):
        client, _ = recovery_app
        _, confirm_token = await _request_and_confirm_token(client)
        weak = "short"
        resp = await client.post(
            "/api/v1/password-recovery/confirm",
            json={
                "password": weak, "confirm_password": weak, "token": confirm_token,
            },
        )
        assert resp.status == 422
        body = await resp.json()
        assert "violations" in body

        # 422 must NOT have consumed the confirmation token: retry with a
        # strong password on the SAME token succeeds.
        strong = "Str0ngPassword!"
        resp2 = await client.post(
            "/api/v1/password-recovery/confirm",
            json={
                "password": strong, "confirm_password": strong, "token": confirm_token,
            },
        )
        assert resp2.status == 202

    async def test_step3_success(self, recovery_app):
        client, db_pool = recovery_app
        _, confirm_token = await _request_and_confirm_token(client)
        new_pw = "AnotherStr0ng!"
        resp = await client.post(
            "/api/v1/password-recovery/confirm",
            json={
                "password": new_pw, "confirm_password": new_pw, "token": confirm_token,
            },
        )
        assert resp.status == 202
        body = await resp.json()
        assert body["status"] == "OK"

        async with await db_pool.acquire() as conn:
            User.Meta.connection = conn
            row = await User.get(username=RECOVERY_TEST_USERNAME)
        assert row.is_new is False  # D17

    async def test_step3_replay_rejected(self, recovery_app):
        client, _ = recovery_app
        _, confirm_token = await _request_and_confirm_token(client)
        pw = "ReplayTest1!"
        resp1 = await client.post(
            "/api/v1/password-recovery/confirm",
            json={"password": pw, "confirm_password": pw, "token": confirm_token},
        )
        assert resp1.status == 202
        resp2 = await client.post(
            "/api/v1/password-recovery/confirm",
            json={"password": pw, "confirm_password": pw, "token": confirm_token},
        )
        assert resp2.status == 400

    async def test_no_autologin(self, recovery_app):
        client, _ = recovery_app
        _, confirm_token = await _request_and_confirm_token(client)
        pw = "NoAutoLogin1!"
        resp = await client.post(
            "/api/v1/password-recovery/confirm",
            json={"password": pw, "confirm_password": pw, "token": confirm_token},
        )
        assert resp.status == 202
        body = await resp.json()
        assert "token" not in body
        assert "refresh_token" not in body

    async def test_duplicate_email_takes_generic_path(self, recovery_app, caplog):
        import logging
        client, _ = recovery_app
        _CAPTURED_NOTIFICATIONS.clear()
        caplog.set_level(logging.WARNING)
        resp = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_DUP_EMAIL}
        )
        assert resp.status == 200
        assert len(_CAPTURED_NOTIFICATIONS) == 1
        assert _CAPTURED_NOTIFICATIONS[0].found is False
        assert any(
            "multiple users match" in rec.message for rec in caplog.records
        )

    async def test_legacy_routes_aliased(self, recovery_app):
        client, _ = recovery_app
        _CAPTURED_NOTIFICATIONS.clear()
        resp = await client.post(
            "/api/v1/forgot-password", json={"email": RECOVERY_UNKNOWN_EMAIL}
        )
        assert resp.status == 200

        resp2 = await client.post(
            "/api/v1/reset-password",
            json={
                "password": "x", "confirm_password": "x", "token": "not-a-real-token",
            },
        )
        # Reaches step-3 logic (invalid token -> 400), proving the alias
        # dispatches to the confirm branch rather than step 1.
        assert resp2.status == 400

    async def test_token_never_logged(self, recovery_app, caplog):
        client, _ = recovery_app
        _CAPTURED_NOTIFICATIONS.clear()
        caplog.set_level("DEBUG")
        resp = await client.post(
            "/api/v1/password-recovery", json={"email": RECOVERY_TEST_EMAIL}
        )
        assert resp.status == 200
        token = _CAPTURED_NOTIFICATIONS[0].token
        resp2 = await client.get(f"/api/v1/password-recovery/{token}")
        assert resp2.status == 200
        for rec in caplog.records:
            assert token not in rec.getMessage()
