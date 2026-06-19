"""Unit tests for the concrete token strategies in navigator_auth.middlewares.strategies."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_auth.middlewares.strategies import (
    APIKeyStrategy,
    PlainTokenStrategy,
    TrocTokenStrategy,
    JWTStrategy,
    DjangoSessionStrategy,
)


class TestAPIKeyStrategy:
    def setup_method(self):
        self.strategy = APIKeyStrategy()

    def test_extract_from_header(self):
        request = make_mocked_request("GET", "/api", headers={"x-api-key": "KEY123"})
        token, scheme = self.strategy.extract(request)
        assert token == "KEY123"
        assert scheme == "api"

    def test_extract_from_query(self):
        request = make_mocked_request("GET", "/api?api_key=QKEY")
        token, scheme = self.strategy.extract(request)
        assert token == "QKEY"
        assert scheme == "api"

    def test_extract_none(self):
        request = make_mocked_request("GET", "/api")
        token, scheme = self.strategy.extract(request)
        assert token is None
        assert scheme is None

    def test_header_takes_precedence(self):
        request = make_mocked_request(
            "GET", "/api?api_key=QKEY",
            headers={"x-api-key": "HKEY"},
        )
        token, _ = self.strategy.extract(request)
        assert token == "HKEY"

    @pytest.mark.asyncio
    async def test_validate_queries_db(self):
        # The validate method uses: async with await db.acquire() as conn:
        # So we need acquire() to return an async context manager.
        mock_conn = AsyncMock()
        mock_conn.fetch_one = AsyncMock(return_value={"user_id": 1, "name": "test"})

        # acquire() is awaited, then the result is used as async context manager.
        # mock_pool.acquire must be an AsyncMock that returns an object
        # implementing __aenter__/__aexit__.
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_pool = MagicMock()
        mock_pool.acquire = AsyncMock(return_value=mock_ctx)

        app = web.Application()
        app["authdb"] = mock_pool
        result = await self.strategy.validate("TOKEN", "api", app)
        assert result["user_id"] == 1

    @pytest.mark.asyncio
    async def test_validate_invalid_key(self):
        mock_conn = AsyncMock()
        mock_conn.fetch_one = AsyncMock(return_value=None)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_pool = MagicMock()
        mock_pool.acquire = AsyncMock(return_value=mock_ctx)

        app = web.Application()
        app["authdb"] = mock_pool
        with pytest.raises(web.HTTPForbidden):
            await self.strategy.validate("BAD", "api", app)


class TestPlainTokenStrategy:
    def setup_method(self):
        self.strategy = PlainTokenStrategy()

    def test_extract_from_authorization(self):
        request = make_mocked_request(
            "GET", "/api",
            headers={"Authorization": "Bearer mytoken"},
        )
        token, scheme = self.strategy.extract(request)
        assert token == "mytoken"
        assert scheme == "Bearer"

    def test_extract_from_auth_query(self):
        request = make_mocked_request("GET", "/api?auth=QTOKEN")
        token, scheme = self.strategy.extract(request)
        assert token == "QTOKEN"
        assert scheme is None

    def test_extract_from_x_token_header(self):
        request = make_mocked_request(
            "GET", "/api",
            headers={"X-Token": "XVAL"},
        )
        token, scheme = self.strategy.extract(request)
        assert token == "XVAL"
        assert scheme is None

    def test_extract_none(self):
        request = make_mocked_request("GET", "/api")
        token, scheme = self.strategy.extract(request)
        assert token is None
        assert scheme is None

    @pytest.mark.asyncio
    async def test_validate_returns_token_and_scheme(self):
        result = await self.strategy.validate("tok", "Bearer", None)
        assert result == {"token": "tok", "scheme": "Bearer"}

    def test_enforce_uses_credentials_required(self):
        request = make_mocked_request("GET", "/api")
        with patch(
            "navigator_auth.middlewares.strategies.AUTH_CREDENTIALS_REQUIRED",
            True,
        ):
            assert self.strategy.should_enforce(request, ()) is True
        with patch(
            "navigator_auth.middlewares.strategies.AUTH_CREDENTIALS_REQUIRED",
            False,
        ):
            assert self.strategy.should_enforce(request, ()) is False


class TestTrocTokenStrategy:
    def setup_method(self):
        self.mock_cipher = MagicMock()
        self.strategy = TrocTokenStrategy(cipher=self.mock_cipher)

    def test_extract_delegates_to_plain(self):
        request = make_mocked_request(
            "GET", "/api?auth=TROCVAL",
        )
        token, scheme = self.strategy.extract(request)
        assert token == "TROCVAL"

    @pytest.mark.asyncio
    async def test_validate_decodes_cipher(self):
        self.mock_cipher.decode.return_value = '{"user": "test"}'
        result = await self.strategy.validate("ENC", None, None)
        self.mock_cipher.decode.assert_called_once_with(passphrase="ENC")
        assert result == '{"user": "test"}'

    @pytest.mark.asyncio
    async def test_validate_invalid_raises(self):
        self.mock_cipher.decode.return_value = None
        with pytest.raises(web.HTTPForbidden):
            await self.strategy.validate("BAD", None, None)


class TestJWTStrategy:
    def setup_method(self):
        self.strategy = JWTStrategy(secret_key="secret", algorithm="HS256")

    def test_extract_bearer_only(self):
        request = make_mocked_request(
            "GET", "/api",
            headers={"Authorization": "Bearer jwt.token.here"},
        )
        token, scheme = self.strategy.extract(request)
        assert token == "jwt.token.here"
        assert scheme == "Bearer"

    def test_extract_wrong_scheme_returns_none(self):
        request = make_mocked_request(
            "GET", "/api",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        token, scheme = self.strategy.extract(request)
        assert token is None

    def test_extract_from_auth_query(self):
        request = make_mocked_request("GET", "/api?auth=jwt.q.token")
        token, scheme = self.strategy.extract(request)
        assert token == "jwt.q.token"

    @pytest.mark.asyncio
    async def test_validate_decodes_jwt(self):
        import jwt as pyjwt
        encoded = pyjwt.encode({"user_id": 42}, "secret", algorithm="HS256")
        result = await self.strategy.validate(encoded, "Bearer", None)
        assert result["user_id"] == 42

    @pytest.mark.asyncio
    async def test_validate_expired_raises(self):
        import jwt as pyjwt
        import time
        encoded = pyjwt.encode(
            {"user_id": 42, "exp": int(time.time()) - 100},
            "secret", algorithm="HS256",
        )
        with pytest.raises(web.HTTPBadRequest, match="Expired"):
            await self.strategy.validate(encoded, "Bearer", None)

    @pytest.mark.asyncio
    async def test_validate_bad_token_raises(self):
        with pytest.raises(web.HTTPBadRequest, match="Invalid"):
            await self.strategy.validate("not.a.jwt", "Bearer", None)


class TestDjangoSessionStrategy:
    def setup_method(self):
        self.strategy = DjangoSessionStrategy(session_prefix="nav_session")

    def test_extract_from_header(self):
        request = make_mocked_request(
            "GET", "/api",
            headers={"x-sessionid": "SESSID123"},
        )
        token, scheme = self.strategy.extract(request)
        assert token == "SESSID123"
        assert scheme == "django"

    def test_extract_none(self):
        request = make_mocked_request("GET", "/api")
        token, scheme = self.strategy.extract(request)
        assert token is None
        assert scheme is None

    @pytest.mark.asyncio
    async def test_validate_decodes_session(self):
        import base64
        session_payload = base64.b64encode(b'abc123:{"user_id":7,"name":"django_user"}')
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=session_payload)
        app = web.Application()
        app["redis"] = mock_redis
        result = await self.strategy.validate("SESSID", "django", app)
        assert result["user_id"] == 7
        assert result["session_id"] == "abc123"
        assert result["key"] == "SESSID"
        mock_redis.get.assert_called_once_with("nav_session:SESSID")

    @pytest.mark.asyncio
    async def test_validate_missing_session(self):
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        app = web.Application()
        app["redis"] = mock_redis
        with pytest.raises(web.HTTPBadRequest, match="Invalid Django Session"):
            await self.strategy.validate("BADSESS", "django", app)
