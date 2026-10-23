"""`_set_address` binds the provider as a parameter (FEAT-105 G9, TASK-121)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from asyncdb.exceptions import DriverError

from navigator_auth.handlers.userattrs import UserAccountHandler

PAYLOAD = "x'; DROP TABLE auth.users; --"


class RecordingConn:
    """Captures (sentence, args, kwargs) so parameterization is assertable."""

    def __init__(self, value="https://example.com/{uid}", exc=None):
        self.calls = []
        self._value = value
        self._exc = exc

    async def fetchval(self, sentence, *args, **kwargs):
        self.calls.append((sentence, args, kwargs))
        if self._exc:
            raise self._exc
        return self._value

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _handler(conn):
    instance = UserAccountHandler.__new__(UserAccountHandler)
    instance._request = MagicMock()
    instance.handler = AsyncMock(return_value=conn)
    return instance


class TestSetAddressParameterization:
    @pytest.mark.asyncio
    async def test_statement_uses_a_placeholder(self):
        conn = RecordingConn()
        await _handler(conn)._set_address(value=None, column=None, data={"uid": "u1", "provider": PAYLOAD})
        assert len(conn.calls) == 1
        sentence = conn.calls[0][0]
        assert "$1" in sentence and PAYLOAD not in sentence

    @pytest.mark.asyncio
    async def test_payload_arrives_as_a_bound_argument(self):
        conn = RecordingConn()
        await _handler(conn)._set_address(value=None, column=None, data={"uid": "u1", "provider": PAYLOAD})
        assert conn.calls[0][1] == (PAYLOAD,)

    @pytest.mark.asyncio
    async def test_no_brace_placeholder_survives_in_the_statement(self):
        conn = RecordingConn()
        await _handler(conn)._set_address(value=None, column=None, data={"uid": "u1", "provider": "twitter"})
        sentence = conn.calls[0][0]
        assert "{provider}" not in sentence and "'" not in sentence

    @pytest.mark.asyncio
    async def test_result_template_is_still_formatted_with_uid(self):
        conn = RecordingConn("https://x.test/{uid}")
        result = await _handler(conn)._set_address(value=None, column=None, data={"uid": "u1", "provider": "x"})
        assert result == "https://x.test/u1"

    @pytest.mark.asyncio
    async def test_missing_provider_issues_no_query(self):
        conn = RecordingConn()
        result = await _handler(conn)._set_address(value=None, column=None, data={"uid": "u1"})
        assert conn.calls == [] and result is None

    @pytest.mark.asyncio
    async def test_driver_error_is_still_swallowed(self):
        conn = RecordingConn(exc=DriverError("boom"))
        result = await _handler(conn)._set_address(value=None, column=None, data={"uid": "u1", "provider": "x"})
        assert result is None


class TestClassAttribute:
    def test_social_network_declares_a_placeholder(self):
        assert "$1" in UserAccountHandler.social_network
        assert "{provider}" not in UserAccountHandler.social_network
