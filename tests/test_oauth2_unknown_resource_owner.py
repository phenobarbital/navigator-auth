"""FEAT-108 M6 — unknown or disabled resource owners fail closed; store outages answer 503.

TASK-200 adds the IdentityProvider.user_from_id tests; TASK-203/204 append provider tests.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError

from navigator_auth.backends.idp import IdentityProvider
from navigator_auth.exceptions import IdentityStoreUnavailable, UserNotFound


def _idp(*, get=None, acquire_error=None) -> IdentityProvider:
    """IdentityProvider over a fake pool: `async with await db.acquire() as conn`."""
    idp = IdentityProvider()
    conn_ctx = MagicMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn_ctx, side_effect=acquire_error)
    idp.app = {"authdb": pool}
    idp.user_search = MagicMock()
    idp.user_search.get = get or AsyncMock(return_value=None)
    return idp


class TestUserFromId:
    @pytest.mark.asyncio
    async def test_found(self):
        user = MagicMock()
        assert await _idp(get=AsyncMock(return_value=user)).user_from_id(1) is user

    @pytest.mark.asyncio
    async def test_no_data_found_is_user_not_found(self):
        with pytest.raises(UserNotFound):
            await _idp(get=AsyncMock(side_effect=NoDataFound("none"))).user_from_id(1)

    @pytest.mark.asyncio
    async def test_empty_result_is_user_not_found(self):
        with pytest.raises(UserNotFound):
            await _idp(get=AsyncMock(return_value=None)).user_from_id(1)

    @pytest.mark.asyncio
    async def test_validation_error_is_reraised(self):
        err = ValidationError("bad row", payload={"a": 1})
        with pytest.raises(ValidationError) as info:
            await _idp(get=AsyncMock(side_effect=err)).user_from_id(1)
        assert info.value is err

    @pytest.mark.asyncio
    @pytest.mark.parametrize("where", ["acquire", "query", "no_pool"])
    async def test_store_outage_is_identity_store_unavailable(self, where):
        secret = "db-secret-detail"
        if where == "acquire":
            cause = ConnectionError(secret)
            idp = _idp(acquire_error=cause)
        elif where == "query":
            cause = RuntimeError(secret)
            idp = _idp(get=AsyncMock(side_effect=cause))
        else:
            cause = None
            idp = _idp()
            idp.app = {}
        with pytest.raises(IdentityStoreUnavailable) as info:
            await idp.user_from_id(1)
        exc = info.value
        assert exc.status == 503
        assert secret not in str(exc)
        if cause is not None:
            assert exc.__cause__ is cause
        else:
            assert isinstance(exc.__cause__, KeyError)
