"""FEAT-108 M3 — APIKeyAuth declines bearers that are not API keys (S1)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.api import APIKeyAuth
from navigator_auth.exceptions import InvalidAuth


def _backend() -> APIKeyAuth:
    """Build APIKeyAuth without application wiring."""
    backend = object.__new__(APIKeyAuth)
    backend.logger = MagicMock()
    backend.get_payload = AsyncMock(return_value=("bearer", "jwt"))
    return backend


@pytest.mark.asyncio
@pytest.mark.parametrize("info", [False, None, {}])
async def test_authenticate_declines_non_apikey_bearer(info):
    backend = _backend()
    backend.get_token_info = AsyncMock(return_value=info)
    assert await backend.authenticate(MagicMock()) is None


@pytest.mark.asyncio
async def test_authenticate_missing_attributes_still_invalid():
    backend = _backend()
    backend.get_token_info = AsyncMock(return_value={"user_id": 7})
    with pytest.raises(InvalidAuth):
        await backend.authenticate(MagicMock())


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [None, {}])
async def test_check_token_info_empty_payload(payload):
    backend = _backend()
    assert await backend.check_token_info(MagicMock(), payload) is False
