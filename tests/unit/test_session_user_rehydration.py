"""FEAT-102 / TASK-100 — legacy session rehydration (spec §4 round-trip table)."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jsonpickle
import pytest
from aiohttp import web

import navigator_session.data  # noqa: F401 — registers the jsonpickle ModelHandler
from navigator_auth.auth import AuthHandler
from navigator_auth.backends.abstract import BaseAuthBackend
from navigator_auth.backends.basic import BasicUser
from navigator_auth.decorators import allowed_organizations
from navigator_auth.exceptions import InvalidAuth
from navigator_auth.identities import Organization

ORG_DICT = {"org_id": "7", "organization": "Example", "slug": "example"}
BAD_ORG = {"organization": "x"}


def _legacy_payload(orgs: list) -> str:
    """jsonpickle string of a BasicUser whose organizations are raw dicts (pre-FEAT-102 session)."""
    user = BasicUser(id=1, data={"username": "legacy"})
    object.__setattr__(user, "organizations", [dict(o) for o in orgs])
    return jsonpickle.encode(user)


class FakeSession:
    """Fake session backed by a jsonpickle payload."""

    def __init__(self, payload: str):
        self._payload = payload

    def decode(self, key):
        return jsonpickle.decode(self._payload)

    def get(self, key, default=None):
        return default


class FakeRequest:
    """Minimal request: mapping access plus ``method``."""

    def __init__(self):
        self._data = {"authenticated": True}
        self.method = "GET"

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value


def _backend_stub():
    """Minimal `self` for unbound calls: only .logger and ._ident are used."""
    return SimpleNamespace(logger=logging.getLogger("test"), _ident=BasicUser)


def test_jsonpickle_roundtrip_keeps_attribute_access():
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT)])
    restored = jsonpickle.decode(jsonpickle.encode(user))
    assert isinstance(restored.organizations[0], Organization)
    assert restored.organizations[0].org_id == "7"  # AC6


@pytest.mark.asyncio
@pytest.mark.parametrize("getter", [BaseAuthBackend.get_session_user, AuthHandler.get_session_user])
async def test_legacy_dict_session_payload_is_normalized(getter):
    session = FakeSession(_legacy_payload([ORG_DICT]))
    user = await getter(_backend_stub(), session)
    assert user is not None
    assert all(isinstance(o, Organization) for o in user.organizations)
    assert user.organizations[0].org_id == "7"
    assert user.is_authenticated is True


@pytest.mark.asyncio
@pytest.mark.parametrize("getter", [BaseAuthBackend.get_session_user, AuthHandler.get_session_user])
async def test_legacy_malformed_session_payload_is_rejected(getter, caplog):
    session = FakeSession(_legacy_payload([BAD_ORG]))
    with caplog.at_level(logging.WARNING):
        user = await getter(_backend_stub(), session)
    assert user is None
    assert "Unable to decode User session" in caplog.text


@pytest.mark.asyncio
async def test_allowed_organizations_accepts_legacy_dict_session():
    @allowed_organizations(["Example"])
    async def handler(request):
        return web.Response(text="ok")

    with (
        patch(
            "navigator_auth.decorators.get_session",
            new_callable=AsyncMock,
            return_value=FakeSession(_legacy_payload([ORG_DICT])),
        ),
        patch("navigator_auth.decorators._attach_vault_to_request"),
    ):
        resp = await handler(FakeRequest())
    assert resp.text == "ok"

    with (
        patch(
            "navigator_auth.decorators.get_session",
            new_callable=AsyncMock,
            return_value=FakeSession(_legacy_payload([BAD_ORG])),
        ),
        patch("navigator_auth.decorators._attach_vault_to_request"),
    ):
        with pytest.raises(web.HTTPUnauthorized):
            await handler(FakeRequest())


@pytest.mark.asyncio
async def test_create_user_rejects_malformed_organizations():
    with pytest.raises(InvalidAuth) as exc:
        await BaseAuthBackend.create_user(_backend_stub(), {"organizations": [BAD_ORG]})
    assert isinstance(exc.value.__cause__, ValueError)
