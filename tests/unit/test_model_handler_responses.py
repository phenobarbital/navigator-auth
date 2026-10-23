"""ModelHandler response helpers — regression for ledger issue:7164a1f421ce.

``navigator.views.BaseHandler.json_response`` takes the payload as its first
positional argument (``response``); it has never accepted ``content=``. Every
call site in ``ModelHandler`` used the keyword, so PUT/POST answered 406 after
the row was already inserted (the ``TypeError`` was swallowed by the insert
except-block) and PATCH/DELETE raised 500.
"""

import ast
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator.views import BaseView

from navigator_auth.handlers import model as model_module
from navigator_auth.handlers.model import ModelHandler

MODEL_HANDLER_SOURCE = Path(model_module.__file__)


class FakeConnection:
    """Connection returned by ``FakeDB.acquire()``."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class FakeDB:
    """Minimal stand-in for the ``authdb`` pool."""

    async def acquire(self):
        return FakeConnection()


class DemoModel:
    """Model whose ``get()`` never finds anything."""

    class Meta:
        name = "demo"
        schema = "public"
        connection = None

    @classmethod
    async def get(cls, **kwargs):
        return None


class DemoHandler(ModelHandler):
    model = DemoModel
    name = "Demo"

    async def session(self):
        return {"user_id": 1}

    async def _get_data(self, session=None):
        return {}


def _handler(method: str = "GET", path: str = "/demo", **match_info) -> DemoHandler:
    app = web.Application()
    app["authdb"] = FakeDB()
    request = make_mocked_request(method, path, match_info=match_info, app=app)
    return DemoHandler(request)


def test_json_response_has_no_content_keyword():
    """The premise of the bug: the upstream helper names the payload ``response``."""
    params = inspect.signature(BaseView.json_response).parameters
    assert "content" not in params
    assert "response" in params


def test_no_call_site_passes_content_keyword():
    """Guard every ``json_response()`` in the module, not just the ones under test."""
    tree = ast.parse(MODEL_HANDLER_SOURCE.read_text())
    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "json_response"
        and any(kw.arg == "content" for kw in node.keywords)
    ]
    assert not offenders, f"json_response(content=...) at lines {offenders}"


@pytest.mark.asyncio
async def test_post_get_returns_json_response():
    handler = _handler()
    response = await handler._post_get([{"id": 1}])
    assert response.status == 200


@pytest.mark.asyncio
async def test_post_get_filters_fields_of_a_single_row():
    """The filtered dict used to be built from itself, so every value came back None."""
    handler = _handler()
    row = SimpleNamespace(user_id=42, name="demo", secret="hidden")
    response = await handler._post_get(row, fields=["user_id", "name"])
    assert json.loads(response.body) == {"user_id": 42, "name": "demo"}


@pytest.mark.asyncio
async def test_post_get_filters_fields_of_a_rowset():
    handler = _handler()
    rows = [SimpleNamespace(user_id=1, secret="a"), SimpleNamespace(user_id=2, secret="b")]
    response = await handler._post_get(rows, fields=["user_id"])
    assert json.loads(response.body) == [{"user_id": 1}, {"user_id": 2}]


@pytest.mark.asyncio
async def test_delete_missing_row_is_not_found():
    """204 is not a status ``error()`` knows about, so it used to answer 400."""
    handler = _handler("DELETE", "/demo/1", id="1")
    with pytest.raises(web.HTTPNotFound):
        await handler.delete()
