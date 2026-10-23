"""ModelHandler response helpers — regression for ledger issues 7164a1f421ce
and 8aa576e356c6.

``navigator.views.BaseHandler.json_response`` takes the payload as its first
positional argument (``response``); it has never accepted ``content=``. Every
call site in ``ModelHandler`` used the keyword, so PUT/POST answered 406 after
the row was already inserted (the ``TypeError`` was swallowed by the insert
except-block) and PATCH/DELETE raised 500.

``no_content()`` returns its response rather than raising it (unlike ``error()``
and ``critical()``), so ``patch()`` fell through both of its not-found branches
and crashed instead of answering 204.
"""

import ast
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from asyncdb.exceptions import NoDataFound
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


class RaisingModel(DemoModel):
    """Model whose ``get()`` reports the miss by raising, as asyncdb does."""

    @classmethod
    async def get(cls, **kwargs):
        raise NoDataFound("demo")


class DemoHandler(ModelHandler):
    model = DemoModel
    name = "Demo"

    async def session(self):
        return {"user_id": 1}

    async def _get_data(self, session=None):
        return {}


class RaisingHandler(DemoHandler):
    model = RaisingModel


class ListPkHandler(DemoHandler):
    """Composite PK, so a request without ``id`` reaches the no-PK branches."""

    pk = ["demo_id"]


def _handler(
    method: str = "GET",
    path: str = "/demo",
    handler_cls: type = DemoHandler,
    **match_info,
) -> ModelHandler:
    app = web.Application()
    app["authdb"] = FakeDB()
    request = make_mocked_request(method, path, match_info=match_info, app=app)
    return handler_cls(request)


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


@pytest.mark.asyncio
async def test_patch_missing_row_is_no_content():
    """Used to fall through and call ``get_fields()`` on None."""
    handler = _handler("PATCH", "/demo/1", id="1")
    response = await handler.patch()
    assert response.status == 204
    assert response.headers["x-error"] == "Demo was not Found"


@pytest.mark.asyncio
async def test_patch_no_data_found_is_no_content():
    """Used to fall through to ``if not result`` with ``result`` unbound."""
    handler = _handler("PATCH", "/demo/1", handler_cls=RaisingHandler, id="1")
    response = await handler.patch()
    assert response.status == 204
    assert response.headers["x-error"] == "Demo was not Found"


@pytest.mark.asyncio
async def test_post_invalid_payload_reports_the_error():
    """``exception=<dict>`` rendered nothing; the client got a bare "406: Not Acceptable"."""
    handler = _handler("POST", "/demo", handler_cls=ListPkHandler)
    with pytest.raises(web.HTTPNotAcceptable) as excinfo:
        await handler.post()
    assert b"Invalid payload for Demo" in (excinfo.value.body or b"")


def test_every_error_call_names_its_payload():
    """``error()`` renders ``reason``/``response``; a dict passed as ``exception`` is dropped."""
    tree = ast.parse(MODEL_HANDLER_SOURCE.read_text())
    unnamed = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "error"
        and not {kw.arg for kw in node.keywords} & {"reason", "response"}
    ]
    assert not unnamed, f"error() without reason=/response= at lines {unnamed}"


def test_no_response_helper_result_is_discarded():
    """``no_content()``/``json_response()``/``response()`` return — they never raise."""
    tree = ast.parse(MODEL_HANDLER_SOURCE.read_text())
    returning = {"no_content", "json_response", "response"}
    discarded = [
        f"{node.value.func.attr}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr in returning
    ]
    assert not discarded, f"response discarded at {discarded}"
