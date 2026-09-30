"""ABAC middleware ordering relative to the authentication middlewares.

``abac_middleware`` reads ``request["authenticated"]``, which the
authentication middlewares set, so it must sit after them in
``app.middlewares`` (aiohttp: first = outermost). This must hold regardless
of whether ``PDP.setup()`` or ``AuthHandler.setup()`` runs first.
"""
import warnings
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from navigator_auth import AuthHandler
from navigator_auth.abac.middleware import abac_middleware
from navigator_auth.abac.pdp import PDP


def _pdp() -> PDP:
    storage = MagicMock()
    storage.load_policies = AsyncMock(return_value=[])
    storage.close = AsyncMock()
    return PDP(storage=storage)


def _auth() -> AuthHandler:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return AuthHandler(secure_cookies=False, enable_authdb=False)


def _assert_abac_after_auth(app: web.Application, auth: AuthHandler) -> None:
    mdl = list(app.middlewares)
    assert mdl.count(abac_middleware) == 1
    assert mdl.index(abac_middleware) > mdl.index(auth.auth_middleware)


@pytest.mark.parametrize("pdp_first", [True, False], ids=["pdp-first", "auth-first"])
def test_abac_runs_after_authentication(pdp_first: bool):
    app = web.Application()
    auth = _auth()
    if pdp_first:
        _pdp().setup(app)
        auth.setup(app)
    else:
        auth.setup(app)
        _pdp().setup(app)

    _assert_abac_after_auth(app, auth)
    app.freeze()


def test_auth_without_pdp_registers_no_abac():
    app = web.Application()
    _auth().setup(app)

    assert abac_middleware not in app.middlewares
