"""Hard deny for system paths, independent of authentication and ABAC/PBAC.

``protected_paths_middleware`` must answer 404 to hidden files, the env/,
etc/ and logs/ directories and secret/config/log files whatever sits behind
it: a permissive exclude list, an "allow everything" authorization step or no
ABAC at all.
"""
import logging
import warnings
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

from navigator_auth import AuthHandler
from navigator_auth.abac.middleware import abac_middleware
from navigator_auth.abac.pdp import PDP
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.middlewares import probes as probes_mod
from navigator_auth.middlewares import protected_paths as pp
from navigator_auth.middlewares.probes import SECURITY_LOGGER, ProbeTracker
from navigator_auth.middlewares.protected_paths import (
    install_protected_paths,
    protected_path_reason,
    protected_paths_middleware,
)

# --- protected_path_reason ---------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/.ENV",
        "/.env.local",
        "/api/.env",
        "/static/.env",
        "/env/.env",
        "/.git/config",
        "/.aws/credentials",
        "/.well-known/.secret",
        "/static/../.env",
        "/etc",
        "/etc/config.ini",
        "/ETC/passwd",
        "/env/production/vars",
        "/logs",
        "/logs/app.log",
        "/settings/settings.py",
        "/static/app.pyc",
        "/backup.sql",
        "/dump.sql.gz",
        "/error.log.1",
        "/certs/server.pem",
        "/private.key",
        "/pyproject.toml",
        "/db.sqlite3",
        "/config.ini.bak",
        "/config.ini.tar",
        "/docker-compose.yml",
        "/agents/config.yaml",
    ],
)
def test_protected_paths_are_detected(path: str):
    assert protected_path_reason(path) is not None


@pytest.mark.parametrize(
    "file_path",
    ["etc/passwd", "env/production/vars", "logs/today", "keys/credentials", "home/id_rsa", "etc"],
)
def test_served_file_paths_are_checked(file_path: str):
    """``/files/etc/passwd``: the directory sits under a prefix or sub-app."""
    assert protected_path_reason(f"/files/{file_path}", file_paths=[file_path]) is not None


def test_secret_file_names_only_apply_to_served_files():
    # A REST resource named like a secret file is not a file.
    assert protected_path_reason("/api/v1/users/credentials") is None
    assert protected_path_reason("/files/credentials", file_paths=["credentials"]) is not None


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/v1/users",
        "/api/v1/logs",
        "/api/v1/env",
        "/api/v1/etc/1",
        "/environment",
        "/etcetera",
        "/logs-viewer",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/static/app.js",
        "/static/report.zip",
        "/static/v1.2.3/app.css",
        "/api/v1/users/john.doe@example.com",
    ],
)
def test_regular_paths_are_not_protected(path: str):
    assert protected_path_reason(path) is None


def test_extra_patterns_add_to_builtin_rules():
    assert protected_path_reason("/private/report", ["/private/*"]) is not None
    assert protected_path_reason("/PRIVATE/report", ["/private/*"]) is not None
    assert protected_path_reason("/public/report", ["/private/*"]) is None


# --- middleware at runtime ----------------------------------------------------


@pytest.fixture
def site(tmp_path: Path) -> Path:
    """A static root that (wrongly) contains secrets, as in a bad deploy."""
    (tmp_path / ".env").write_text("SECRET=1\n")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config.ini").write_text("[db]\npassword=x\n")
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "app.log").write_text("log\n")
    (tmp_path / "index.html").write_text("<h1>ok</h1>")
    return tmp_path


@web.middleware
async def allow_everything(request, handler):
    """Stand-in for a misconfigured authz/ABAC step that authorizes anything."""
    request["authenticated"] = True
    request["authz_allowed"] = True
    return await handler(request)


def _app(site: Path, guarded: bool) -> web.Application:
    app = web.Application(middlewares=[allow_everything])
    app[AUTH_EXCLUDE_LIST_KEY] = ["/*"]  # wildcard exclude list
    app.router.add_static("/", site)
    if guarded:
        install_protected_paths(app)
    return app


@pytest.fixture
def probes(monkeypatch) -> ProbeTracker:
    tracker = ProbeTracker(threshold=3, window=60, cooldown=300, max_hosts=100)
    monkeypatch.setattr(probes_mod, "probe_tracker", tracker)
    monkeypatch.setattr(probes_mod, "trusted_proxies", set())
    return tracker


@pytest.mark.asyncio
async def test_without_guard_the_static_route_leaks_secrets(site):
    """Sanity check: the leak the guard exists for is real."""
    async with TestClient(TestServer(_app(site, guarded=False))) as client:
        response = await client.get("/.env")
        assert response.status == 200
        assert "SECRET" in await response.text()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/.env", "/etc/config.ini", "/logs/app.log"])
async def test_guard_blocks_even_when_everything_else_allows(site, probes, path):
    async with TestClient(TestServer(_app(site, guarded=True))) as client:
        response = await client.get(path)
        assert response.status == 404
        assert "SECRET" not in await response.text()


@pytest.mark.asyncio
async def test_guard_blocks_percent_encoded_paths(site, probes):
    async with TestClient(TestServer(_app(site, guarded=True))) as client:
        response = await client.get(URL("/%2eenv", encoded=True))
        assert response.status == 404
        assert "SECRET" not in await response.text()


@pytest.mark.asyncio
async def test_guard_lets_regular_files_through(site, probes):
    async with TestClient(TestServer(_app(site, guarded=True))) as client:
        response = await client.get("/index.html")
        assert response.status == 200


@pytest.mark.asyncio
async def test_guard_logs_and_feeds_the_probe_tracker(site, probes, caplog):
    caplog.set_level(logging.INFO, logger=SECURITY_LOGGER)
    async with TestClient(TestServer(_app(site, guarded=True))) as client:
        for path in ("/.env", "/.git/config", "/etc/config.ini"):
            assert (await client.get(path)).status == 404
    messages = [r.getMessage() for r in caplog.records if r.name == SECURITY_LOGGER]
    assert any("blocked GET '/.env'" in m for m in messages)
    warnings_ = [r for r in caplog.records if r.name == SECURITY_LOGGER and r.levelno == logging.WARNING]
    assert len(warnings_) == 1
    assert "possible scan or attack" in warnings_[0].getMessage()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/files/etc/config.ini", "/files/etc/passwd", "/service/etc/passwd", "/service/logs/app.log"])
async def test_guard_covers_prefixed_static_and_subapps(site, probes, path):
    (site / "etc" / "passwd").write_text("root:x\n")
    child = web.Application()
    child.router.add_static("/", site)
    app = web.Application(middlewares=[allow_everything])
    app.router.add_static("/files", site)
    app.add_subapp("/service", child)
    install_protected_paths(app)
    async with TestClient(TestServer(app)) as client:
        response = await client.get(path)
        assert response.status == 404
        assert (await client.get("/files/index.html")).status == 200
        assert (await client.get("/service/index.html")).status == 200


@pytest.mark.asyncio
async def test_rest_routes_named_like_files_keep_working(probes):
    async def credentials(request):
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/api/v1/users/credentials", credentials)
    app.router.add_get("/api/v1/users/credentials/{cid}", credentials)
    install_protected_paths(app)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get("/api/v1/users/credentials")).status == 200
        assert (await client.get("/api/v1/users/credentials/abc")).status == 200


@pytest.mark.asyncio
async def test_guard_honours_auth_deny_paths(site, probes, monkeypatch):
    monkeypatch.setattr(pp.conf, "AUTH_DENY_PATHS", ["/index.*"])
    async with TestClient(TestServer(_app(site, guarded=True))) as client:
        assert (await client.get("/index.html")).status == 404


# --- registration -------------------------------------------------------------


def _pdp() -> PDP:
    storage = MagicMock()
    storage.load_policies = AsyncMock(return_value=[])
    storage.close = AsyncMock()
    return PDP(storage=storage)


def _auth() -> AuthHandler:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return AuthHandler(secure_cookies=False, enable_authdb=False)


def test_install_is_idempotent_and_outermost():
    app = web.Application(middlewares=[allow_everything])
    install_protected_paths(app)
    install_protected_paths(app)
    assert list(app.middlewares).count(protected_paths_middleware) == 1
    assert app.middlewares[0] is protected_paths_middleware


def test_auth_handler_installs_the_guard_first():
    app = web.Application()
    auth = _auth()
    auth.setup(app)
    mdl = list(app.middlewares)
    assert mdl[0] is protected_paths_middleware
    assert mdl.index(protected_paths_middleware) < mdl.index(auth.auth_middleware)
    app.freeze()


def test_pdp_alone_installs_the_guard():
    """ABAC without AuthHandler still gets the guard."""
    app = web.Application()
    _pdp().setup(app)
    assert app.middlewares[0] is protected_paths_middleware


@pytest.mark.parametrize("pdp_first", [True, False], ids=["pdp-first", "auth-first"])
def test_guard_stays_first_with_both_setups(pdp_first: bool):
    app = web.Application()
    auth = _auth()
    if pdp_first:
        _pdp().setup(app)
        auth.setup(app)
    else:
        auth.setup(app)
        _pdp().setup(app)
    mdl = list(app.middlewares)
    assert mdl.count(protected_paths_middleware) == 1
    assert mdl[0] is protected_paths_middleware
    assert mdl.index(abac_middleware) > mdl.index(auth.auth_middleware)
    app.freeze()
