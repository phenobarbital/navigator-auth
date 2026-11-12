"""IP rate limiters key on the real client IP, not the proxy peer."""

import importlib
from ipaddress import ip_address
from types import SimpleNamespace

import pytest

from navigator_auth.authorizations._client_ip import limiter_client_ip

PROXY = "10.0.0.1"
CLIENT = "203.0.113.7"


def _req(remote, headers=None):
    return SimpleNamespace(remote=remote, headers=headers or {})


def test_trusted_proxy_resolves_forwarded_client():
    req = _req(PROXY, {"X-Forwarded-For": f"198.51.100.9, {CLIENT}"})
    assert limiter_client_ip(req, {ip_address(PROXY)}) == CLIENT


def test_untrusted_peer_cannot_spoof():
    req = _req(CLIENT, {"X-Forwarded-For": "192.0.2.50"})
    assert limiter_client_ip(req, {ip_address(PROXY)}) == CLIENT


def test_untrusted_peer_cannot_spoof_cf_header():
    req = _req(CLIENT, {"CF-Connecting-IP": "192.0.2.50"})
    assert limiter_client_ip(req, {ip_address(PROXY)}) == CLIENT


def test_no_proxies_is_raw_remote():
    assert limiter_client_ip(_req(PROXY, {"X-Forwarded-For": CLIENT})) == PROXY


@pytest.mark.parametrize("request_", [SimpleNamespace(), _req(None), _req("")])
def test_missing_remote_is_unknown(request_):
    assert limiter_client_ip(request_) == "unknown"


def test_non_ip_remote_is_kept():
    assert limiter_client_ip(_req("unix-socket")) == "unix-socket"


@pytest.mark.parametrize("module_path", ["navigator_auth.mfa.login", "navigator_auth.handlers.mfa"])
def test_mfa_remote_honours_trusted_proxies(module_path, monkeypatch):
    module = importlib.import_module(module_path)
    monkeypatch.setattr(module, "_TRUSTED_PROXIES", {ip_address(PROXY)})
    assert module._remote(_req(PROXY, {"X-Forwarded-For": CLIENT})) == CLIENT
    monkeypatch.setattr(module, "_TRUSTED_PROXIES", set())
    assert module._remote(_req(PROXY, {"X-Forwarded-For": CLIENT})) == PROXY


class _RecordingLimiter:
    def __init__(self):
        self.keys = []

    async def check(self, key):
        self.keys.append(key)
        return True


async def _run_step1(handler_mod, proxies, monkeypatch):
    cls = handler_mod.PasswordRecoveryHandler
    handler = object.__new__(cls)
    ip_limiter = _RecordingLimiter()
    processed = []

    async def _json_data():
        return {"email": "User@Example.com"}

    async def _process(email):
        processed.append(email)

    async def _pad(start):
        return None

    monkeypatch.setattr(handler_mod, "_TRUSTED_PROXIES", proxies)
    monkeypatch.setattr(cls, "request", _req(PROXY, {"X-Forwarded-For": CLIENT}), raising=False)
    monkeypatch.setattr(cls, "json_data", lambda self: _json_data(), raising=False)
    monkeypatch.setattr(cls, "json_response", lambda self, **kw: kw, raising=False)
    monkeypatch.setattr(cls, "_process_recovery_request", lambda self, e: _process(e), raising=False)
    monkeypatch.setattr(cls, "_pad_latency", lambda self, s: _pad(s), raising=False)
    monkeypatch.setattr(cls, "_ip_limiter", ip_limiter, raising=False)
    monkeypatch.setattr(cls, "_email_limiter", _RecordingLimiter(), raising=False)
    await handler._step1_request()
    assert processed == ["user@example.com"]
    return ip_limiter.keys


@pytest.mark.asyncio
async def test_recovery_step1_keys_ip_limiter_on_client(monkeypatch):
    mod = importlib.import_module("navigator_auth.handlers.recovery.handler")
    assert await _run_step1(mod, {ip_address(PROXY)}, monkeypatch) == [CLIENT]


@pytest.mark.asyncio
async def test_recovery_step1_default_keys_on_remote(monkeypatch):
    mod = importlib.import_module("navigator_auth.handlers.recovery.handler")
    assert await _run_step1(mod, set(), monkeypatch) == [PROXY]
