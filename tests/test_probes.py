"""Security warning for hosts that repeatedly probe the server unauthenticated.

``ProbeTracker`` counts rejected (4xx) unauthenticated requests per client IP
and logs one warning on the ``navigator_auth.security`` logger when a host
crosses the threshold inside the window; ``protected_paths_middleware`` (the
outermost middleware) feeds it, with or without ABAC.
"""
import ipaddress
import logging

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.middlewares.protected_paths import protected_paths_middleware
from navigator_auth.middlewares import probes as probes_mod
from navigator_auth.middlewares.probes import SECURITY_LOGGER, ProbeTracker

ATTACKER = "203.0.113.7"
PROXY = "10.0.0.1"


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _tracker(
    clock: FakeClock,
    threshold: int = 3,
    window: float = 60,
    cooldown: float = 300,
    max_hosts: int = 100,
) -> ProbeTracker:
    return ProbeTracker(
        threshold=threshold, window=window, cooldown=cooldown, max_hosts=max_hosts, clock=clock
    )


def _security_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == SECURITY_LOGGER]


# --- ProbeTracker -----------------------------------------------------------


def test_below_threshold_does_not_warn(caplog):
    tracker = _tracker(FakeClock())
    assert tracker.record(ATTACKER, "/.env", 404) is False
    assert tracker.record(ATTACKER, "/.env.local", 404) is False
    assert _security_records(caplog) == []


def test_threshold_within_window_warns_once(caplog):
    clock = FakeClock()
    tracker = _tracker(clock)
    results = []
    for path in ("/.env", "/owa/auth/logon.aspx", "/api/v1/pods"):
        results.append(tracker.record(ATTACKER, path, 404))
        clock.now += 1
    assert results == [False, False, True]
    records = _security_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    message = records[0].getMessage()
    assert ATTACKER in message
    assert "/owa/auth/logon.aspx" in message


def test_hits_spread_beyond_window_do_not_warn(caplog):
    clock = FakeClock()
    tracker = _tracker(clock, window=10)
    for _ in range(6):
        assert tracker.record(ATTACKER, "/.env", 404) is False
        clock.now += 6
    assert _security_records(caplog) == []


def test_cooldown_suppresses_repeat_warnings(caplog):
    clock = FakeClock()
    tracker = _tracker(clock, cooldown=300)
    for _ in range(3):
        tracker.record(ATTACKER, "/.env", 404)
    # Burst keeps going inside the cooldown: no new warning.
    for _ in range(10):
        clock.now += 1
        assert tracker.record(ATTACKER, "/.env", 404) is False
    assert len(_security_records(caplog)) == 1
    # Once the cooldown is over, a new burst from the same host is reported.
    clock.now += 300
    assert [tracker.record(ATTACKER, "/.env", 404) for _ in range(3)] == [False, False, True]
    assert len(_security_records(caplog)) == 2


def test_hosts_are_counted_separately(caplog):
    tracker = _tracker(FakeClock())
    for host in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
        assert tracker.record(host, "/.env", 404) is False
    assert _security_records(caplog) == []


def test_max_hosts_drops_least_recently_seen(caplog):
    tracker = _tracker(FakeClock(), max_hosts=2)
    tracker.record("198.51.100.1", "/.env", 404)
    tracker.record("198.51.100.1", "/.env", 404)
    tracker.record("198.51.100.2", "/.env", 404)
    tracker.record("198.51.100.3", "/.env", 404)  # evicts .1
    # .1 starts from zero again, so one more hit is not enough.
    assert tracker.record("198.51.100.1", "/.env", 404) is False
    assert _security_records(caplog) == []


def test_zero_threshold_disables_tracking(caplog):
    tracker = _tracker(FakeClock(), threshold=0)
    assert tracker.enabled is False
    for _ in range(50):
        assert tracker.record(ATTACKER, "/.env", 404) is False
    assert _security_records(caplog) == []


def test_logged_paths_are_escaped_and_truncated(caplog):
    tracker = _tracker(FakeClock(), threshold=1)
    tracker.record(ATTACKER, "/x\nFAKE LOG LINE" + "a" * 500, 404)
    message = _security_records(caplog)[0].getMessage()
    assert "\n" not in message
    assert "a" * 201 not in message


# --- integration through protected_paths_middleware --------------------------


@pytest.fixture
def probes(monkeypatch) -> ProbeTracker:
    tracker = ProbeTracker(threshold=3, window=60, cooldown=300, max_hosts=100)
    monkeypatch.setattr(probes_mod, "probe_tracker", tracker)
    monkeypatch.setattr(probes_mod, "trusted_proxies", set())
    return tracker


def _request(path: str, *, remote: str = ATTACKER, headers=None):
    request = make_mocked_request("GET", path, headers=headers, app=web.Application())
    return request.clone(remote=remote)


async def _not_found(request: web.Request) -> web.StreamResponse:
    raise web.HTTPNotFound()


async def _auth_rejects(request: web.Request) -> web.StreamResponse:
    """What the authentication middleware does with a bad or missing token."""
    raise web.HTTPUnauthorized()


async def _unauthorized_response(request: web.Request) -> web.StreamResponse:
    return web.Response(status=401)


async def _ok(request: web.Request) -> web.StreamResponse:
    return web.Response(text="ok")


async def _authenticated_not_found(request: web.Request) -> web.StreamResponse:
    request["authenticated"] = True  # set by the inner auth middleware
    raise web.HTTPNotFound()


async def _call(request, handler):
    return await protected_paths_middleware(request, handler)


@pytest.mark.asyncio
async def test_repeated_rejections_raise_one_warning(probes, caplog):
    for path in ("/owa/auth/errorFE.aspx", "/RDWeb", "/api/v1/pods"):
        with pytest.raises(web.HTTPNotFound):
            await _call(_request(path), _not_found)
    records = _security_records(caplog)
    assert len(records) == 1
    assert ATTACKER in records[0].getMessage()


@pytest.mark.asyncio
async def test_failed_authentication_is_counted(probes, caplog):
    for _ in range(3):
        with pytest.raises(web.HTTPUnauthorized):
            await _call(_request("/api/v1/users"), _auth_rejects)
    assert len(_security_records(caplog)) == 1


@pytest.mark.asyncio
async def test_returned_4xx_responses_are_counted(probes, caplog):
    for _ in range(3):
        response = await _call(_request("/version"), _unauthorized_response)
        assert response.status == 401
    assert len(_security_records(caplog)) == 1


@pytest.mark.asyncio
async def test_blocked_system_paths_are_counted(probes, caplog):
    for path in ("/.env", "/.env.local", "/etc/config.ini"):
        with pytest.raises(web.HTTPNotFound):
            await _call(_request(path), _ok)
    warnings_ = [r for r in _security_records(caplog) if r.levelno == logging.WARNING]
    assert len(warnings_) == 1


@pytest.mark.asyncio
async def test_successful_responses_are_ignored(probes, caplog):
    for _ in range(10):
        response = await _call(_request("/static/app.js"), _ok)
        assert response.status == 200
    assert _security_records(caplog) == []


@pytest.mark.asyncio
async def test_authenticated_requests_are_ignored(probes, caplog):
    for _ in range(10):
        with pytest.raises(web.HTTPNotFound):
            await _call(_request("/missing"), _authenticated_not_found)
    assert _security_records(caplog) == []


@pytest.mark.asyncio
async def test_spoofed_forwarded_for_is_ignored(probes, caplog):
    # Peer is not a trusted proxy: rotating X-Forwarded-For must not split
    # the attacker into many "hosts".
    for i in range(3):
        headers = {"X-Forwarded-For": f"198.51.100.{i}"}
        with pytest.raises(web.HTTPNotFound):
            await _call(_request("/missing", headers=headers), _not_found)
    records = _security_records(caplog)
    assert len(records) == 1
    assert ATTACKER in records[0].getMessage()


@pytest.mark.asyncio
async def test_client_ip_behind_trusted_proxy(probes, monkeypatch, caplog):
    monkeypatch.setattr(probes_mod, "trusted_proxies", {ipaddress.ip_address(PROXY)})
    for _ in range(3):
        headers = {"X-Forwarded-For": ATTACKER}
        with pytest.raises(web.HTTPNotFound):
            await _call(_request("/missing", remote=PROXY, headers=headers), _not_found)
    message = _security_records(caplog)[0].getMessage()
    assert ATTACKER in message
    assert PROXY not in message


@pytest.mark.asyncio
async def test_only_trusted_hops_falls_back_to_peer(probes, monkeypatch, caplog):
    monkeypatch.setattr(probes_mod, "trusted_proxies", {ipaddress.ip_address(PROXY)})
    for _ in range(3):
        headers = {"X-Forwarded-For": PROXY}
        with pytest.raises(web.HTTPNotFound):
            await _call(_request("/missing", remote=PROXY, headers=headers), _not_found)
    assert len(_security_records(caplog)) == 1
