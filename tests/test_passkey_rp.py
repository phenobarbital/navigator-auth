"""FEAT-101 TASK-89 — RelyingPartyResolver."""
import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import ConfigError, InvalidAuth
from navigator_auth.passkey.rp import RelyingPartyResolver

PARTIES = [
    {"origin": "https://a.test", "rp_id": "a.test", "rp_name": "A", "org_id": 5, "client_id": 1},
    {"origin": "https://b.test", "rp_id": "b.test", "rp_name": "B", "org_id": 7, "client_id": 2},
]


def _req(**headers):
    return make_mocked_request("POST", "/", headers=headers)


def test_rp_resolver_exact_origin():
    """Known Origin → its RP; unknown/missing/null → 401; Host and X-Forwarded-Host ignored."""
    r = RelyingPartyResolver(PARTIES)
    assert r.resolve(_req(Origin="https://a.test")).org_id == 5
    assert r.resolve(_req(Origin="https://B.TEST")).org_id == 7
    assert r.resolve(_req(Origin="https://a.test/")).rp_id == "a.test"
    for bad in (
        "https://a.test.evil.com", "https://evil.a.test", "http://a.test",
        "https://a.test:8443", "null", "https://a.test/../", "https://u@a.test", "",
    ):
        with pytest.raises(InvalidAuth):
            r.resolve(_req(Origin=bad))
    # Host / X-Forwarded-Host are never consulted
    with pytest.raises(InvalidAuth):
        r.resolve(_req(Host="a.test"))
    with pytest.raises(InvalidAuth):
        r.resolve(_req(**{"X-Forwarded-Host": "a.test", "Origin": "https://evil.test"}))
    # Referer fallback only when Origin is absent, exact match on its origin
    assert r.resolve(_req(Referer="https://a.test/login?x=1")).rp_id == "a.test"
    with pytest.raises(InvalidAuth):
        r.resolve(_req(Referer="https://a.test.evil.com/login"))
    with pytest.raises(InvalidAuth):
        r.resolve(_req(Origin="null", Referer="https://a.test/login"))


def test_rp_resolver_empty_config():
    with pytest.raises(ConfigError):
        RelyingPartyResolver([])


def test_rp_resolver_invalid_entries():
    with pytest.raises(ConfigError, match=r"\[1\]"):
        RelyingPartyResolver([PARTIES[0], {"origin": "https://c.test"}])
    with pytest.raises(ConfigError):
        RelyingPartyResolver([{"origin": "https://c.test/path", "rp_id": "c.test"}])
    with pytest.raises(ConfigError, match="duplicate"):
        RelyingPartyResolver([PARTIES[0], {**PARTIES[0], "origin": "HTTPS://A.test/"}])


def test_rp_resolver_by_rp_id():
    r = RelyingPartyResolver(PARTIES)
    assert r.by_rp_id("b.test").org_id == 7
    assert r.by_rp_id("zzz") is None
