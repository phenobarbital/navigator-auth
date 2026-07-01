"""Tests for User-Agent authorization and the optional geo-fence.

The GeoIP database lookup is mocked, so these tests do not require the
``geoip2`` package or a ``.mmdb`` file.
"""
import ipaddress
import pytest
from navigator_auth.authorizations import useragent as ua_mod
from navigator_auth.authorizations.useragent import authz_useragent
from navigator_auth.authorizations._client_ip import get_client_ip, parse_proxies

POWERBI_UA = "Microsoft.Data.Mashup (https://go.microsoft.com/fwlink/?LinkID=304225)"


class FakeRequest:
    """Minimal stand-in for aiohttp.web.Request."""

    def __init__(self, headers=None, remote="127.0.0.1"):
        self.headers = headers or {}
        self.remote = remote


# --------------------------------------------------------------------------- #
# get_client_ip / parse_proxies
# --------------------------------------------------------------------------- #
def test_parse_proxies_skips_invalid():
    proxies = parse_proxies(["127.0.0.1", "not-an-ip", "10.0.0.1"])
    assert ipaddress.ip_address("127.0.0.1") in proxies
    assert ipaddress.ip_address("10.0.0.1") in proxies
    assert len(proxies) == 2


def test_get_client_ip_uses_xff_behind_trusted_proxy():
    # ngrok/PBI topology: the trusted edge appends the observed client IP as
    # the right-most entry. That right-most value is the genuine client.
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={"X-Forwarded-For": "20.41.5.87"},
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "20.41.5.87"


def test_get_client_ip_skips_trusted_proxies_in_chain():
    # Classic multi-hop: real client, then internal proxy appended to the
    # right. With the internal proxy trusted, the client is resolved.
    proxies = parse_proxies(["127.0.0.1", "10.0.0.5"])
    req = FakeRequest(
        headers={"X-Forwarded-For": "181.95.151.21, 10.0.0.5"},
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "181.95.151.21"


def test_get_client_ip_rejects_spoofed_leftmost_value():
    # An attacker prepends a whitelisted IP; the trusted edge still appends
    # the real (attacker) IP on the right. Right-most-wins defeats the spoof.
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={"X-Forwarded-For": "20.41.5.87, 203.0.113.9"},
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "203.0.113.9"


def test_get_client_ip_all_hops_trusted_returns_none():
    # Nothing but trusted proxies in the chain: no client to authorize on.
    proxies = parse_proxies(["127.0.0.1", "10.0.0.5"])
    req = FakeRequest(
        headers={"X-Forwarded-For": "10.0.0.5"},
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) is None


def test_get_client_ip_ignores_xff_from_untrusted_peer():
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={"X-Forwarded-For": "1.2.3.4"},
        remote="8.8.8.8",  # not a trusted proxy
    )
    assert get_client_ip(req, proxies) == "8.8.8.8"


def test_get_client_ip_no_remote():
    assert get_client_ip(FakeRequest(remote=None), set()) is None


def test_get_client_ip_cf_connecting_ip_behind_trusted_proxy():
    # cloudflared tunnel topology: peer is loopback, no X-Forwarded-For,
    # Cloudflare's edge header carries the real client.
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={"CF-Connecting-IP": "203.0.113.9"},
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "203.0.113.9"


def test_get_client_ip_prefers_xff_over_cf():
    # When both headers are present, the right-to-left XFF walk wins.
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={
            "X-Forwarded-For": "198.51.100.7",
            "CF-Connecting-IP": "203.0.113.9",
        },
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "198.51.100.7"


def test_get_client_ip_cf_fallback_when_xff_all_trusted():
    # XFF exhausted (only trusted proxies): CF-Connecting-IP still resolves.
    proxies = parse_proxies(["127.0.0.1", "10.0.0.5"])
    req = FakeRequest(
        headers={
            "X-Forwarded-For": "10.0.0.5",
            "CF-Connecting-IP": "203.0.113.9",
        },
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "203.0.113.9"


def test_get_client_ip_ignores_cf_from_untrusted_peer():
    # A direct client sending CF-Connecting-IP must not spoof the whitelist.
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={"CF-Connecting-IP": "20.41.5.87"},
        remote="8.8.8.8",
    )
    assert get_client_ip(req, proxies) == "8.8.8.8"


def test_get_client_ip_malformed_cf_falls_back_to_remote():
    proxies = parse_proxies(["127.0.0.1"])
    req = FakeRequest(
        headers={"CF-Connecting-IP": "not-an-ip"},
        remote="127.0.0.1",
    )
    assert get_client_ip(req, proxies) == "127.0.0.1"


# --------------------------------------------------------------------------- #
# authz_useragent — security OFF (legacy behaviour)
# --------------------------------------------------------------------------- #
@pytest.fixture
def patch_ua(monkeypatch):
    """Helper to set module-level config for the useragent backend."""
    def _apply(*, allowed_ua, security, countries=("US", "CA"), proxies=("127.0.0.1",)):
        monkeypatch.setattr(ua_mod, "ALLOWED_UA", list(allowed_ua))
        monkeypatch.setattr(ua_mod, "USERAGENT_SECURITY", security)
        monkeypatch.setattr(ua_mod, "USERAGENT_ALLOWED_COUNTRIES", list(countries))
        monkeypatch.setattr(ua_mod, "ALLOWED_IP_TRUSTED_PROXIES", list(proxies))
    return _apply


@pytest.mark.asyncio
async def test_ua_no_match_denies(patch_ua):
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=False)
    handler = authz_useragent()
    req = FakeRequest(headers={"User-Agent": "curl/8.0"})
    assert await handler.check_authorization(req) is False


@pytest.mark.asyncio
async def test_ua_match_security_off_allows(patch_ua):
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=False)
    handler = authz_useragent()
    req = FakeRequest(headers={"User-Agent": POWERBI_UA})
    assert await handler.check_authorization(req) is True


# --------------------------------------------------------------------------- #
# authz_useragent — security ON (geo-fence)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_geofence_allows_us(patch_ua, monkeypatch):
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=True)
    monkeypatch.setattr(ua_mod, "lookup_country", lambda ip: "US")
    handler = authz_useragent()
    req = FakeRequest(
        headers={"User-Agent": POWERBI_UA, "X-Forwarded-For": "23.45.67.89"},
        remote="127.0.0.1",
    )
    assert await handler.check_authorization(req) is True


@pytest.mark.asyncio
async def test_geofence_allows_canada(patch_ua, monkeypatch):
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=True)
    monkeypatch.setattr(ua_mod, "lookup_country", lambda ip: "CA")
    handler = authz_useragent()
    req = FakeRequest(
        headers={"User-Agent": POWERBI_UA, "X-Forwarded-For": "99.224.1.1"},
        remote="127.0.0.1",
    )
    assert await handler.check_authorization(req) is True


@pytest.mark.asyncio
async def test_geofence_blocks_foreign_country(patch_ua, monkeypatch):
    # 181.95.151.21 (the ngrok log example) geolocates to Paraguay -> blocked.
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=True)
    monkeypatch.setattr(ua_mod, "lookup_country", lambda ip: "PY")
    handler = authz_useragent()
    req = FakeRequest(
        headers={"User-Agent": POWERBI_UA, "X-Forwarded-For": "181.95.151.21"},
        remote="127.0.0.1",
    )
    assert await handler.check_authorization(req) is False


@pytest.mark.asyncio
async def test_geofence_fails_closed_on_unknown(patch_ua, monkeypatch):
    # No GeoIP DB / unknown IP -> lookup returns None -> deny.
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=True)
    monkeypatch.setattr(ua_mod, "lookup_country", lambda ip: None)
    handler = authz_useragent()
    req = FakeRequest(
        headers={"User-Agent": POWERBI_UA, "X-Forwarded-For": "23.45.67.89"},
        remote="127.0.0.1",
    )
    assert await handler.check_authorization(req) is False


@pytest.mark.asyncio
async def test_geofence_requires_ua_first(patch_ua, monkeypatch):
    # Non-matching UA is denied before any geo lookup happens.
    patch_ua(allowed_ua=["Microsoft.Data.Mashup"], security=True)
    calls = []

    def _spy(ip):
        calls.append(ip)
        return "US"

    monkeypatch.setattr(ua_mod, "lookup_country", _spy)
    handler = authz_useragent()
    req = FakeRequest(headers={"User-Agent": "curl/8.0"}, remote="127.0.0.1")
    assert await handler.check_authorization(req) is False
    assert calls == []  # geo lookup never invoked
