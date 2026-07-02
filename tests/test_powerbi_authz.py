"""Tests for the PowerBI IP authorization backend (``authz_powerbi``).

The backend is a *sibling* of ``authz_allowed_ips`` — both share the
:class:`SubnetAuthzHandler` CIDR-matching engine but keep independent network
sets. ``authz_powerbi`` seeds only from ``POWERBI_ALLOWED_IPS`` and is
populated at startup from the Azure Service-Tag download (mocked here so no
network access is required); ``authz_allowed_ips`` seeds only from the
operator-managed ``ALLOWED_IPS`` list. Neither leaks into the other.
"""
import pytest
from navigator_auth.authorizations import powerbi as pbi_mod
from navigator_auth.authorizations import _subnet as subnet_mod
from navigator_auth.authorizations import azure_service_tags as ast_mod
from navigator_auth.authorizations import SubnetAuthzHandler
from navigator_auth.authorizations.powerbi import authz_powerbi
from navigator_auth.authorizations.allowed_ips import authz_allowed_ips


@pytest.fixture(autouse=True)
def _trust_localhost_proxy(monkeypatch):
    """Trust 127.0.0.1 as a proxy (the ngrok/reverse-proxy topology) so the
    X-Forwarded-For client IP is honored in these tests."""
    monkeypatch.setattr(subnet_mod, "ALLOWED_IP_TRUSTED_PROXIES", ["127.0.0.1"])


class FakeRequest:
    """Minimal stand-in for aiohttp.web.Request."""

    def __init__(self, headers=None, remote="127.0.0.1"):
        self.headers = headers or {}
        self.remote = remote


def _pbi_request(client_ip: str) -> FakeRequest:
    """A request arriving through a trusted proxy (127.0.0.1) with XFF."""
    return FakeRequest(
        headers={"X-Forwarded-For": client_ip},
        remote="127.0.0.1",
    )


def test_shares_engine_but_not_allowed_ips_lineage():
    # Both backends reuse the CIDR engine, but powerbi is NOT an authz_allowed_ips
    # so operator-managed IPs (added via AllowedIPHandler) never target it.
    assert issubclass(authz_powerbi, SubnetAuthzHandler)
    assert issubclass(authz_allowed_ips, SubnetAuthzHandler)
    assert not issubclass(authz_powerbi, authz_allowed_ips)
    assert not isinstance(authz_powerbi(), authz_allowed_ips)


def test_network_sets_are_independent(monkeypatch):
    # A user IP added to authz_allowed_ips must not appear in authz_powerbi.
    monkeypatch.setattr(pbi_mod, "POWERBI_ALLOWED_IPS", ["20.41.5.0/25"])
    user_backend = authz_allowed_ips(allowed=[])  # no global seed for this test
    pbi_backend = authz_powerbi()
    user_backend.add_networks(["10.9.9.0/24"])  # e.g. AWS keepalive subnet
    assert any(str(n) == "10.9.9.0/24" for n in user_backend._networks)
    assert not any(str(n) == "10.9.9.0/24" for n in pbi_backend._networks)
    assert not any(str(n) == "20.41.5.0/25" for n in user_backend._networks)


def test_seeds_from_powerbi_allowed_ips_not_global(monkeypatch):
    # authz_powerbi seeds ONLY from POWERBI_ALLOWED_IPS, never ALLOWED_IPS.
    monkeypatch.setattr(pbi_mod, "POWERBI_ALLOWED_IPS", ["20.41.5.0/25"])
    backend = authz_powerbi()
    assert len(backend._networks) == 1
    assert str(backend._networks[0]) == "20.41.5.0/25"


@pytest.mark.asyncio
async def test_authorizes_seeded_powerbi_subnet(monkeypatch):
    monkeypatch.setattr(pbi_mod, "POWERBI_ALLOWED_IPS", ["20.41.5.0/25"])
    backend = authz_powerbi()
    # The real client (right-most XFF behind the trusted proxy) is in range.
    assert await backend.check_authorization(_pbi_request("20.41.5.87")) is True
    # An address outside the PBI subnet is denied.
    assert await backend.check_authorization(_pbi_request("8.8.8.8")) is False


@pytest.mark.asyncio
async def test_load_service_tags_injects_prefixes(monkeypatch):
    monkeypatch.setattr(pbi_mod, "POWERBI_ALLOWED_IPS", [])

    async def fake_fetch(tags, timeout=60):
        assert tags == ["PowerBI"]
        return ["13.73.248.16/29", "20.41.5.0/25"]

    monkeypatch.setattr(ast_mod, "fetch_service_tag_prefixes", fake_fetch)

    backend = authz_powerbi()
    backend.service_tags = ["PowerBI"]
    assert backend._networks == []

    added = await backend.load_service_tags()
    assert added == 2
    assert await backend.check_authorization(_pbi_request("20.41.5.87")) is True


@pytest.mark.asyncio
async def test_load_service_tags_empty_is_safe(monkeypatch):
    # A failed/empty fetch adds nothing and leaves static seeds intact.
    monkeypatch.setattr(pbi_mod, "POWERBI_ALLOWED_IPS", ["203.0.113.0/24"])

    async def fake_fetch(tags, timeout=60):
        return []

    monkeypatch.setattr(ast_mod, "fetch_service_tag_prefixes", fake_fetch)

    backend = authz_powerbi()
    backend.service_tags = ["PowerBI"]
    added = await backend.load_service_tags()
    assert added == 0
    # Static seed still authorizes.
    assert await backend.check_authorization(_pbi_request("203.0.113.10")) is True


@pytest.mark.asyncio
async def test_load_service_tags_noop_without_tags(monkeypatch):
    monkeypatch.setattr(pbi_mod, "POWERBI_ALLOWED_IPS", [])
    backend = authz_powerbi()
    backend.service_tags = []
    assert await backend.load_service_tags() == 0
