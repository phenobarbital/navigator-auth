"""Tests for FEAT-097 Module 1: pysaml2 dependency swap, SAML config keys,
redirect-validator promotion (TASK-054).
"""
import pytest
from navigator_auth import conf
from navigator_auth.backends.abstract import BaseAuthBackend


class _Stub(BaseAuthBackend):
    async def on_startup(self, app):
        ...

    async def check_credentials(self, request):
        ...


@pytest.fixture
def backend(monkeypatch):
    monkeypatch.setattr("navigator_auth.backends.abstract.ALLOWED_HOSTS", ["*.example.com"])
    return _Stub(user_model=None)


def test_validate_redirect_relative(backend):
    assert backend.validate_redirect_host("/home") == "/home"


def test_validate_redirect_allowed(backend):
    assert backend.validate_redirect_host("https://app.example.com/x") == "https://app.example.com/x"


def test_validate_redirect_rejected(backend):
    assert backend.validate_redirect_host("https://evil.test/x") is None


def test_validate_redirect_extra_hosts(backend):
    assert backend.validate_redirect_host(
        "https://sp.partner.io/acs", extra_hosts=["sp.partner.io"]
    )


def test_validate_redirect_none(backend):
    assert backend.validate_redirect_host(None) is None


def test_conf_defaults():
    assert conf.SAML_CLOCK_SKEW == 60
    assert conf.SAML_FLOW_TTL == 600
    assert conf.SAML_EXECUTOR_WORKERS == 4
    assert conf.SAML_IDP_SERVICE_PROVIDERS == []
    assert conf.SAML_BINDING == "redirect"
    assert conf.SAML_ALLOW_UNSOLICITED is True
    assert conf.SAML_WANT_ASSERTIONS_SIGNED is True
    assert conf.SAML_WANT_RESPONSE_SIGNED is False
    assert conf.SAML_METADATA_RELOAD == 3600
    assert conf.SAML_IDP_REQUIRE_AUTH_METHODS == []
    # existing keys untouched
    assert conf.SAML_PATH is None
    assert isinstance(conf.SAML_MAPPING, dict)


def test_backends_package_imports():
    """The package must still import even though the legacy `saml.py`
    (python3-saml) cannot import once python3-saml is removed from deps."""
    import navigator_auth.backends  # noqa: F401
