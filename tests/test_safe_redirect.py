"""Open-redirect gate: ``navigator_auth.libs.redirect``.

Covers the bypasses the previous per-backend checks let through
(protocol-relative URLs, ``user@host`` netloc spoofing, glob patterns) and
the behaviour the multi-app deployment relies on (any subdomain of a trusted
base domain, relative paths, mobile deep links).
"""
import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.libs import redirect as mod
from navigator_auth.libs.redirect import (
    is_safe_redirect,
    is_trusted_host,
    normalize_domain,
    safe_redirect_url,
    trusted_domains,
)


@pytest.fixture(autouse=True)
def _trusted(monkeypatch):
    monkeypatch.setattr(mod, "AUTH_TRUSTED_DOMAINS", ["trocdigital.io", "localhost"])
    monkeypatch.setattr(mod, "AUTH_TRUSTED_REDIRECT_SCHEMES", [])
    monkeypatch.setattr(mod, "AUTH_REDIRECT_URI", "/")
    monkeypatch.setattr(mod, "PREFERRED_AUTH_SCHEME", "https")


def _request(host: str = "api.trocdigital.io") -> object:
    return make_mocked_request("GET", "/auth/login", headers={"Host": host})


# --- normalisation ---------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        (" Example.COM ", "example.com"),
        ("*.example.com", "example.com"),
        (".example.com", "example.com"),
        ("https://example.com:8443/path", "example.com"),
        ("localhost:5000", "localhost"),
        ("user@example.com:80", "example.com"),
        ("[::1]:8080", "::1"),
        ("", None),
        (None, None),
        ("*", None),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_trusted_domains_reads_config_and_extra():
    assert trusted_domains() == {"trocdigital.io", "localhost"}
    assert "extra.dev" in trusted_domains(extra=["https://extra.dev:9000"])


# --- host trust ------------------------------------------------------------

@pytest.mark.parametrize(
    "host",
    ["trocdigital.io", "app.trocdigital.io", "a.b.trocdigital.io", "APP.TrocDigital.IO", "localhost"],
)
def test_trusted_hosts(host):
    assert is_trusted_host(host)


@pytest.mark.parametrize(
    "host",
    ["evil.com", "trocdigital.io.evil.com", "nottrocdigital.io", "localhost.evil.com", "", None],
)
def test_untrusted_hosts(host):
    assert not is_trusted_host(host)


def test_request_host_is_always_trusted(monkeypatch):
    monkeypatch.setattr(mod, "AUTH_TRUSTED_DOMAINS", [])
    assert is_trusted_host("other.example", _request("other.example:8443"))
    assert not is_trusted_host("evil.com", _request("other.example:8443"))


# --- is_safe_redirect ------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "/",
        "/dashboard",
        "/dashboard?next=/x&y=1#frag",
        "dashboard",
        "https://app.trocdigital.io/home",
        "http://sub.app.trocdigital.io:8080/home?token=x",
        "HTTPS://APP.TROCDIGITAL.IO/",
        "https://localhost:3000/callback",
        "navigator://login/callback",
        "myapp:/oauth2redirect",
        "com.example.app://callback",
        "com.googleusercontent.apps.123-abc:/oauth2redirect",
    ],
)
def test_safe_targets(url):
    assert is_safe_redirect(url, _request())


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com/",
        "https://evil.com/?x=trocdigital.io",
        "https://trocdigital.io.evil.com/",
        "//evil.com/x",
        "///evil.com",
        "/\\evil.com",
        "\\\\evil.com",
        "https://api.trocdigital.io@evil.com/",
        "https://localhost@evil.com/",
        "https://evil.com\\@app.trocdigital.io/",
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,hi",
        "vbscript:msgbox",
        "file:///etc/passwd",
        "https:///nohost",
        "https://evil.com/\r\nSet-Cookie: x=1",
        "",
        None,
        123,
    ],
)
def test_unsafe_targets(url):
    assert not is_safe_redirect(url, _request())


def test_custom_scheme_allowlist(monkeypatch):
    monkeypatch.setattr(mod, "AUTH_TRUSTED_REDIRECT_SCHEMES", ["navigator"])
    assert is_safe_redirect("navigator://cb", _request())
    assert is_safe_redirect("NAVIGATOR://cb", _request())
    assert not is_safe_redirect("otherapp://cb", _request())
    # the allow-list never re-enables browser-executable schemes
    monkeypatch.setattr(mod, "AUTH_TRUSTED_REDIRECT_SCHEMES", ["javascript"])
    assert not is_safe_redirect("javascript:alert(1)", _request())


def test_host_port_is_not_a_scheme():
    # "localhost:5000/x" must not be treated as a custom-scheme deep link
    assert is_safe_redirect("localhost:5000/x", _request())  # relative-ish path, resolved on our domain
    assert safe_redirect_url(_request(), "localhost:5000/x").startswith("https://api.trocdigital.io/")


# --- safe_redirect_url -----------------------------------------------------

def test_relative_resolved_on_request_domain():
    assert safe_redirect_url(_request(), "/dashboard") == "https://api.trocdigital.io/dashboard"
    assert safe_redirect_url(_request(), "dashboard") == "https://api.trocdigital.io/dashboard"


def test_trusted_absolute_kept_verbatim():
    url = "https://app.trocdigital.io/home?x=1"
    assert safe_redirect_url(_request(), url) == url


def test_deep_link_kept_verbatim():
    assert safe_redirect_url(_request(), "navigator://cb") == "navigator://cb"


def test_untrusted_falls_back_to_default(caplog):
    with caplog.at_level("WARNING"):
        out = safe_redirect_url(_request(), "https://evil.com/")
    assert out == "https://api.trocdigital.io/"
    assert "evil.com" in caplog.text


def test_untrusted_falls_back_to_explicit_fallback():
    assert safe_redirect_url(_request(), "//evil.com", fallback="/login") == "https://api.trocdigital.io/login"
    fb = "https://app.trocdigital.io/done"
    assert safe_redirect_url(_request(), "https://evil.com", fallback=fb) == fb


def test_missing_candidate_uses_fallback():
    assert safe_redirect_url(_request(), None) == "https://api.trocdigital.io/"
    assert safe_redirect_url(_request(), "  ") == "https://api.trocdigital.io/"


def test_explicit_domain_url_is_honoured():
    out = safe_redirect_url(_request(), "/x", domain_url="https://other.trocdigital.io")
    assert out == "https://other.trocdigital.io/x"


def test_extra_hosts_are_trusted_for_that_call_only():
    assert is_safe_redirect("https://sp.partner.io/acs", _request(), extra_hosts=["sp.partner.io"])
    assert is_safe_redirect("https://sp.partner.io/acs", _request(), extra_hosts=["sp.partner.io:8443"])
    assert not is_safe_redirect("https://sp.partner.io/acs", _request())
    assert not is_safe_redirect("https://sp.partner.io@evil.com/", _request(), extra_hosts=["sp.partner.io"])
