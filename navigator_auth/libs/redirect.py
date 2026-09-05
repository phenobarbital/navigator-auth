"""Open-redirect protection for user-supplied redirect targets.

Navigator Auth lets the *frontend* tell the backend where to send the
browser once authentication finishes (``?redirect_uri=``, SAML
``RelayState``, the identity-link ``finish_redirect`` ...). One backend
serves dozens of sub-apps on many sub-domains, so that target cannot be a
fixed setting; but honouring it verbatim is a classic **open redirect**:
``https://api.example.com/auth/login?redirect_uri=https://evil.com`` lands
a freshly minted token on an attacker's page.

:func:`safe_redirect_url` is the single gate every redirect goes through:

* **Relative paths** (``/dashboard``) are always accepted and resolved
  against the current request's own domain. Protocol-relative
  (``//evil.com``) and backslash (``/\\evil.com``) forms are rejected.
* **Absolute ``http(s)`` URLs** are accepted only when the *hostname*
  (never the raw ``netloc``, which ``user@host`` tricks can spoof) is one
  of the trusted domains or a subdomain of one. The host serving the
  current request is always trusted.
* **Custom schemes** (mobile deep links: ``navigator://``,
  ``com.example.app:/oauth``) are accepted, optionally restricted to
  ``AUTH_TRUSTED_REDIRECT_SCHEMES``; schemes a browser would *execute*
  (``javascript:``, ``data:`` ...) are always rejected.

Anything rejected falls back to the configured default landing page on the
current domain, so a tampered link degrades gracefully instead of breaking
the login.
"""
from typing import Optional, Iterable
from urllib.parse import urlparse
from aiohttp import web
from navconfig.logging import logging
from ..conf import (
    AUTH_TRUSTED_DOMAINS,
    AUTH_TRUSTED_REDIRECT_SCHEMES,
    AUTH_REDIRECT_URI,
    PREFERRED_AUTH_SCHEME,
)

__all__ = (
    "FORBIDDEN_SCHEMES",
    "normalize_domain",
    "trusted_domains",
    "is_trusted_host",
    "is_safe_redirect",
    "safe_redirect_url",
)

# Schemes a browser would execute or that never denote another application.
FORBIDDEN_SCHEMES = frozenset(
    {"javascript", "data", "vbscript", "file", "blob", "about", "jar", "ftp"}
)
_WEB_SCHEMES = frozenset({"http", "https"})


def normalize_domain(value: Optional[str]) -> Optional[str]:
    """Reduce a configured entry to a bare, lower-cased hostname.

    Accepts the forms operators actually write — ``example.com``,
    ``*.example.com``, ``.example.com``, ``https://example.com:8443/`` or
    ``localhost:5000`` — and returns ``example.com`` / ``localhost``.
    ``None`` when nothing usable remains.
    """
    if not value:
        return None
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).netloc
    # user@host:port -> host:port -> host
    value = value.rsplit("@", 1)[-1]
    if value.startswith("[") and "]" in value:  # IPv6 literal
        value = value[1 : value.index("]")]
    else:
        value = value.split(":", 1)[0]
    value = value.lstrip("*").strip(".")
    return value or None


def trusted_domains(extra: Iterable[str] = ()) -> frozenset:
    """Effective set of trusted base domains (config plus ``extra``)."""
    entries = list(AUTH_TRUSTED_DOMAINS) + list(extra)
    return frozenset(d for d in (normalize_domain(e) for e in entries) if d)


def _request_hostname(request: Optional[web.Request]) -> Optional[str]:
    if request is None:
        return None
    try:
        host = request.host
    except AttributeError:
        return None
    return normalize_domain(host)


def is_trusted_host(
    hostname: Optional[str],
    request: Optional[web.Request] = None,
    extra_hosts: Iterable[str] = (),
) -> bool:
    """``True`` when ``hostname`` is a trusted domain or a subdomain of one.

    The host serving ``request`` (when given) and any ``extra_hosts`` the
    caller vouches for (e.g. a SAML SP's ACS host) are trusted as well.
    """
    hostname = normalize_domain(hostname)
    if not hostname:
        return False
    extra = [h for h in (_request_hostname(request),) if h]
    extra.extend(extra_hosts)
    domains = trusted_domains(extra=extra)
    return any(
        hostname == domain or hostname.endswith(f".{domain}") for domain in domains
    )


def _split_scheme(url: str) -> tuple[str, str]:
    """``(scheme, rest)`` with ``scheme`` lower-cased, or ``("", url)``.

    Unlike :func:`urlparse`, ``host:port/path`` is *not* mistaken for a
    scheme: a purely numeric run right after the colon means a port.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if not scheme:
        return "", url
    rest = url[len(parsed.scheme) + 1 :]
    port, _, _ = rest.partition("/")
    if port.isdigit():
        return "", url
    return scheme, rest


def is_safe_redirect(
    url: Optional[str],
    request: Optional[web.Request] = None,
    extra_hosts: Iterable[str] = (),
) -> bool:
    """Whether ``url`` may be used as a redirect target as-is or once resolved.

    ``extra_hosts`` are additional trusted hosts for this call only.
    """
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not url or any(ch in url for ch in "\r\n\t\x00"):
        return False
    scheme, _ = _split_scheme(url)
    if not scheme:
        # Relative reference: refuse protocol-relative ("//host") and the
        # backslash variants browsers normalise to it ("/\host", "\\host").
        if url[0] == "\\":
            return False
        if url[0] == "/" and len(url) > 1 and url[1] in "/\\":
            return False
        return not urlparse(url).netloc
    if scheme in FORBIDDEN_SCHEMES:
        return False
    if scheme in _WEB_SCHEMES:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        # Browsers (WHATWG) treat "\\" as "/" in http(s) URLs, so
        # "https://evil.com\\@trusted.io/" is host evil.com to the browser
        # while urlparse reports trusted.io: refuse the parser differential.
        if "\\" in parsed.netloc:
            return False
        return is_trusted_host(parsed.hostname, request, extra_hosts=extra_hosts)
    # Custom (deep-link) scheme.
    if AUTH_TRUSTED_REDIRECT_SCHEMES:
        return scheme in AUTH_TRUSTED_REDIRECT_SCHEMES
    return True


def _domain_url(request: web.Request) -> str:
    netloc = urlparse(str(request.url)).netloc
    return f"{PREFERRED_AUTH_SCHEME}://{netloc}"


def _resolve(url: str, domain_url: str) -> str:
    """Turn a relative path into an absolute URL on ``domain_url``."""
    scheme, _ = _split_scheme(url)
    if scheme:
        return url
    if not url.startswith("/"):
        url = f"/{url}"
    return f"{domain_url}{url}"


def safe_redirect_url(
    request: web.Request,
    candidate: Optional[str],
    fallback: Optional[str] = None,
    domain_url: Optional[str] = None,
) -> str:
    """Return the URL the browser may be redirected to.

    ``candidate`` is the untrusted, user-supplied target. When it passes
    :func:`is_safe_redirect` it is returned, with relative paths resolved
    against ``domain_url`` (the current request's domain by default). When it
    does not, a warning is logged and ``fallback`` — an operator-controlled
    value, ``AUTH_REDIRECT_URI`` by default — is resolved the same way and
    returned instead, so the login still completes on a safe page.
    """
    if domain_url is None:
        domain_url = _domain_url(request)
    if fallback is None:
        fallback = AUTH_REDIRECT_URI or "/"
    if isinstance(candidate, str):
        candidate = candidate.strip()
    if candidate and is_safe_redirect(candidate, request):
        return _resolve(candidate, domain_url)
    if candidate:
        logging.warning(
            f"Rejected redirect to untrusted target {candidate!r}; "
            f"falling back to {fallback!r}"
        )
    return _resolve(fallback, domain_url)
