"""Shared helpers to resolve the real client IP behind trusted proxies.

Used by both ``authz_allowed_ips`` (CIDR matching) and ``authz_useragent``
(geo-fencing) so the trusted-proxy / ``X-Forwarded-For`` logic lives in one
place.
"""
import ipaddress
import logging
from aiohttp import web

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_proxies(entries: list[str]) -> set[IPAddress]:
    """Build a set of proxy IP addresses, skipping (and logging) invalid ones."""
    proxies: set[IPAddress] = set()
    for entry in entries:
        try:
            proxies.add(ipaddress.ip_address(entry))
        except ValueError:
            logging.warning(f"authz: ignoring invalid trusted proxy IP: {entry}")
    return proxies


def _cf_connecting_ip(request: web.Request) -> str | None:
    """Return a validated ``CF-Connecting-IP`` header value, or None.

    Cloudflare sets this header to the original visitor IP at its edge.
    Callers must only trust it when the direct peer is a trusted proxy
    (e.g. a local ``cloudflared`` tunnel) — otherwise it is
    client-spoofable, just like ``X-Forwarded-For``.
    """
    value = request.headers.get("CF-Connecting-IP", "").strip()
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        logging.warning(f"authz: ignoring malformed CF-Connecting-IP: {value!r}")
        return None
    return value


def get_client_ip(
    request: web.Request,
    proxies: set[IPAddress] | None = None,
) -> str | None:
    """Extract the real client IP, respecting trusted proxies.

    ``X-Forwarded-For`` and ``CF-Connecting-IP`` are only honored when the
    direct TCP peer (``request.remote``) is a trusted proxy; otherwise the
    headers are attacker-controlled and are ignored in favor of the direct
    peer.

    When honored, the ``X-Forwarded-For`` chain is walked from RIGHT to LEFT
    (closest proxy → original client) and the first address that is **not**
    itself a trusted proxy is returned. A well-behaved proxy appends the
    address it actually observed to the right of the header, so any value a
    malicious client injects stays to the left and is never trusted. This
    closes the ``X-Forwarded-For`` spoofing hole where sending
    ``X-Forwarded-For: <whitelisted-ip>`` would previously bypass the check.

    ``CF-Connecting-IP`` (set by the Cloudflare edge, e.g. behind a
    ``cloudflared`` tunnel) is used as a fallback when ``X-Forwarded-For``
    is absent or contains only trusted proxies.
    """
    remote = request.remote
    if not remote:
        return None
    try:
        remote_addr = ipaddress.ip_address(remote)
    except ValueError:
        return None
    # Only trust forwarding headers when the direct peer is a known proxy.
    if not (proxies and remote_addr in proxies):
        return remote
    forwarded = request.headers.get("X-Forwarded-For", "")
    if not forwarded:
        return _cf_connecting_ip(request) or remote
    # Right-to-left: the first hop that is not a trusted proxy is the client.
    for hop in reversed(forwarded.split(",")):
        hop = hop.strip()
        if not hop:
            continue
        try:
            hop_addr = ipaddress.ip_address(hop)
        except ValueError:
            # A malformed value from an untrusted position; stop trusting the
            # rest of the chain and fall back to the direct peer.
            return remote
        if hop_addr in proxies:
            continue
        return hop
    # Every hop was a trusted proxy: fall back to Cloudflare's edge header
    # before giving up on client information entirely.
    return _cf_connecting_ip(request)
