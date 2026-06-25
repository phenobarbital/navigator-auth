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


def get_client_ip(
    request: web.Request,
    proxies: set[IPAddress] | None = None,
) -> str | None:
    """Extract the real client IP, respecting trusted proxies.

    When the direct TCP peer is one of ``proxies``, the left-most entry of
    ``X-Forwarded-For`` (the original client) is returned; otherwise the
    direct peer (``request.remote``) is used.
    """
    remote = request.remote
    if not remote:
        return None
    try:
        remote_addr = ipaddress.ip_address(remote)
    except ValueError:
        return None
    if proxies and remote_addr in proxies:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return remote
