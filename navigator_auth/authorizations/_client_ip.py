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

    ``X-Forwarded-For`` is only honored when the direct TCP peer
    (``request.remote``) is a trusted proxy; otherwise the header is
    attacker-controlled and is ignored in favor of the direct peer.

    When it is honored, the chain is walked from RIGHT to LEFT (closest
    proxy → original client) and the first address that is **not** itself a
    trusted proxy is returned. A well-behaved proxy appends the address it
    actually observed to the right of the header, so any value a malicious
    client injects stays to the left and is never trusted. This closes the
    ``X-Forwarded-For`` spoofing hole where sending
    ``X-Forwarded-For: <whitelisted-ip>`` would previously bypass the check.
    """
    remote = request.remote
    if not remote:
        return None
    try:
        remote_addr = ipaddress.ip_address(remote)
    except ValueError:
        return None
    # Only trust XFF when the direct peer is a known proxy.
    if not (proxies and remote_addr in proxies):
        return remote
    forwarded = request.headers.get("X-Forwarded-For", "")
    if not forwarded:
        return remote
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
    # Every hop was a trusted proxy: no client information to authorize on.
    return None
