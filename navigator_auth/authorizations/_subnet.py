"""Shared engine for subnet-based (CIDR) authorization backends.

Provides :class:`SubnetAuthzHandler`, the reusable client-IP resolution and
CIDR-matching machinery behind every subnet-based authorization backend.
Concrete backends subclass it and seed their own, *independent* network set:

- :class:`~.allowed_ips.authz_allowed_ips` — subnets explicitly added by the
  user (via ``ALLOWED_IPS`` and the runtime ``AllowedIPHandler`` endpoint),
  e.g. an on-prem keepalive or an Amazon AWS local subnet.
- :class:`~.powerbi.authz_powerbi` — only the Microsoft PowerBI Azure
  Service-Tag ranges.

Because these are *sibling* subclasses (not one deriving from the other), each
backend keeps a fully separate ``_networks`` set: user-added ranges never leak
into the PowerBI whitelist and vice-versa. New subnet-based backends (other
cloud/service-tag providers) can be added the same way — subclass this handler
and set :attr:`service_tags`.
"""
import ipaddress
import logging
from aiohttp import web
from ..conf import ALLOWED_IP_TRUSTED_PROXIES, AUTHZ_DEBUG
from ._client_ip import get_client_ip, parse_proxies
from .abstract import BaseAuthzHandler


class SubnetAuthzHandler(BaseAuthzHandler):
    """Authorize requests whose client IP falls inside an allowed CIDR set.

    Supports individual IPs and CIDR notation (e.g. ``10.0.0.0/8``) and
    resolves the real client IP from ``X-Forwarded-For`` only when the direct
    peer is a trusted proxy. Subclasses seed their own network set (and,
    optionally, :attr:`service_tags`); this base never reads any global
    whitelist on its own so each backend stays independent.
    """

    #: Azure Service-Tag names to load into this backend at startup. Empty by
    #: default; subclasses override it to opt into dynamic service-tag loading.
    service_tags: list[str] = []

    def __init__(
        self,
        allowed: list[str] | None = None,
        proxies: list[str] | None = None,
    ):
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in (allowed or []):
            self._add_network(entry)
        # Trusted proxies default to the shared ALLOWED_IP_TRUSTED_PROXIES.
        self._proxies = parse_proxies(
            ALLOWED_IP_TRUSTED_PROXIES if proxies is None else proxies
        )

    def _add_network(self, entry: str) -> bool:
        try:
            self._networks.append(
                ipaddress.ip_network(entry, strict=False)
            )
            return True
        except ValueError:
            logging.warning(
                f"{type(self).__name__}: ignoring invalid IP/CIDR: {entry}"
            )
            return False

    def add_networks(self, cidrs: list[str]) -> int:
        """Add CIDR ranges at runtime. Returns number of successfully added entries."""
        added = 0
        for entry in cidrs:
            if self._add_network(entry):
                added += 1
        logging.info(
            f"{type(self).__name__}: dynamically added {added} network ranges "
            f"(total: {len(self._networks)})"
        )
        return added

    async def load_service_tags(self) -> int:
        """Fetch this backend's Azure Service-Tag prefixes and add them.

        Returns the number of CIDR ranges successfully added. Safe to call when
        offline: a failed/empty fetch simply adds nothing and leaves the
        statically-seeded networks in place. A backend with no
        :attr:`service_tags` is a no-op.
        """
        if not self.service_tags:
            return 0
        # Imported lazily so the network dependency is only touched at startup.
        from .azure_service_tags import fetch_service_tag_prefixes
        prefixes = await fetch_service_tag_prefixes(self.service_tags)
        if not prefixes:
            if AUTHZ_DEBUG:
                logging.warning(
                    f"{type(self).__name__}: no service-tag prefixes returned "
                    f"for {self.service_tags}"
                )
            return 0
        return self.add_networks(prefixes)

    def _get_client_ip(self, request: web.Request) -> str | None:
        """Extract the real client IP, respecting trusted proxies."""
        return get_client_ip(request, self._proxies)

    async def check_authorization(self, request: web.Request) -> bool:
        if not self._networks:
            return False
        client_ip = self._get_client_ip(request)
        if AUTHZ_DEBUG:
            logging.debug(
                f"{type(self).__name__}: authorization request from "
                f"client IP {client_ip!r} (peer={request.remote!r}, "
                f"xff={request.headers.get('X-Forwarded-For')!r}, "
                f"cf={request.headers.get('CF-Connecting-IP')!r}, "
                f"{getattr(request, 'method', '?')} {getattr(request, 'path', '?')})"
            )
        if not client_ip:
            return False
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            logging.debug(
                f"{type(self).__name__}: invalid client IP {client_ip!r}, denying"
            )
            return False
        for network in self._networks:
            if addr in network:
                if AUTHZ_DEBUG:
                    logging.debug(
                        f"{type(self).__name__}: authorized {client_ip} "
                        f"(matched network {network})"
                    )
                return True
        logging.info(
            f"{type(self).__name__}: {client_ip} not in any allowed network "
            f"({len(self._networks)} ranges checked)"
        )
        return False
