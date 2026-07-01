"""Authorization based on allowed IP addresses and CIDR ranges."""
import ipaddress
import logging
from aiohttp import web
from ..conf import ALLOWED_IPS, ALLOWED_IP_TRUSTED_PROXIES
from ._client_ip import get_client_ip, parse_proxies
from .abstract import BaseAuthzHandler


class authz_allowed_ips(BaseAuthzHandler):
    """Allowed IPs.

    Authorize requests based on the client's source IP address.
    Supports individual IPs and CIDR notation (e.g. 10.0.0.0/8).
    Checks X-Forwarded-For when the direct peer is a trusted proxy.

    Can be extended at runtime via ``add_networks()`` — used by the
    ``authz_powerbi`` subclass to inject PowerBI Azure Service Tag ranges
    at startup, and by ``AllowedIPHandler`` to add ranges on demand.
    """

    def __init__(
        self,
        allowed: list[str] | None = None,
        proxies: list[str] | None = None,
    ):
        # ``allowed``/``proxies`` let subclasses (e.g. authz_powerbi) seed from
        # their own config instead of the global ALLOWED_IPS list.
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in (ALLOWED_IPS if allowed is None else allowed):
            self._add_network(entry)
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
                f"authz_allowed_ips: ignoring invalid IP/CIDR: {entry}"
            )
            return False

    def add_networks(self, cidrs: list[str]) -> int:
        """Add CIDR ranges at runtime. Returns number of successfully added entries."""
        added = 0
        for entry in cidrs:
            if self._add_network(entry):
                added += 1
        logging.info(
            f"authz_allowed_ips: dynamically added {added} network ranges "
            f"(total: {len(self._networks)})"
        )
        return added

    def _get_client_ip(self, request: web.Request) -> str | None:
        """Extract the real client IP, respecting trusted proxies."""
        return get_client_ip(request, self._proxies)

    async def check_authorization(self, request: web.Request) -> bool:
        if not self._networks:
            return False
        client_ip = self._get_client_ip(request)
        if not client_ip:
            return False
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        for network in self._networks:
            if addr in network:
                logging.debug(
                    f"Authorization based on ALLOWED IP: {client_ip} in {network}"
                )
                return True
        return False
