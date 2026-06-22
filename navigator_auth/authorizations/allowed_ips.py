"""Authorization based on allowed IP addresses and CIDR ranges."""
import ipaddress
import logging
from aiohttp import web
from ..conf import ALLOWED_IPS, ALLOWED_IP_TRUSTED_PROXIES
from .abstract import BaseAuthzHandler


class authz_allowed_ips(BaseAuthzHandler):
    """Allowed IPs.

    Authorize requests based on the client's source IP address.
    Supports individual IPs and CIDR notation (e.g. 10.0.0.0/8).
    Checks X-Forwarded-For when the direct peer is a trusted proxy.

    Can be extended at runtime via ``add_networks()`` — used by
    ``auth_startup`` to inject Azure Service Tag ranges dynamically.
    """

    def __init__(self):
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._proxies: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for entry in ALLOWED_IPS:
            self._add_network(entry)
        for entry in ALLOWED_IP_TRUSTED_PROXIES:
            try:
                self._proxies.add(ipaddress.ip_address(entry))
            except ValueError:
                logging.warning(
                    f"authz_allowed_ips: ignoring invalid proxy IP: {entry}"
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
        remote = request.remote
        if not remote:
            return None
        try:
            remote_addr = ipaddress.ip_address(remote)
        except ValueError:
            return None
        if self._proxies and remote_addr in self._proxies:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return remote

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
