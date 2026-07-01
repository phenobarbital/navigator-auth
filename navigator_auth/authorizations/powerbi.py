"""PowerBI IP authorization backend.

Extends :class:`authz_allowed_ips` to whitelist the Microsoft PowerBI /
Power Query Online Azure Service Tag ranges. Unlike the generic
``authz_allowed_ips`` backend (seeded from ``ALLOWED_IPS``), this backend is
seeded only from ``POWERBI_ALLOWED_IPS`` and is populated at server startup
with the live PowerBI service-tag prefixes downloaded from Microsoft.

The startup fetch (see ``AuthHandler._load_powerbi_service_tags``) only runs
when this backend is actually installed in ``AUTHORIZATION_BACKENDS`` — the
backend's presence is the opt-in switch, so no separate ``*_ENABLED`` flag is
needed.
"""
import logging
from ..conf import POWERBI_ALLOWED_IPS, POWERBI_SERVICE_TAGS
from .allowed_ips import authz_allowed_ips


class authz_powerbi(authz_allowed_ips):
    """Authorize requests originating from PowerBI Azure Service Tag ranges.

    Reuses the (X-Forwarded-For spoofing-safe) client-IP resolution and CIDR
    matching of :class:`authz_allowed_ips`, but keeps its own network set so
    PowerBI ranges never leak into the general-purpose allowed-IPs whitelist.
    """

    #: Azure Service Tag names whose prefixes authorize PowerBI traffic.
    service_tags: list[str] = POWERBI_SERVICE_TAGS

    def __init__(self):
        # Seed from the PowerBI-specific static list (not ALLOWED_IPS);
        # trusted proxies are shared via ALLOWED_IP_TRUSTED_PROXIES.
        super().__init__(allowed=POWERBI_ALLOWED_IPS)

    async def load_service_tags(self) -> int:
        """Fetch PowerBI Azure Service-Tag prefixes and add them.

        Returns the number of CIDR ranges successfully added. Safe to call
        when offline: a failed/empty fetch simply adds nothing and leaves the
        statically-seeded ``POWERBI_ALLOWED_IPS`` in place.
        """
        if not self.service_tags:
            return 0
        # Imported lazily so the network dependency is only touched at startup.
        from .azure_service_tags import fetch_service_tag_prefixes

        prefixes = await fetch_service_tag_prefixes(self.service_tags)
        if not prefixes:
            logging.warning(
                "authz_powerbi: no service-tag prefixes returned for %s",
                self.service_tags,
            )
            return 0
        return self.add_networks(prefixes)
