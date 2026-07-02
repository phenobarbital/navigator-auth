"""PowerBI IP authorization backend.

A subnet-based authorization backend (see :class:`.SubnetAuthzHandler`) that
whitelists **only** the Microsoft PowerBI / Power Query Online Azure Service
Tag ranges. It is a *sibling* of ``authz_allowed_ips`` — both share the CIDR
matching engine but keep independent network sets, so PowerBI ranges never
leak into the operator-managed ``ALLOWED_IPS`` whitelist and user-added IPs
never leak into the PowerBI set.

The backend is seeded from ``POWERBI_ALLOWED_IPS`` (static fallback) and
populated at server startup with the live PowerBI service-tag prefixes
downloaded from Microsoft (``POWERBI_SERVICE_TAGS``).

The startup fetch (see ``AuthHandler._load_subnet_service_tags``) only runs
when this backend is actually installed in ``AUTHORIZATION_BACKENDS`` — the
backend's presence is the opt-in switch, so no separate ``*_ENABLED`` flag is
needed. New subnet-based providers can follow the same pattern: subclass
:class:`.SubnetAuthzHandler` and set ``service_tags``.
"""
from ..conf import POWERBI_ALLOWED_IPS, POWERBI_SERVICE_TAGS
from ._subnet import SubnetAuthzHandler


class authz_powerbi(SubnetAuthzHandler):
    """Authorize requests originating from PowerBI Azure Service Tag ranges.

    Reuses the (X-Forwarded-For spoofing-safe) client-IP resolution and CIDR
    matching of :class:`.SubnetAuthzHandler`, but keeps its own network set so
    PowerBI ranges never leak into the general-purpose allowed-IPs whitelist.
    """

    #: Azure Service Tag names whose prefixes authorize PowerBI traffic.
    service_tags: list[str] = POWERBI_SERVICE_TAGS

    def __init__(self):
        # Seed from the PowerBI-specific static list (not ALLOWED_IPS);
        # trusted proxies are shared via ALLOWED_IP_TRUSTED_PROXIES.
        super().__init__(allowed=POWERBI_ALLOWED_IPS)
