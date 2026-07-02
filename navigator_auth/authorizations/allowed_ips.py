"""Authorization based on user-defined allowed IP addresses and CIDR ranges.

``authz_allowed_ips`` holds the subnets *explicitly added by the operator* —
seeded from the global ``ALLOWED_IPS`` list and extendable at runtime through
the ``AllowedIPHandler`` endpoint (e.g. an on-prem keepalive or an Amazon AWS
local subnet). It deliberately does **not** contain any provider/service-tag
ranges; those live in dedicated sibling backends such as ``authz_powerbi``.

The CIDR-matching engine lives in :class:`.SubnetAuthzHandler`.
"""
from ..conf import ALLOWED_IPS
from ._subnet import SubnetAuthzHandler


class authz_allowed_ips(SubnetAuthzHandler):
    """Allowed IPs.

    Authorize requests based on the client's source IP address.
    Supports individual IPs and CIDR notation (e.g. 10.0.0.0/8).
    Checks X-Forwarded-For when the direct peer is a trusted proxy.

    Seeded from the global ``ALLOWED_IPS`` whitelist and extendable at runtime
    via ``add_networks()`` — used by ``AllowedIPHandler`` to add operator
    ranges on demand. Provider-specific ranges (e.g. PowerBI Azure Service
    Tags) are handled by separate sibling backends so they never leak into
    this general-purpose whitelist.
    """

    def __init__(
        self,
        allowed: list[str] | None = None,
        proxies: list[str] | None = None,
    ):
        # Default to the global operator-managed ALLOWED_IPS list.
        super().__init__(
            allowed=ALLOWED_IPS if allowed is None else allowed,
            proxies=proxies,
        )
