"""Authorization Middlewares for Navigator."""

from .hosts import authz_hosts
from .allow_hosts import authz_allow_hosts
from .allowed_ips import authz_allowed_ips
from .powerbi import authz_powerbi
from .useragent import authz_useragent

__all__ = (
    "authz_hosts",
    "authz_allow_hosts",
    "authz_allowed_ips",
    "authz_powerbi",
    "authz_useragent",
)
