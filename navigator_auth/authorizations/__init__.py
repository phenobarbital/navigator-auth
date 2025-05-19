"""Authorization Middlewares for Navigator."""

from .hosts import authz_hosts
from .allow_hosts import authz_allow_hosts
from .useragent import authz_useragent

__all__ = (
    "authz_hosts",
    "authz_allow_hosts",
    "authz_useragent",
)
