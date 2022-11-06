""" Authorization based on Allowed HOSTS lists."""
import fnmatch
import logging
from aiohttp import web
from navigator_auth.conf import ALLOWED_HOSTS
from .abstract import BaseAuthzHandler


class authz_allow_hosts(BaseAuthzHandler):
    """
    Allowed Hosts.
       Check if Origin is on the Allowed Hosts List.
    """

    async def check_authorization(self, request: web.Request) -> bool:
        origin = request.host if request.host else request.headers["origin"]
        for key in ALLOWED_HOSTS:
            if fnmatch.fnmatch(origin, key):
                logging.debug(
                    f'Authorization based on ALLOW HOST {key}'
                )
                return True
        return False
