""" Authorization based on HOSTS lists."""
import logging
from aiohttp import web
from ..conf import HOSTS, AUTHZ_DEBUG
from .abstract import BaseAuthzHandler


class authz_hosts(BaseAuthzHandler):
    """
    BasicHosts.
       Use for basic Host authorization, simply creating a list of allowed hosts
    """

    async def check_authorization(self, request: web.Request) -> bool:
        if request.host in HOSTS:
            if AUTHZ_DEBUG:
                logging.debug(
                    f"Authorization based on HOST {request.host}"
                )
            return True
        try:
            if request.headers["origin"] in HOSTS:
                if AUTHZ_DEBUG:
                    logging.debug(
                        f"Authorization based on HOST {request.headers['origin']}"
                    )
                return True
        except KeyError:
            return False
        return False
