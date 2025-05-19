import logging
from aiohttp import web
from ..conf import ALLOWED_UA
from .abstract import BaseAuthzHandler


class authz_useragent(BaseAuthzHandler):
    """
    User Agent.
        Allow Any request Coming from a Service
        Identified by its User-Agent string.
    """

    async def check_authorization(self, request: web.Request) -> bool:
        ua = request.headers.get("User-Agent", "").lower()
        for key in ALLOWED_UA:
            if key.lower() in ua:
                logging.debug("Authorization: allowing Service based on User-Agent")
                return True
        return False
