import logging
from aiohttp import web
from ..conf import (
    ALLOWED_UA,
    ALLOWED_IP_TRUSTED_PROXIES,
    USERAGENT_SECURITY,
    USERAGENT_ALLOWED_COUNTRIES,
    AUTHZ_DEBUG
)
from ._client_ip import get_client_ip, parse_proxies
from ._geoip import lookup_country
from .abstract import BaseAuthzHandler


class authz_useragent(BaseAuthzHandler):
    """User-Agent based authorization.

    Allows any request whose ``User-Agent`` matches one of ``ALLOWED_UA``
    (case-insensitive substring match).

    When ``USERAGENT_SECURITY`` is enabled a matching User-Agent is necessary
    but **not sufficient**: the real client IP must also geolocate to one of
    ``USERAGENT_ALLOWED_COUNTRIES`` (default ``US, CA``). This is a temporary
    hardening for service clients (e.g. PowerBI / Power Query) that cannot be
    pinned to a CIDR range while they migrate to API-key authentication.

    Lookups fail **closed**: if the country cannot be determined (no GeoIP
    database, package missing, or unknown IP) the request is denied.
    """

    def __init__(self):
        self._proxies = parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)

    async def check_authorization(self, request: web.Request) -> bool:
        ua = request.headers.get("User-Agent", "").strip().lower()
        # A missing or empty User-Agent is never authorized (fail closed).
        if not ua:
            return False
        if all(key.lower() not in ua for key in ALLOWED_UA):
            return False
        if not USERAGENT_SECURITY:
            if AUTHZ_DEBUG:
                logging.debug(
                    f"Authorization: allowing Service based on User-Agent: {ua}"
                )
            return True
        # Geo-fence: User-Agent match must come from an allowed country.
        client_ip = get_client_ip(request, self._proxies)
        country = lookup_country(client_ip)
        if country in USERAGENT_ALLOWED_COUNTRIES:
            if AUTHZ_DEBUG:
                logging.info(
                    f"Authorization: allowing User-Agent service from "
                    f"{client_ip} ({country})"
                )
            return True
        logging.warning(
            "Authorization: User-Agent matched but denied by geo-fence "
            f"ip={client_ip} country={country or 'unknown'}"
        )
        return False
