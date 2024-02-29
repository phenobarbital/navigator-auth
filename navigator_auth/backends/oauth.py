"""Oauth.

Oauth is a Abstract Class with basic functionalities for all Oauth2 backends.
"""
from abc import abstractmethod
from aiohttp import web
from ..exceptions import AuthException
from .external import ExternalAuth


class OauthAuth(ExternalAuth):
    """OauthAuth.

    Description: Abstract Class for all Oauth2 backends.
    """

    _auth_code: str = "code"
    _external_auth: bool = True

    @abstractmethod
    async def get_credentials(self, request: web.Request):
        pass

    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials."""
        try:
            domain_url = self.get_domain(request)
            self.redirect_uri = self.redirect_uri.format(
                domain=domain_url, service=self._service_name
            )
            # Build the URL
            params = await self.get_credentials(request)
            url = self.prepare_url(self.authorize_uri, params)
            # Step A: redirect
            return self.redirect(url)
        except Exception as err:
            raise AuthException(
                f"{self._service_name}: Client doesn't have information: {err}"
            ) from err

    def get_auth_response(self, request: web.Request) -> dict:
        return dict(request.rel_url.query.items())

    def get_auth_code(self, response: dict) -> str:
        try:
            code = response.get(self._auth_code)
        except KeyError:
            code = None
        if not code:
            raise RuntimeError(
                f"Auth Error: {self._service_name} Code not accessible"
            )
        return code
