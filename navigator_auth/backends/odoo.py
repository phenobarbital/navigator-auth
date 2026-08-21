"""OdooAuth.

Description: Backend Authentication/Authorization using an Odoo server
as OAuth2 provider.

Odoo has no OAuth2 *provider* out of the box (its ``auth_oauth`` module
makes Odoo an OAuth2 client). This backend targets the community
OAuth2-provider addon conventions (OCA ``oauth_provider``): an
authorization-code grant with ``client_secret_post`` authentication and
a JSON userinfo endpoint. Because deployments vary, every endpoint path
is configurable:

    ODOO_DOMAIN          e.g. https://erp.example.com  (required)
    ODOO_CLIENT_ID / ODOO_CLIENT_SECRET
    ODOO_AUTHORIZE_PATH  default /oauth2/auth
    ODOO_TOKEN_PATH      default /oauth2/token
    ODOO_USERINFO_PATH   default /oauth2/userinfo
    ODOO_SCOPES          default "profile,email"

The identity-link flow (saving an Odoo credential into the user's
identity vault) is fully inherited from the generic implementation in
``ExternalAuth``.
"""

import secrets
from aiohttp import web
from navconfig.logging import logging
from ..conf import (
    ODOO_DOMAIN,
    ODOO_CLIENT_ID,
    ODOO_CLIENT_SECRET,
    ODOO_AUTHORIZE_PATH,
    ODOO_TOKEN_PATH,
    ODOO_USERINFO_PATH,
    ODOO_SCOPES,
    ODOO_IDENTITY_SCOPES,
)
from .oauth import OauthAuth

ODOO_LOGIN_FLOW = "odoo_auth_{state}"


class OdooAuth(OauthAuth):
    """OdooAuth.

    Description: Authentication Backend using an Odoo OAuth2 provider.
    """

    userid_attribute: str = "sub"
    user_attribute: str = "name"
    username_attribute: str = "email"
    _service_name: str = "odoo"
    _description: str = "Odoo OAuth2 Authentication (OCA oauth_provider)"

    def configure(self, app):
        super(OdooAuth, self).configure(app)  # first, configure parents

        domain = (ODOO_DOMAIN or "").rstrip("/")
        self.base_url = f"{domain}/"
        self.authorize_uri = f"{domain}{ODOO_AUTHORIZE_PATH}"
        self.userinfo_uri = f"{domain}{ODOO_USERINFO_PATH}"
        self._issuer = domain
        self._token_uri = f"{domain}{ODOO_TOKEN_PATH}"

    async def get_credentials(self, request: web.Request, redirect_uri: str):
        state = secrets.token_urlsafe(32)
        await self._flow_store.set(
            ODOO_LOGIN_FLOW.format(state=state),
            {"redirect_uri": redirect_uri},
            ttl=600,
        )
        return {
            "client_id": f"{ODOO_CLIENT_ID}",
            "redirect_uri": redirect_uri,
            "scope": " ".join(ODOO_SCOPES),
            "state": state,
            "response_type": "code",
        }

    async def auth_callback(self, request: web.Request):
        state = request.query.get("state")
        flow = None
        if state:
            flow = await self._flow_store.getdel(
                ODOO_LOGIN_FLOW.format(state=state)
            )
        if not flow:
            response = {
                "message": "Odoo: Invalid or expired authentication state."
            }
            return web.json_response(response, status=403)
        code = request.query.get("code")
        if not code:
            response = {"message": "Auth Error: Odoo Code not accessible"}
            return web.json_response(response, status=403)
        try:
            exchange = await self.token_request(
                self._token_uri,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": flow["redirect_uri"],
                    "client_id": f"{ODOO_CLIENT_ID}",
                    "client_secret": ODOO_CLIENT_SECRET,
                },
            )
        except Exception as err:  # pylint: disable=W0703
            response = {"message": f"Odoo: Error getting Access Token: {err}"}
            return web.json_response(response, status=403)
        access_token = exchange["access_token"]
        token_type = exchange.get("token_type", "Bearer")
        try:
            data = await self.get(
                self.userinfo_uri, token=access_token, token_type=token_type
            )
            userdata, uid = self.build_user_info(
                data, access_token, mapping=self.user_mapping
            )
            data = await self.validate_user_info(
                request, uid, userdata, access_token
            )
            return self.home_redirect(
                request, token=data["token"], token_type="Bearer"
            )
        except Exception as err:
            logging.exception(f"Odoo Auth Error: {err}")
            return self.redirect(uri=self.login_failed_uri)

    ### Identity-link flow: generic implementation, Odoo endpoints.
    def identity_scopes(self) -> list:
        return ODOO_IDENTITY_SCOPES

    def get_identity_client(self) -> tuple:
        return (ODOO_CLIENT_ID, ODOO_CLIENT_SECRET)

    def get_identity_userid(self, userinfo: dict):
        value = userinfo.get("sub", userinfo.get("user_id", userinfo.get("id")))
        return str(value) if value is not None else None

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
