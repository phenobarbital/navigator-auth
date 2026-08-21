"""OktaAuth.

Description: Backend Authentication/Authorization using Okta Service.
"""

import base64
import secrets
from aiohttp import web
from okta_jwt_verifier import JWTVerifier
from navconfig.logging import logging
from ..conf import (
    OKTA_CLIENT_ID,
    OKTA_CLIENT_SECRET,
    OKTA_DOMAIN,
    OKTA_AUDIENCE,
    OKTA_IDENTITY_SCOPES,
    # OKTA_APP_NAME
)

from .oauth import OauthAuth

OKTA_LOGIN_FLOW = "okta_auth_{state}"


async def is_token_valid(token, issuer, client_id, audience=None):
    jwt_verifier = JWTVerifier(issuer, client_id, audience or OKTA_AUDIENCE)
    try:
        await jwt_verifier.verify_access_token(token)
        return True
    except Exception:
        return False


async def is_id_token_valid(token, issuer, client_id, nonce, audience=None):
    jwt_verifier = JWTVerifier(issuer, client_id, audience or OKTA_AUDIENCE)
    try:
        await jwt_verifier.verify_id_token(token, nonce=nonce)
        return True
    except Exception:
        return False


class OktaAuth(OauthAuth):
    """OktaAuth.

    Description: Authentication Backend using Third-party Okta Service.
    """

    user_attribute: str = "user"
    username_attribute: str = "email"
    userid_attribute: str = "sub"
    pwd_atrribute: str = "password"
    _service_name: str = "okta"
    _description: str = "Okta Authentication"

    def configure(self, app):
        super(OktaAuth, self).configure(app)  # first, configure parents

        # auth paths.
        self.base_url = f"https://{OKTA_DOMAIN}/"
        self.authorize_uri = f"https://{OKTA_DOMAIN}/oauth2/default/v1/authorize"
        self.userinfo_uri = f"https://{OKTA_DOMAIN}/oauth2/default/v1/userinfo"
        self._issuer = f"https://{OKTA_DOMAIN}/oauth2/default"
        self._token_uri = f"https://{OKTA_DOMAIN}/oauth2/default/v1/token"
        self._introspection_uri = f"https://{OKTA_DOMAIN}/oauth2/default/v1/introspect"

    async def get_credentials(self, request: web.Request, redirect_uri: str):
        # CSRF/replay protection: random single-use state + nonce,
        # stored server-side and verified in the callback.
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        await self._flow_store.set(
            OKTA_LOGIN_FLOW.format(state=state),
            {"nonce": nonce, "redirect_uri": redirect_uri},
            ttl=600,
        )
        return {
            "client_id": f"{OKTA_CLIENT_ID}",
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "response_type": "code",
            "response_mode": "query",
        }

    async def auth_callback(self, request: web.Request):
        state = request.query.get("state")
        flow = None
        if state:
            flow = await self._flow_store.getdel(
                OKTA_LOGIN_FLOW.format(state=state)
            )
        if not flow:
            response = {
                "message": "Okta: Invalid or expired authentication state."
            }
            return web.json_response(response, status=403)
        code = request.query.get("code")
        if not code:
            response = {"message": "Auth Error: Okta Code not accessible"}
            return web.json_response(response, status=403)
        # B.- processing the code
        query_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": flow["redirect_uri"],
        }
        try:
            basic = base64.b64encode(
                f"{OKTA_CLIENT_ID}:{OKTA_CLIENT_SECRET}".encode()
            ).decode()
            exchange = await self.token_request(
                self._token_uri,
                data=query_params,
                headers={"Authorization": f"Basic {basic}"},
            )
        except Exception as err:
            response = {"message": f"Okta: Error Getting User Profile information: {err}"}
            return web.json_response(response, status=403)
        # Get tokens and validate
        if not exchange.get("token_type"):
            response = {"message": "Okta: Unsupported token type. Should be 'Bearer'."}
            return web.json_response(response, status=403)
        # user data
        access_token = exchange["access_token"]
        id_token = exchange["id_token"]

        if not await is_token_valid(access_token, self._issuer, OKTA_CLIENT_ID):
            response = {"message": "Okta: Access Token Invalid."}
            return web.json_response(response, status=403)

        if not await is_id_token_valid(id_token, self._issuer, OKTA_CLIENT_ID, flow["nonce"]):
            response = {"message": "Okta: ID Token Invalid."}
            return web.json_response(response, status=403)

        # Authorization flow successful, get userinfo and login user
        try:
            data = await self.get(self.userinfo_uri, token=access_token, token_type="Bearer")
            userdata, uid = self.build_user_info(data, access_token, mapping=self.user_mapping)
            # get user data
            data = await self.validate_user_info(request, uid, userdata, access_token)
            return self.home_redirect(request, token=data["token"], token_type="Bearer")
        except Exception as err:
            logging.exception(f"Okta Auth Error: {err}")
            return self.redirect(uri=self.login_failed_uri)

    ### Identity-link flow
    def identity_scopes(self) -> list:
        # offline_access is required for Okta to issue a refresh token
        return OKTA_IDENTITY_SCOPES

    def get_identity_client(self) -> tuple:
        return (OKTA_CLIENT_ID, OKTA_CLIENT_SECRET)

    def _basic_auth_header(self) -> dict:
        basic = base64.b64encode(
            f"{OKTA_CLIENT_ID}:{OKTA_CLIENT_SECRET}".encode()
        ).decode()
        return {"Authorization": f"Basic {basic}"}

    async def exchange_code_for_tokens(self, request, flow):
        from ..identity.types import TokenResponse
        from ..exceptions import AuthException

        code = request.rel_url.query.get("code")
        if not code:
            raise AuthException("okta: no authorization code in callback")
        payload = await self.token_request(
            self._token_uri,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": flow["redirect_uri"],
            },
            headers=self._basic_auth_header(),
        )
        return TokenResponse.from_oauth_response(
            payload, scopes=self.identity_scopes()
        )

    async def refresh_identity_tokens(self, refresh_token: str):
        from ..identity.types import TokenResponse

        payload = await self.token_request(
            self._token_uri,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": " ".join(self.identity_scopes()),
            },
            headers=self._basic_auth_header(),
        )
        token = TokenResponse.from_oauth_response(payload)
        if not token.refresh_token:
            token.refresh_token = refresh_token
        return token

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
