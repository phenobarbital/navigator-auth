"""GoogleAuth.

Description: Backend Authentication/Authorization using Google AUTH API.
"""

from aiohttp import web
from aiogoogle import Aiogoogle
from aiogoogle.auth.utils import create_secret
from navconfig.logging import logging
from ..exceptions import AuthException
from ..conf import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_API_SCOPES,
)
from .external import ExternalAuth

GOOGLE_LOGIN_FLOW = "google_auth_{state}"

# OIDC userinfo claim mapping (Google returns `sub`, not `id`):
GOOGLE_MAPPING = {
    "id": "sub",
    "email": "email",
    "username": "email",
    "first_name": "given_name",
    "last_name": "family_name",
    "display_name": "name",
    "given_name": "given_name",
    "family_name": "family_name",
}


class GoogleAuth(ExternalAuth):
    """GoogleAuth.

    Authentication Backend using Google+aiogoogle.
    """

    user_attribute: str = "user"
    username_attribute: str = "email"
    pwd_atrribute: str = "password"
    userid_attribute: str = "id"
    _service_name: str = "google"
    _description: str = "Google Apps Authentication"

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        super().__init__(
            user_attribute, userid_attribute, password_attribute, **kwargs
        )
        self.user_mapping = GOOGLE_MAPPING

    def configure(self, app):
        super(GoogleAuth, self).configure(app)
        # base client credentials; redirect_uri is computed per request.
        self._credentials = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "scopes": GOOGLE_API_SCOPES,
        }

    def get_google_credentials(self, redirect_uri: str, scopes: list = None) -> dict:
        """Per-request client credentials dict for aiogoogle."""
        return {
            **self._credentials,
            "scopes": scopes or GOOGLE_API_SCOPES,
            "redirect_uri": redirect_uri,
        }

    async def get_payload(self, request):
        pass

    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials."""
        # per-request state and nonce, stored server-side: backends are
        # process-wide singletons, so per-login data cannot live on `self`.
        state = create_secret()
        nonce = create_secret()
        redirect_uri = self.get_redirect_uri(request)
        ## getting Finish Redirect URL
        self.get_finish_redirect_url(request)
        credentials = self.get_google_credentials(redirect_uri)
        await self._flow_store.set(
            GOOGLE_LOGIN_FLOW.format(state=state),
            {"nonce": nonce, "redirect_uri": redirect_uri},
            ttl=600,
        )
        google = Aiogoogle(client_creds=credentials)
        if google.openid_connect.is_ready(credentials):
            uri = google.openid_connect.authorization_url(
                client_creds=credentials,
                state=state,
                nonce=nonce,
                access_type="offline",
                include_granted_scopes=True,
                # login_hint=user,
                prompt="select_account",
            )
            # Step A: redirect
            return self.redirect(uri)
        else:
            raise AuthException("Client doesn't have info for Authentication")

    async def auth_callback(self, request: web.Request):
        if error := request.query.get("error"):
            response = {
                "message": "Google Login Error",
                "error": error,
                "error_description": request.query.get("error_description"),
            }
            return web.json_response(response, status=403)
        if code := request.query.get("code"):
            state = request.query.get("state")
            flow = None
            if state:
                flow = await self._flow_store.getdel(
                    GOOGLE_LOGIN_FLOW.format(state=state)
                )
            if not flow:
                response = {
                    "message": "Something wrong with Authentication State",
                    "error": "Authenticate Error",
                }
                return web.json_response(response, status=403)
            credentials = self.get_google_credentials(flow["redirect_uri"])
            google = Aiogoogle(client_creds=credentials)
            user_creds = await google.openid_connect.build_user_creds(
                grant=code,
                client_creds=credentials,
                nonce=flow["nonce"],
                verify=True,
            )
            userdata = await google.openid_connect.get_user_info(user_creds)
            try:
                access_token = user_creds["id_token_jwt"]
                # GOOGLE_MAPPING maps the OIDC `sub` claim onto `id`:
                userdata, uid = self.build_user_info(
                    userdata, access_token, mapping=self.user_mapping
                )
                data = await self.validate_user_info(request, uid, userdata, access_token)
                return self.home_redirect(request, token=data["token"], token_type="Bearer")
            except Exception as err:
                logging.exception(f"Google Auth Error: {err}")
                return self.redirect(uri=self.login_failed_uri)
        else:
            response = {
                "message": "Something wrong with Google Callback",
                "error": "Authenticate Error",
            }
            return web.json_response(response, status=403)

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
