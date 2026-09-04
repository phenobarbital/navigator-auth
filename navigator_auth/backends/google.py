"""GoogleAuth.

Description: Backend Authentication/Authorization using Google AUTH API.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from aiohttp import web
from aiogoogle import Aiogoogle
from aiogoogle.auth.utils import create_secret
from navconfig.logging import logging
from navigator_session import get_session
from ..exceptions import AuthException, InvalidAuth, UserNotFound
from ..identity.types import TokenResponse
from ..responses import JSONResponse
from ..conf import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_API_SCOPES,
    GOOGLE_IDENTITY_SCOPES,
)
from .external import ExternalAuth

GOOGLE_LOGIN_FLOW = "google_auth_{state}"

#: FEAT-096 TASK-050 — Google's static JWKS (no OIDC discovery needed).
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ID_TOKEN_ISSUERS = ["accounts.google.com", "https://accounts.google.com"]
GOOGLE_TOKENINFO_URI = "https://oauth2.googleapis.com/tokeninfo"


def _looks_like_jwt(value: Optional[str]) -> bool:
    """True when *value* has the 3-dot-separated JWT shape."""
    return bool(value) and value.count(".") == 2

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
        # raw OAuth2 endpoints, used by the identity-link flow
        # (the login flow goes through aiogoogle's OIDC client):
        self.authorize_uri = "https://accounts.google.com/o/oauth2/v2/auth"
        self._token_uri = "https://oauth2.googleapis.com/token"
        self.userinfo_uri = "https://openidconnect.googleapis.com/v1/userinfo"

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

    ### Identity-link flow
    def identity_scopes(self) -> list:
        return GOOGLE_IDENTITY_SCOPES

    def identity_authorize_params(self) -> dict:
        # Google only re-issues a refresh token on explicit consent:
        return {
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
        }

    def get_identity_client(self) -> tuple:
        return (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

    def get_identity_userid(self, userinfo: dict):
        value = userinfo.get("sub", userinfo.get("id"))
        return str(value) if value is not None else None

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    def get_auth(self, request):
        """Extract (token, token_type) from the Authorization header or the
        `token` query param — mirrors AzureAuth.get_auth."""
        token = None
        try:
            if "Authorization" in request.headers:
                try:
                    token_type, token = request.headers.get("Authorization").strip().split(" ", 1)
                except ValueError as ex:
                    raise AuthException("Invalid authorization Header", status=400) from ex
            else:
                qs = {key: val for (key, val) in request.rel_url.query.items()}
                token_type = "Bearer"
                token = qs.get("token", None)
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(f"Google: Error getting payload: {err}")
            return None
        return [token, token_type]

    # ------------------------------------------------------------------
    # FEAT-096 TASK-050: verify_external_token — audience-bound verifier
    # used by the token-exchange login flow (backends/exchange.py) and by
    # check_credentials below.
    # ------------------------------------------------------------------

    async def verify_external_token(
        self,
        token: str,
        token_type: str = "Bearer",
        id_token: Optional[str] = None,
    ) -> tuple[dict, TokenResponse]:
        """Verify a Google bearer was minted for THIS client and is live.

        Prefers an id_token (given explicitly, or when `token` itself has
        the JWT shape and no separate id_token was supplied): fully
        verified via Google's static JWKS (signature, `aud ==
        GOOGLE_CLIENT_ID`, `iss`), requiring a verified e-mail. Otherwise
        treats `token` as an opaque access token: `tokeninfo` must report
        `aud` or `azp == GOOGLE_CLIENT_ID`, then the OIDC userinfo
        endpoint supplies the (verified-e-mail) profile.
        """
        jwt_candidate = id_token or (token if _looks_like_jwt(token) else None)
        scopes: list = []
        expires_at = None
        if jwt_candidate:
            claims = await self._verify_jwt(
                jwt_candidate,
                audience=GOOGLE_CLIENT_ID,
                issuer=GOOGLE_ID_TOKEN_ISSUERS,
                jwks_url=GOOGLE_JWKS_URL,
            )
            self._require_verified_email(claims)
            userinfo = claims
            provider_user_id = claims.get("sub")
            exp = claims.get("exp")
            if exp is not None:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
            access_token_out = token if (token and token != jwt_candidate) else jwt_candidate
        else:
            try:
                tokeninfo = await self.get(
                    url=f"{GOOGLE_TOKENINFO_URI}?access_token={token}"
                )
            except Exception as err:  # pylint: disable=W0703
                self.logger.warning(f"google: tokeninfo request failed: {err}")
                raise InvalidAuth("expired") from err
            aud = tokeninfo.get("aud")
            azp = tokeninfo.get("azp")
            if GOOGLE_CLIENT_ID not in (aud, azp):
                self.logger.warning(f"google: tokeninfo wrong audience aud={aud!r} azp={azp!r}")
                raise InvalidAuth("wrong_audience")
            scope = tokeninfo.get("scope")
            scopes = scope.split() if isinstance(scope, str) else list(scope or [])
            expires_in = tokeninfo.get("expires_in")
            if expires_in is not None:
                try:
                    expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))
                except (TypeError, ValueError):
                    expires_at = None
            try:
                userinfo = await self.get(
                    url=self.userinfo_uri, token=token, token_type=token_type
                )
            except Exception as err:  # pylint: disable=W0703
                self.logger.warning(f"google: userinfo request failed: {err}")
                raise InvalidAuth("expired") from err
            self._require_verified_email(userinfo)
            provider_user_id = userinfo.get("sub")
            access_token_out = token
        provider_user_id = str(provider_user_id) if provider_user_id is not None else None
        normalized = TokenResponse(
            access_token=access_token_out,
            token_type=token_type,
            id_token=jwt_candidate or id_token,
            expires_at=expires_at,
            provider_user_id=provider_user_id,
            scopes=scopes,
        )
        return userinfo, normalized

    async def check_credentials(self, request):
        """Authentication and create a session (mirrors AzureAuth's
        non-redirect branch)."""
        token, token_type = self.get_auth(request)
        qs = {key: val for (key, val) in request.rel_url.query.items()}
        id_token = qs.get("id_token")
        try:
            data, _normalized = await self.verify_external_token(
                token, token_type=token_type, id_token=id_token
            )
            if not data:
                return self.auth_error(reason="No user information available", status=403)
        except InvalidAuth as err:
            self.logger.warning(f"Google: check_credentials rejected: {err}")
            return self.auth_error(reason="Invalid or foreign token", status=401)
        except Exception as err:
            self.logger.exception(f"Google: Error getting User information: {err}")
            return self.auth_error(reason=f"Error getting User Information: {err}", status=403)
        try:
            userdata, uid = self.build_user_info(userdata=data, token=token, mapping=self.user_mapping)
        except ValueError as err:
            return self.auth_error(reason=f"Invalid User Information: {err}", status=401)
        try:
            data = await self.validate_user_info(request, uid, userdata, token)
        except UserNotFound:
            return self.auth_error(reason=f"User not Found: {uid}", status=401)
        try:
            session = await get_session(request)
            if not session:
                session = {}
            sessioninfo = {**data, **userdata}
            return JSONResponse(sessioninfo, status=200)
        except RuntimeError as err:
            response = {"message": "Session Error", "error": str(err)}
            return JSONResponse(response, status=402)
