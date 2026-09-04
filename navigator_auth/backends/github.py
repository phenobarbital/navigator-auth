"""GithubAuth.

Description: Backend Authentication/Authorization using GitHub OAuth2.

Supports both classic OAuth Apps (non-expiring token, no refresh token)
and GitHub Apps user-to-server tokens (8h expiry + refresh token).
"""

import base64
import secrets
from datetime import datetime
from typing import Optional
from aiohttp import web
from navconfig.logging import logging
from navigator_session import get_session
from ..exceptions import AuthException, InvalidAuth, UserNotFound
from ..identity.types import TokenResponse
from ..responses import JSONResponse
from ..conf import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_SCOPES,
    GITHUB_IDENTITY_SCOPES,
)
from .oauth import OauthAuth

GITHUB_LOGIN_FLOW = "github_auth_{state}"

#: FEAT-096 TASK-051 — GitHub REST "Check a token" endpoint. Authenticated
#: with OUR OWN client credentials (Basic auth), not the caller's token:
#: 200 -> the token is valid and belongs to this app; 404 -> foreign or
#: revoked; 401 -> our own client credentials are misconfigured.
GITHUB_CHECK_TOKEN_URI = "https://api.github.com/applications/{client_id}/token"


class GithubAuth(OauthAuth):
    """GithubAuth.

    Description: Authentication Backend using Third-party GitHub Service.
    """

    userid_attribute: str = "login"
    user_attribute: str = "name"
    username_attribute: str = "email"
    _service_name: str = "github"
    _description: str = "Github Oauth Authentication"

    def configure(self, app):
        super(GithubAuth, self).configure(app)  # first, configure parents

        # auth paths.
        self.base_url = "https://api.github.com/"
        self.authorize_uri = "https://github.com/login/oauth/authorize"
        self.userinfo_uri = "https://api.github.com/user"
        self._issuer = "https://api.github.com/"
        self._token_uri = "https://github.com/login/oauth/access_token"

    async def get_credentials(self, request: web.Request, redirect_uri: str):
        # CSRF protection: random state, single-use, stored server-side.
        state = secrets.token_urlsafe(32)
        await self._flow_store.set(
            GITHUB_LOGIN_FLOW.format(state=state),
            {"redirect_uri": redirect_uri},
            ttl=600,
        )
        return {
            "client_id": f"{GITHUB_CLIENT_ID}",
            "redirect_uri": redirect_uri,
            "scope": " ".join(GITHUB_SCOPES),
            "state": state,
            "allow_signup": "false",
        }

    async def get_github_email(
        self, access_token: str, verified_only: bool = False
    ) -> str:
        """Resolve the user's primary email when /user returns null
        (users with a private email address).

        `verified_only=True` (used by `verify_external_token`, TASK-051)
        restricts the result to a `primary and verified` entry, returning
        `None` when there isn't one. The default (unchanged, used by the
        login-callback path) falls back to the first listed e-mail when no
        primary+verified entry exists.
        """
        try:
            emails = await self.get(
                "https://api.github.com/user/emails",
                token=access_token,
                token_type="Bearer",
                headers={"Accept": "application/vnd.github+json"},
            )
            for entry in emails or []:
                if entry.get("primary") and entry.get("verified"):
                    return entry.get("email")
            if emails and not verified_only:
                return emails[0].get("email")
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"Github: cannot fetch user emails: {err}")
        return None

    async def auth_callback(self, request: web.Request):
        auth_response = self.get_auth_response(request)
        state = auth_response.get("state")
        flow = None
        if state:
            flow = await self._flow_store.getdel(
                GITHUB_LOGIN_FLOW.format(state=state)
            )
        if not flow:
            response = {
                "message": "Github: Invalid or expired authentication state."
            }
            return web.json_response(response, status=403)
        try:
            code = self.get_auth_code(auth_response)
        except Exception as err:
            message = f"Github: Missing Auth Code: {auth_response}"
            logging.exception(message)
            response = {"message": message, "error": str(err)}
            return web.json_response(response, status=403)
        try:
            result = await self.token_request(
                self._token_uri,
                data={
                    "client_id": f"{GITHUB_CLIENT_ID}",
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": flow["redirect_uri"],
                },
            )
        except Exception as err:  # pylint: disable=W0703
            message = f"Github Error getting Access Token: {err}"
            logging.exception(message)
            response = {"message": message}
            return web.json_response(response, status=403)
        access_token = result["access_token"]
        # then, will get user info:
        try:
            headers = {"Accept": "application/vnd.github+json"}
            data = await self.get(
                self.userinfo_uri,
                token=access_token,
                token_type="Bearer",
                headers=headers,
            )
            if data:
                if not data.get("email"):
                    email = await self.get_github_email(access_token)
                    if email:
                        data["email"] = email
                userdata, uid = self.build_user_info(data, access_token, mapping=self.user_mapping)
                # also, user information:
                data = await self.validate_user_info(request, uid, userdata, access_token)
                # Redirect User to HOME
                return self.home_redirect(request, token=data["token"], token_type="Bearer")
            else:
                return self.redirect(uri=self.login_failed_uri)
        except Exception as err:
            logging.exception(err)
            return self.redirect(uri=self.login_failed_uri)

    ### Identity-link flow
    def identity_scopes(self) -> list:
        return GITHUB_IDENTITY_SCOPES

    def identity_authorize_params(self) -> dict:
        return {"allow_signup": "false"}

    def get_identity_client(self) -> tuple:
        return (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)

    def get_identity_userid(self, userinfo: dict):
        # numeric account id is stable even across username changes
        value = userinfo.get("id", userinfo.get("login"))
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
            self.logger.exception(f"Github: Error getting payload: {err}")
            return None
        return [token, token_type]

    # ------------------------------------------------------------------
    # FEAT-096 TASK-051: verify_external_token — audience-bound verifier
    # used by the token-exchange login flow (backends/exchange.py) and by
    # check_credentials below.
    # ------------------------------------------------------------------

    async def _check_app_token(self, token: str) -> dict:
        """POST /applications/{client_id}/token ("check a token"),
        authenticated with OUR OWN client credentials — this both
        validates the token and confirms it was minted for this app."""
        basic = base64.b64encode(
            f"{GITHUB_CLIENT_ID}:{GITHUB_CLIENT_SECRET}".encode()
        ).decode()
        url = GITHUB_CHECK_TOKEN_URI.format(client_id=GITHUB_CLIENT_ID)
        try:
            return await self.post(
                url,
                headers={
                    "Authorization": f"Basic {basic}",
                    "Accept": "application/vnd.github+json",
                },
                json={"access_token": token},
            )
        except AuthException as err:
            # ExternalAuth.request() collapses every non-200 response into
            # a generic AuthException whose message is the (stringified)
            # response body — GitHub's "check a token" endpoint has two
            # stable, documented bodies for its two failure modes, so we
            # branch on that rather than the (unavailable) status code.
            message = str(err)
            if "Not Found" in message:
                self.logger.warning(
                    "github: token check 404 (foreign or revoked token)"
                )
                raise InvalidAuth("wrong_audience") from err
            if "Bad credentials" in message:
                self.logger.error(
                    f"github: check-token client credentials rejected: {err}"
                )
                raise AuthException(
                    "github: token-exchange client credentials misconfigured",
                    status=500,
                ) from err
            self.logger.warning(f"github: token check failed: {err}")
            raise InvalidAuth("invalid_token") from err

    async def verify_external_token(
        self,
        token: str,
        token_type: str = "Bearer",
        id_token: Optional[str] = None,
    ) -> tuple[dict, TokenResponse]:
        """Verify a GitHub bearer belongs to THIS OAuth app and is live.

        `id_token` is accepted (and ignored) for signature parity with the
        other providers — GitHub has none.
        """
        check = await self._check_app_token(token)
        user = dict(check.get("user") or {})
        scopes = list(check.get("scopes") or [])
        expires_at = None
        expires_at_raw = check.get("expires_at")  # GitHub Apps user-to-server tokens only
        if expires_at_raw:
            try:
                expires_at = datetime.fromisoformat(
                    str(expires_at_raw).replace("Z", "+00:00")
                )
            except ValueError:
                expires_at = None
        if not user.get("email"):
            email = await self.get_github_email(token, verified_only=True)
            if not email:
                raise InvalidAuth("email_unverified")
            user["email"] = email
        provider_user_id = user.get("id")
        provider_user_id = str(provider_user_id) if provider_user_id is not None else None
        normalized = TokenResponse(
            access_token=token,
            token_type=token_type,
            expires_at=expires_at,
            provider_user_id=provider_user_id,
            scopes=scopes,
        )
        return user, normalized

    async def check_credentials(self, request):
        """Authentication and create a session (mirrors AzureAuth's
        non-redirect branch)."""
        token, token_type = self.get_auth(request)
        try:
            data, _normalized = await self.verify_external_token(token, token_type=token_type)
            if not data:
                return self.auth_error(reason="No user information available", status=403)
        except InvalidAuth as err:
            self.logger.warning(f"Github: check_credentials rejected: {err}")
            return self.auth_error(reason="Invalid or foreign token", status=401)
        except Exception as err:
            self.logger.exception(f"Github: Error getting User information: {err}")
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
