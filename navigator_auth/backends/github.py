"""GithubAuth.

Description: Backend Authentication/Authorization using GitHub OAuth2.

Supports both classic OAuth Apps (non-expiring token, no refresh token)
and GitHub Apps user-to-server tokens (8h expiry + refresh token).
"""

import secrets
from aiohttp import web
from navconfig.logging import logging
from ..conf import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_SCOPES,
)
from .oauth import OauthAuth

GITHUB_LOGIN_FLOW = "github_auth_{state}"


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

    async def get_github_email(self, access_token: str) -> str:
        """Resolve the user's primary email when /user returns null
        (users with a private email address)."""
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
            if emails:
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

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
