"""AzureAuth.

Description: Backend Authentication/Authorization using Microsoft authentication.
"""

import base64
from typing import Optional
import orjson
from aiohttp import web
import msal
import redis.asyncio as aioredis
from msal.authority import AuthorityBuilder, AZURE_PUBLIC
from navconfig.logging import logging
from navigator_session import get_session
from ..exceptions import AuthException, UserNotFound
from ..identity.types import TokenResponse
from ..conf import (
    AZURE_ADFS_CLIENT_ID,
    AZURE_ADFS_CLIENT_SECRET,
    AZURE_ADFS_DOMAIN,
    AZURE_ADFS_TENANT_ID,
    AZURE_SESSION_TIMEOUT,
    AZURE_MAPPING,
)
from ..libs.json import json_encoder, json_decoder
from ..responses import JSONResponse
from .external import ExternalAuth


logging.getLogger("msal").setLevel(logging.INFO)


def decode_part(raw, encoding="utf-8"):
    """decode_part.
    Decode a part of the JWT.
    JWT is encoded by padding-less base64url,
    based on `JWS specs <https://tools.ietf.org/html/rfc7515#appendix-C>`_.
    Args:
        raw (str): Data to be encoded-
        encoding (str, optional): If you are going to decode the first 2 parts of a JWT
        i.e. the header or the payload, the default value "utf-8" would work fine.
        If you are going to decode the last part i.e. the signature part,
        it is a binary string so you should use `None` as encoding here.

    Returns:
        str: part string decoded.
    """
    raw += "=" * (-len(raw) % 4)  # https://stackoverflow.com/a/32517907/728675
    raw = str(raw)
    output = base64.urlsafe_b64decode(raw)
    if encoding:
        output = output.decode(encoding)
    return output


class AzureAuth(ExternalAuth):
    """AzureAuth.

    Authentication Backend for Microsoft Online Services.
    """

    user_attribute: str = "username"
    # username_attribute: str = "userPrincipalName"
    username_attribute: str = "username"
    userid_attribute: str = "id"
    pwd_atrribute: str = "password"
    _service_name: str = "azure"
    _description: str = "Microsoft Azure Authentication"

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        super().__init__(user_attribute, userid_attribute, password_attribute, **kwargs)
        self.user_mapping = AZURE_MAPPING

    def configure(self, app):
        super(AzureAuth, self).configure(app)
        # TODO: build the callback URL and append to routes
        self.base_url: str = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}"
        self.authorize_uri = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}/oauth2/v2.0/authorize"  # noqa
        self.userinfo_uri = "https://graph.microsoft.com/v1.0/me"
        # issuer:
        self._issuer = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}"
        self._token_uri = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}/oauth2/v2.0/token"  # noqa
        self.authority = AuthorityBuilder(AZURE_PUBLIC, "contoso.onmicrosoft.com")
        self.users_info = "https://graph.microsoft.com/v1.0/users"

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## redis connection pool is created by ExternalAuth.on_startup
        await super(AzureAuth, self).on_startup(app)

    def get_msal_app(self, token_cache: msal.SerializableTokenCache = None):
        authority = self._issuer if self._issuer else self.authority
        return msal.ConfidentialClientApplication(
            AZURE_ADFS_CLIENT_ID,
            authority=authority,
            client_credential=AZURE_ADFS_CLIENT_SECRET,
            validate_authority=True,
            token_cache=token_cache,
        )

    def get_msal_client(self):
        authority = self._issuer if self._issuer else self.authority
        return msal.ClientApplication(
            AZURE_ADFS_CLIENT_ID,
            authority=authority,
            client_credential=AZURE_ADFS_CLIENT_SECRET,
            validate_authority=True,
        )

    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials."""
        try:
            user, pwd = await self.get_payload(request)
        except Exception as err:
            user = None
            pwd = None
            logging.error(err)
        ## getting Finish Redirect URL
        self.get_finish_redirect_url(request)
        if user and pwd:
            Default_SCOPE = ["User.ReadBasic.All"]
            # will use User/Pass Authentication
            app = self.get_msal_client()
            # Firstly, check the cache to see if this end user has signed in before
            accounts = app.get_accounts(username=user)
            result = None
            if accounts:
                result = app.acquire_token_silent(Default_SCOPE, account=accounts[0])
            if not result:
                # we need to get a new token from AAD
                result = app.acquire_token_by_username_password(user, pwd, Default_SCOPE)
                client_info = {}
                if "client_info" in result:
                    # It happens when client_info and profile are in request
                    client_info = json_decoder(decode_part(result["client_info"]))
                try:
                    if "access_token" in result:
                        access_token = result["access_token"]
                        data = await self.get(
                            url=self.userinfo_uri,
                            token=access_token,
                            token_type="Bearer",
                        )
                        data = {**data, **client_info}
                        userdata, uid = self.build_user_info(
                            userdata=data, token=access_token, mapping=self.user_mapping
                        )
                        # also, user information:
                        data = await self.validate_user_info(request, uid, userdata, access_token)
                        # Redirect User to HOME
                        return self.home_redirect(request, token=data["token"], token_type=self.scheme)
                    else:
                        if 65001 in result.get("error_codes", []):
                            # AAD requires user consent for U/P flow
                            print(
                                "Visit this to consent:",
                                app.get_authorization_request_url(Default_SCOPE),
                            )
                        else:
                            error = result.get("error")
                            desc = result.get("error_description")
                            correlation = result.get("correlation_id")
                            message = f"Azure {error}: {desc}, correlation id: {correlation}"
                            logging.exception(message)
                            raise web.HTTPForbidden(reason=message)
                except Exception as err:
                    raise web.HTTPForbidden(reason=f"Azure: Invalid Response from Server {err}.")
        else:
            qs = self.queryparams(request)
            redirect = None
            if "redirect_uri" in qs:
                redirect = qs.pop("redirect_uri")
            domain_url = self.get_domain(request)
            self.redirect_uri = self.redirect_uri.format(domain=domain_url, service=self._service_name)
            self.logger.notice(f"Redirect URL: {self.redirect_uri}")
            SCOPE = ["https://graph.microsoft.com/.default"]
            app = self.get_msal_app()
            try:
                flow = app.initiate_auth_code_flow(
                    scopes=SCOPE,
                    redirect_uri=self.redirect_uri,
                    domain_hint=AZURE_ADFS_DOMAIN,
                    max_age=int(AZURE_SESSION_TIMEOUT),
                )
                async with aioredis.Redis(connection_pool=self._pool) as redis:
                    state = flow["state"]
                    flow["internal_redirect"] = redirect
                    await redis.setex(f"azure_auth_{state}", AZURE_SESSION_TIMEOUT, json_encoder(flow))
                login_url = flow["auth_uri"]
                return self.redirect(login_url)
            except Exception as err:
                raise AuthException(f"Azure: Client doesn't have info for Authentication: {err}") from err

    async def auth_callback(self, request: web.Request):
        try:
            auth_response = dict(request.rel_url.query.items())
            state = None
            try:
                state = auth_response["state"]
            except (TypeError, KeyError, ValueError):
                return self.failed_redirect(request, error="MISSING_AUTH_NONCE", message="Missing Auth Nonce")
            flow = {}
            try:
                async with aioredis.Redis(connection_pool=self._pool) as redis:
                    result = await redis.get(f"azure_auth_{state}")
                    flow = orjson.loads(result)
            except Exception:
                return self.failed_redirect(
                    request, error="ERROR_RATE_LIMIT_EXCEEDED", message="Lost Authentication Flow, please try again."
                )
            app = self.get_msal_app()
            internal_redirect = flow.pop("internal_redirect", None)
            try:
                result = app.acquire_token_by_auth_code_flow(auth_code_flow=flow, auth_response=auth_response)
                if "token_type" not in result:
                    if "error" in result:
                        error = result["error"]
                        desc = result["error_description"]
                        message = f"Azure {error}: {desc}"
                        logging.exception(message)
                        return self.failed_redirect(
                            request, error="AUTHENTICATION_ERROR", message="Failed to generate session token"
                        )
                    else:
                        return self.failed_redirect(request, error="AUTHENTICATION_ERROR", message=f"Info: {result}")
                token_type = result["token_type"]
                access_token = result["access_token"]
                client_info = {}
                if "client_info" in result:
                    # It happens when client_info and profile are in request
                    client_info = orjson.loads(decode_part(result["client_info"]))
                # getting user information:
                try:
                    data = await self.get(
                        url=self.userinfo_uri,
                        token=access_token,
                        token_type=token_type,
                    )
                    # build user information:
                    data = {**data, **client_info}
                    userdata, uid = self.build_user_info(userdata=data, token=access_token, mapping=self.user_mapping)
                    data = await self.validate_user_info(request, uid, userdata, access_token)
                except Exception as err:
                    logging.exception(f"Azure: Error getting User information: {err}")
                    return self.failed_redirect(
                        request, error="ERROR_USER_NOT_FOUND", message=f"Error getting User information: {err}"
                    )
                # Redirect User to HOME
                try:
                    token = data["token"]
                except (KeyError, TypeError):
                    token = None
                return self.home_redirect(request, token=token, token_type=token_type, uri=internal_redirect)
            except Exception as err:
                logging.exception(err)
                return self.failed_redirect(
                    request, error="ERROR_INVALID_REQUEST", message=f"Error getting User information: {err}"
                )
        except Exception as err:
            logging.exception(err)
            return self.failed_redirect(request, error="ERROR_UNKNOWN", message=f"Error: {err}")

    ### Identity-link flow (MSAL-based)
    def identity_scopes(self) -> list:
        from ..conf import AZURE_IDENTITY_SCOPES

        # MSAL adds openid/profile/offline_access reserved scopes itself
        return AZURE_IDENTITY_SCOPES

    def get_identity_userid(self, userinfo: dict):
        value = userinfo.get("id", userinfo.get("userPrincipalName"))
        return str(value) if value is not None else None

    @staticmethod
    def _refresh_token_from_cache(
        cache: msal.SerializableTokenCache,
    ) -> Optional[str]:
        """MSAL never returns the refresh token in the result dict;
        it must be read from the token cache."""
        try:
            tokens = cache.find(msal.TokenCache.CredentialType.REFRESH_TOKEN)
            for entry in tokens:
                secret = entry.get("secret")
                if secret:
                    return secret
        except Exception:  # pylint: disable=W0703
            pass
        return None

    @staticmethod
    def _token_from_msal_result(
        result: dict, cache: msal.SerializableTokenCache
    ) -> TokenResponse:
        if "error" in result or "access_token" not in result:
            error = result.get("error", "unknown_error")
            desc = result.get("error_description", "")
            raise AuthException(f"azure: {error}: {desc}")
        scope = result.get("scope")
        scopes = scope.split() if isinstance(scope, str) else list(scope or [])
        return TokenResponse(
            access_token=result["access_token"],
            token_type=result.get("token_type", "Bearer"),
            refresh_token=AzureAuth._refresh_token_from_cache(cache),
            expires_in=result.get("expires_in"),
            scopes=scopes,
            raw={k: v for k, v in result.items() if k != "refresh_token"},
        )

    async def authorize_identity(
        self, request: web.Request, user_id, finish_redirect: str
    ):
        from ..conf import IDENTITY_LINK_TTL

        redirect_uri = self.get_redirect_uri(request)
        app = self.get_msal_app()
        flow = app.initiate_auth_code_flow(
            scopes=self.identity_scopes(),
            redirect_uri=redirect_uri,
        )
        # MSAL generates its own state: use it as the link-flow key.
        payload = {
            "user_id": user_id,
            "provider": self._service_name,
            "flow": "identity_link",
            "finish_redirect": finish_redirect,
            "redirect_uri": redirect_uri,
            "extra": {"msal_flow": flow},
        }
        await self._flow_store.start_link(
            flow["state"], payload, ttl=IDENTITY_LINK_TTL
        )
        return self.redirect(flow["auth_uri"])

    async def exchange_code_for_tokens(
        self, request: web.Request, flow: dict
    ) -> TokenResponse:
        auth_response = dict(request.rel_url.query.items())
        cache = msal.SerializableTokenCache()
        app = self.get_msal_app(token_cache=cache)
        result = app.acquire_token_by_auth_code_flow(
            auth_code_flow=flow["extra"]["msal_flow"],
            auth_response=auth_response,
        )
        return self._token_from_msal_result(result, cache)

    async def refresh_identity_tokens(self, refresh_token: str) -> TokenResponse:
        cache = msal.SerializableTokenCache()
        app = self.get_msal_app(token_cache=cache)
        result = app.acquire_token_by_refresh_token(
            refresh_token, scopes=self.identity_scopes()
        )
        token = self._token_from_msal_result(result, cache)
        if not token.refresh_token:
            token.refresh_token = refresh_token
        return token

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    def get_auth(self, request):
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
            self.logger.exception(f"Azure: Error getting payload: {err}")
            return None
        return [token, token_type]

    async def check_credentials(self, request):
        """Authentication and create a session."""
        token, token_type = self.get_auth(request)
        try:
            data = await self.get(
                url=self.userinfo_uri,
                token=token,
                token_type=token_type,
            )
            if not data:
                return self.auth_error(
                    reason={"message": "Access Denied", "error": "No user information available"}, status=403
                )
        except Exception as err:
            self.logger.exception(f"Azure: Error getting User information: {err}")
            return self.auth_error(
                reason={"message": "Access Denied", "error": f"Error getting User Information: {err}"}, status=403
            )
        # Creating User Session:
        try:
            userdata, uid = self.build_user_info(userdata=data, token=token, mapping=self.user_mapping)
        except ValueError as err:
            return self.auth_error(
                reason={"message": "Access Denied", "error": f"Invalid User Information: {err}"}, status=401
            )
        try:
            data = await self.validate_user_info(request, uid, userdata, token)
        except UserNotFound:
            return self.auth_error(reason={"message": "Access Denied", "error": f"User not Found: {uid}"}, status=401)
        # if redirect, then redirect to page, else, returns session:
        qs = {key: val for (key, val) in request.rel_url.query.items()}
        try:
            acc_token = data["token"]
        except (KeyError, TypeError):
            acc_token = None
        redirect = qs.pop("redirect", None)
        if not redirect:
            redirect = request.headers.get("redirect", None)
        if redirect is not None:
            # passing QS transparently to backend:
            return self.home_redirect(request, token=acc_token, token_type=token_type, uri=redirect, queryparams=qs)
        else:
            # return session information:
            try:
                session = await get_session(request)
                if not session:
                    # Empty Session
                    session = {}
                sessioninfo = {**data, **userdata}
                return JSONResponse(sessioninfo, status=200)
            except RuntimeError as err:
                response = {"message": "Session Error", "error": str(err)}
                return JSONResponse(response, status=402)
