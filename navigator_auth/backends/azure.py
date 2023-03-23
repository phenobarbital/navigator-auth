"""AzureAuth.

Description: Backend Authentication/Authorization using Microsoft authentication.
"""
import base64
import orjson
from aiohttp import web
import msal
import aioredis
from msal.authority import AuthorityBuilder, AZURE_PUBLIC
from navconfig.logging import logging
from navigator_auth.exceptions import AuthException
from navigator_auth.conf import (
    AZURE_ADFS_CLIENT_ID,
    AZURE_ADFS_CLIENT_SECRET,
    AZURE_ADFS_DOMAIN,
    AZURE_ADFS_TENANT_ID,
    AZURE_SESSION_TIMEOUT,
    REDIS_AUTH_URL,
)
from navigator_auth.libs.json import json_encoder, json_decoder
from .external import ExternalAuth


logging.getLogger("msal").setLevel(logging.INFO)


def decode_part(raw, encoding="utf-8"):
    """decode_part.
    Decode a part of the JWT.
    JWT is encoded by padding-less base64url,
    based on `JWS specs <https://tools.ietf.org/html/rfc7515#appendix-C>`_.
    Args:
        raw (str): Data to be encoded-
        encoding (str, optional): If you are going to decode the first 2 parts of a JWT, i.e. the header
        or the payload, the default value "utf-8" would work fine.
        If you are going to decode the last part i.e. the signature part,
        it is a binary string so you should use `None` as encoding here. Defaults to "utf-8".

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
    _user_mapping: dict = {
        "email": "mail",
        "username": "userPrincipalName",
        "given_name": "givenName",
        "family_name": "surname",
        "name": "displayName",
        "phone": "mobilePhone"
    }
    _description: str = "Microsoft Azure Authentication"

    def configure(self, app, router):
        super(AzureAuth, self).configure(app, router)

        # TODO: build the callback URL and append to routes
        self.base_url: str = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}"
        self.authorize_uri = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}/oauth2/v2.0/authorize"
        self.userinfo_uri = "https://graph.microsoft.com/v1.0/me"
        # issuer:
        self._issuer = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}"
        self._token_uri = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}/oauth2/v2.0/token"
        self.authority = AuthorityBuilder(AZURE_PUBLIC, "contoso.onmicrosoft.com")
        self.users_info = "https://graph.microsoft.com/v1.0/users"

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## loading redis connection:
        await super(AzureAuth, self).on_startup(app)
        self._pool = aioredis.ConnectionPool.from_url(
            REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""
        try:
            await self._pool.disconnect(inuse_connections=True)
        except Exception as e:  # pylint: disable=W0703
            logging.warning(e)

    async def get_payload(self, request):
        ctype = request.content_type
        if request.method == "POST":
            if ctype in (
                "multipart/mixed",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
            ):
                data = await request.post()
                if len(data) > 0:
                    user = data.get(self.user_attribute, None)
                    password = data.get(self.pwd_atrribute, None)
                    return [user, password]
                else:
                    return [None, None]
            elif ctype == "application/json":
                try:
                    data = await request.json()
                    user = data[self.user_attribute]
                    password = data[self.pwd_atrribute]
                    return [user, password]
                except Exception:
                    return [None, None]
        else:
            return [None, None]

    async def get_cache(self, request: web.Request, state: str):
        cache = msal.SerializableTokenCache()
        result = None
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            result = await redis.get(f"azure_cache_{state}")
        if result:
            cache.deserialize(result)
        return cache

    async def save_cache(
        self, request: web.Request, state: str, cache: msal.SerializableTokenCache
    ):
        if cache.has_state_changed:
            result = cache.serialize()
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                await redis.setex(f"azure_cache_{state}", AZURE_SESSION_TIMEOUT, result)

    def get_msal_app(self):
        authority = self._issuer if self._issuer else self.authority
        return msal.ConfidentialClientApplication(
            AZURE_ADFS_CLIENT_ID,
            authority=authority,
            client_credential=AZURE_ADFS_CLIENT_SECRET,
            validate_authority=True
            # token_cache=cache
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
                result = app.acquire_token_by_username_password(
                    user, pwd, Default_SCOPE
                )
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
                        userdata, uid = self.build_user_info(data)
                        # also, user information:
                        data = await self.validate_user_info(
                            request, uid, userdata, access_token
                        )
                        # Redirect User to HOME
                        return self.home_redirect(
                            request, token=data["token"], token_type="Bearer"
                        )
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
                            message = (
                                f"Azure {error}: {desc}, correlation id: {correlation}"
                            )
                            logging.exception(message)
                            raise web.HTTPForbidden(reason=message)
                except Exception as err:
                    raise web.HTTPForbidden(
                        reason=f"Azure: Invalid Response from Server {err}."
                    )
        else:
            domain_url = self.get_domain(request)
            self.redirect_uri = self.redirect_uri.format(
                domain=domain_url, service=self._service_name
            )
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
                    await redis.setex(
                        f"azure_auth_{state}", AZURE_SESSION_TIMEOUT, json_encoder(flow)
                    )
                login_url = flow["auth_uri"]
                return self.redirect(login_url)
            except Exception as err:
                raise AuthException(
                    f"Azure: Client doesn't have info for Authentication: {err}"
                ) from err

    async def auth_callback(self, request: web.Request):
        try:
            auth_response = dict(request.rel_url.query.items())
            state = None
            # SCOPE = ["https://graph.microsoft.com/.default"]
            try:
                state = auth_response["state"]
            except (TypeError, KeyError, ValueError):
                return self.failed_redirect(
                    request, error="MISSING_AUTH_NONCE"
                )
            try:
                async with aioredis.Redis(connection_pool=self._pool) as redis:
                    result = await redis.get(f"azure_auth_{state}")
                    flow = orjson.loads(result)
            except Exception:
                return self.failed_redirect(request, error="ERROR_RATE_LIMIT_EXCEEDED", message="ERROR_RATE_LIMIT_EXCEEDED")
            app = self.get_msal_app()
            try:
                result = app.acquire_token_by_auth_code_flow(
                    auth_code_flow=flow, auth_response=auth_response
                )
                if "token_type" in result:
                    token_type = result["token_type"]
                    access_token = result["access_token"]
                    # refresh_token = result['refresh_token']
                    id_token = result["id_token"]
                    claims = result["id_token_claims"]
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
                        userdata, uid = self.build_user_info(data)
                        userdata["id_token"] = id_token
                        userdata["claims"] = claims
                        data = await self.validate_user_info(
                            request, uid, userdata, access_token
                        )
                    except Exception as err:
                        logging.exception(
                            f"Azure: Error getting User information: {err}"
                        )
                        return self.failed_redirect(
                            request, error="ERROR_RESOURCE_NOT_FOUND", message=f"Azure: Error getting User information: {err}"
                        )
                    # Redirect User to HOME
                    return self.home_redirect(
                        request, token=data["token"], token_type=token_type
                    )
                elif "error" in result:
                    error = result["error"]
                    desc = result["error_description"]
                    message = f"Azure {error}: {desc}"
                    logging.exception(message)
                    return self.failed_redirect(
                        request, error="AUTHENTICATION_ERROR",
                        message="Failed to generate session token"
                    )
                else:
                    return self.failed_redirect(
                        request, error="ERROR_CONFIGURATION"
                    )
            except Exception as err:
                logging.exception(err)
                return self.failed_redirect(
                    request, error="ERROR_INVALID_REQUEST"
                )
        except Exception as err:
            logging.exception(err)
            return self.failed_redirect(
                request, error="ERROR_UNKNOWN"
            )

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
