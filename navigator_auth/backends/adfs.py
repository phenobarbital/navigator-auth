"""ADFSAuth.

Description: Backend Authentication/Authorization using Okta Service.
"""
import base64
from aiohttp import web
import jwt

# needed by ADFS
import requests
import redis.asyncio as aioredis
import requests.adapters
from ..exceptions import AuthException
from ..conf import (
    ADFS_SERVER,
    ADFS_CLIENT_ID,
    ADFS_TENANT_ID,
    ADFS_RESOURCE,
    ADFS_DEFAULT_RESOURCE,
    ADFS_AUDIENCE,
    ADFS_SCOPES,
    ADFS_ISSUER,
    USERNAME_CLAIM,
    GROUP_CLAIM,
    ADFS_CLAIM_MAPPING,
    ADFS_CALLBACK_REDIRECT_URL,
    ADFS_LOGIN_REDIRECT_URL,
    AZURE_SESSION_TIMEOUT,
    AZURE_AD_SERVER,
    exclude_list,
    ADFS_MAPPING,
    REDIS_AUTH_URL
)
from .jwksutils import get_public_key
from .external import ExternalAuth
from ..libs.json import json_encoder, json_decoder

_jwks_cache = {}


class ADFSAuth(ExternalAuth):
    """ADFSAuth.

    Description: Authentication Backend using
    Active Directory Federation Service (ADFS).
    """

    _service_name: str = "adfs"
    user_attribute: str = "user"
    userid_attribute: str = "upn"
    username_attribute: str = "username"
    pwd_atrribute: str = "password"
    version = "v1.1"
    _description: str = "SSO (Active Directory FS)"
    user_mapping: dict = ADFS_MAPPING

    def configure(self, app):
        router = app.router
        # URIs:
        if ADFS_TENANT_ID:
            self.server = AZURE_AD_SERVER
            self.tenant_id = ADFS_TENANT_ID
            self.username_claim = "upn"
            self.groups_claim = "groups"
            self.claim_mapping = ADFS_CLAIM_MAPPING
            self.discovery_oid_uri = f"https://login.microsoftonline.com/{self.tenant_id}/.well-known/openid-configuration"
        else:
            self.server = ADFS_SERVER
            self.tenant_id = "adfs"
            self.username_claim = USERNAME_CLAIM
            self.groups_claim = GROUP_CLAIM
            self.claim_mapping = ADFS_CLAIM_MAPPING
            self.discovery_oid_uri = (
                f"https://{self.server}/adfs/.well-known/openid-configuration"
            )
            self._discovery_keys_uri = f"https://{self.server}/adfs/discovery/keys"

        self.base_uri = f"https:://{self.server}/"
        self.end_session_endpoint = (
            f"https://{self.server}/{self.tenant_id}/ls/?wa=wsignout1.0"
        )
        self._issuer = f"https://{self.server}/{self.tenant_id}/services/trust"
        self.authorize_uri = f"https://{self.server}/{self.tenant_id}/oauth2/authorize/"
        self._token_uri = f"https://{self.server}/{self.tenant_id}/oauth2/token"
        self.userinfo_uri = f"https://{self.server}/{self.tenant_id}/userinfo"

        if ADFS_LOGIN_REDIRECT_URL is not None:
            login = ADFS_LOGIN_REDIRECT_URL
        else:
            login = f"/api/v1/auth/{self._service_name}"

        if ADFS_CALLBACK_REDIRECT_URL is not None:
            callback = ADFS_CALLBACK_REDIRECT_URL
            self.redirect_uri = "{domain}" + callback
            # Excluding Redirect for Authorization
            exclude_list.append(self.redirect_uri)
        else:
            callback = f"/auth/{self._service_name}/callback/"
            self.redirect_uri = "{domain}" + callback
            exclude_list.append(callback)
        # Login and Redirect Routes:
        router.add_route(
            "GET", login, self.authenticate, name=f"{self._service_name}_login"
        )
        # finish login (callback)
        router.add_route(
            "*",
            callback,
            self.auth_callback,
            name=f"{self._service_name}_callback_login",
        )
        super(ADFSAuth, self).configure(app)

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## loading redis connection:
        await super(ADFSAuth, self).on_startup(app)
        self._pool = aioredis.ConnectionPool.from_url(
            REDIS_AUTH_URL,
            decode_responses=True,
            encoding="utf-8"
        )

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""
        try:
            await self._pool.disconnect(
                inuse_connections=True
            )
        except Exception as e:  # pylint: disable=W0703
            pass

    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials.

        Description: This function returns the ADFS authorization URL.
        """
        domain_url = self.get_domain(request)
        self.redirect_uri = self.redirect_uri.format(
            domain=domain_url, service=self._service_name
        )
        ## getting Finish Redirect URL
        self.get_finish_redirect_url(request)
        qs = self.queryparams(request)
        redirect = None
        if "redirect_uri" in qs:
            redirect = qs.pop("redirect_uri")
        try:
            self.state = base64.urlsafe_b64encode(self.redirect_uri.encode()).decode()
            resource = ADFS_RESOURCE if ADFS_RESOURCE else ADFS_DEFAULT_RESOURCE
            query_params = {
                "client_id": ADFS_CLIENT_ID,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "resource": resource,
                "response_mode": "query",
                "state": self.state,
                "scope": ADFS_SCOPES,
            }
            params = requests.compat.urlencode(query_params)
            login_url = f"{self.authorize_uri}?{params}"
            # Saving redirect info on Redis:
            flow = {}
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                flow['internal_redirect'] = redirect
                await redis.setex(
                    f"adfs_auth_{self.state}",
                    600,
                    json_encoder(flow)
                )
            # Step A: redirect
            return self.redirect(login_url)
        except Exception as err:
            self.logger.exception(err)
            raise AuthException(
                f"Client doesn't have info for ADFS Authentication: {err}"
            ) from err

    async def auth_callback(self, request: web.Request):
        domain_url = self.get_domain(request)
        self.redirect_uri = self.redirect_uri.format(
            domain=domain_url, service=self._service_name
        )
        try:
            auth_response = dict(request.rel_url.query.items())
            if 'error' in auth_response:
                self.logger.exception(
                    f"ADFS: Error getting User information: {auth_response!r}"
                )
                raise web.HTTPForbidden(
                    reason=f"ADFS: Unable to Authenticate: {auth_response!r}"
                )
            authorization_code = auth_response["code"]
            state = None
            try:
                state = auth_response["state"]
            except (TypeError, KeyError, ValueError):
                return self.failed_redirect(
                    request, error="MISSING_AUTH_NONCE",
                    message="Missing Auth Nonce"
                )
            flow = {}
            print('STATE > ', state)
            internal_redirect = None
            # making validation with previous state
            try:
                async with aioredis.Redis(connection_pool=self._pool) as redis:
                    result = await redis.get(f"adfs_auth_{state}")
                    flow = json_decoder(result)
                    internal_redirect = flow.pop(
                        'internal_redirect',
                        None
                    )
            except Exception:
                pass
        except Exception as err:
            raise web.HTTPForbidden(
                reason=f"ADFS: Invalid Callback response: {err}: {auth_response}"
            ) from err
        self.logger.debug(
            f"Authorization Code: {authorization_code}"
        )
        # getting an Access Token
        query_params = {
            "code": authorization_code,
            "client_id": ADFS_CLIENT_ID,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
            "scope": ADFS_SCOPES,
        }
        self.logger.debug(
            f'Token Params: {query_params!r}'
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            exchange = await self.post(
                self._token_uri, data=query_params, headers=headers
            )
            if "error" in exchange:
                error = exchange.get("error")
                desc = exchange.get("error_description")
                message = f"ADFS {error}: {desc}"
                self.logger.exception(message)
                raise web.HTTPForbidden(reason=message)
            else:
                ## processing the exchange response:
                access_token = exchange["access_token"]
                token_type = exchange["token_type"]  # ex: Bearer
                # id_token = exchange["id_token"]
                self.logger.debug(
                    f"Received access token: {access_token}"
                )
        except Exception as err:
            raise web.HTTPForbidden(
                reason=f"Invalid Response from Token Server {err}."
            )
        try:
            # decipher the Access Token:
            # getting user information:
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require_exp": False,
                "require_iat": False,
                "require_nbf": False,
            }
            public_key = get_public_key(
                access_token, self.tenant_id, self.discovery_oid_uri
            )
            # Validate token and extract claims
            data = jwt.decode(
                access_token,
                key=public_key,
                algorithms=["RS256", "RS384", "RS512"],
                verify=True,
                audience=ADFS_AUDIENCE,
                issuer=ADFS_ISSUER,
                options=options,
            )
            try:
                del data['aud']
                del data['iss']
                del data['iat']
                del data['exp']
            except KeyError:
                pass
        except Exception as e:
            raise web.HTTPForbidden(
                reason=f"Unable to decode JWT token {e}."
            )
        try:
            self.logger.debug(
                f'Received User: {data!r}'
            )
            self.logger.debug(
                f'Backend Mapping: {self.user_mapping}'
            )
            userdata, uid = self.build_user_info(
                userdata=data,
                token=access_token,
                mapping=self.user_mapping
            )
            userdata[self.username_attribute] = userdata[self.userid_attribute]
            data = await self.validate_user_info(
                request, uid, userdata, access_token
            )
        except Exception as err:
            self.logger.exception(
                f"ADFS: Error getting User information: {err}"
            )
            raise web.HTTPForbidden(
                reason=f"ADFS: Error with User Information: {err}"
            )
        # Redirect User to HOME
        try:
            token = data["token"]
        except (KeyError, TypeError):
            token = None
        return self.home_redirect(
            request,
            token=token,
            token_type=token_type,
            uri=internal_redirect
        )

    async def logout(self, request):
        # first: removing the existing session
        # second: redirect to SSO logout
        self.logger.debug(
            f"ADFS LOGOUT URI: {self.end_session_endpoint}"
        )
        return web.HTTPFound(self.end_session_endpoint)

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
