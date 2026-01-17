"""Oauth2 Provider.

Navigator as a Oauth2 Provider.
"""
from datetime import datetime, timedelta
from typing import Optional, Any
from collections.abc import Awaitable
import importlib
from urllib.parse import urlparse
from requests.models import PreparedRequest
from aiohttp import web
from datamodel.exceptions import ValidationError
from navconfig import config
import jsonpickle
from ...identities import AuthUser
from ...conf import (
    AUTH_LOGIN_FAILED_URI,
    AUTH_LOGOUT_REDIRECT_URI,
    AUTH_MISSING_ACCOUNT,
    AUTH_SUCCESSFUL_CALLBACKS,
    PREFERRED_AUTH_SCHEME,
    exclude_list,
    REDIS_URL
)
from navigator_session import get_session
from ...exceptions import (
    FailedAuth,

    UserNotFound,
    InvalidAuth,
)
from ...responses import JSONResponse
from ..abstract import BaseAuthBackend
from .models import OauthUser, OauthRefreshToken
from .client_backend import (
    PostgresClientStorage,
    RedisClientStorage,
    MemoryClientStorage
)
from .code_backend import AuthorizationCodeStorage, RefreshTokenStorage

class Oauth2Provider(BaseAuthBackend):
    """Oauth2Provider.

    Navigator-Auth as a Oauth2 provider.
    """

    user_attribute: str = "user"
    username_attribute: str = "username"
    pwd_atrribute: str = "password"
    user_mapping: dict = {}
    _ident: AuthUser = OauthUser
    _success_callbacks: Optional[list[str]] = AUTH_SUCCESSFUL_CALLBACKS
    _callbacks: Optional[list[Any]] = None

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        super().__init__(
            user_attribute,
            userid_attribute,
            password_attribute,
            **kwargs
        )
        self.base_url: str = ""
        ## TODO: customize URLs
        self.login_uri: str = "/oauth2/login"
        self.authorize_uri: str = "/oauth2/authorize"
        self.token_uri: str = "/oauth2/token"
        self.userinfo_uri: str = "/oauth2/userinfo"
        self.logout_uri: str = "/oauth2/logout"
        self.consent_uri: str = "/oauth2/consent"
        self.login_failed_uri = AUTH_LOGIN_FAILED_URI
        self.logout_redirect_uri = AUTH_LOGOUT_REDIRECT_URI or '/oauth2/login'
        self.redirect_uri = None
        self.client_storage = None
        self.code_storage = None
        self.refresh_token_storage = None

    def configure(self, app):
        router = app.router
        # start login (Authorize)
        router.add_route(
            "*",
            self.authorize_uri,
            self.authorize,
            name="nav_oauth2_authorize",
        )
        router.add_route(
            "*",
            "/oauth2/authorize/",
            self.authorize,
            name="nav_oauth2_authorize_alt",
        )
        ## added to excluded list:
        exclude_list.append(self.authorize_uri)
        exclude_list.append(
            "/oauth2/authorize/"
        )
        ## login
        router.add_route(
            "*",
            self.login_uri,
            self.auth_login,
            name="nav_oauth2_login",
        )
        exclude_list.append(self.login_uri)
        
        # Consent
        router.add_route(
            "*",
            self.consent_uri,
            self.consent,
            name="nav_oauth2_consent",
        )
        
        # Token Request
        router.add_route(
            "*",
            self.token_uri,
            self.token_request,
            name="nav_oauth2_token_request",
        )
        exclude_list.append(self.token_uri)
        # User Info
        router.add_route(
            "GET",
            self.userinfo_uri,
            self.userinfo,
            name="nav_oauth2_userinfo",
        )
        # logout process
        router.add_route(
            "GET",
            self.logout_uri,
            self.logout,
            name="nav_oauth2_api_logout",
        )
        # Logout redirection
        router.add_route(
            "GET",
            self.logout_redirect_uri,
            self.finish_logout,
            name="nav_oauth2_complete_logout",
        )
        exclude_list.append(self.logout_redirect_uri)
        super(Oauth2Provider, self).configure(app)

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## geting User Model for saving users:
        ## TODO: Migrate Code to IdP
        if AUTH_MISSING_ACCOUNT == "create":
            self._user_model = self._idp.user_model
        else:
            self._user_model = None
        ## Using Startup for detecting and loading functions.
        if self._success_callbacks:
            self.get_successful_callbacks()
            
        # Initialize Client Storage
        client_store_type = config.get('OAUTH2_CLIENT_STORAGE', fallback='postgres')
        if client_store_type == 'redis':
             self.client_storage = RedisClientStorage(REDIS_URL)
        elif client_store_type == 'memory':
             self.client_storage = MemoryClientStorage()
        else:
             self.client_storage = PostgresClientStorage()
             
        # Initialize Code Storage
        self.code_storage = AuthorizationCodeStorage(REDIS_URL)
        self.refresh_token_storage = RefreshTokenStorage(REDIS_URL)

    async def on_cleanup(self, app: web.Application):
        pass

    def get_successful_callbacks(self) -> list[Awaitable]:
        fns = []
        for fn in self._success_callbacks:
            try:
                pkg, module = fn.rsplit(".", 1)
                mod = importlib.import_module(pkg)
                obj = getattr(mod, module)
                fns.append(obj)
            except ImportError as e:
                raise RuntimeError(
                    f"Auth Callback: Error getting Callback Function: {fn}, {e!s}"
                ) from e
        self._callbacks = fns

    def get_domain(self, request: web.Request) -> str:
        uri = urlparse(str(request.url))
        domain_url = f"{PREFERRED_AUTH_SCHEME}://{uri.netloc}"
        self.logger.debug(
            f"OAUTH2 DOMAIN URL: {domain_url}"
        )
        return domain_url

    def prepare_url(self, url: str, params: dict = None):
        req = PreparedRequest()
        req.prepare_url(url, params)
        return req.url

    def redirect(self, uri: str, location: bool = False):
        """redirect.
        Making the redirection Any External Page.
        """
        self.logger.debug(f"Redirect URI: {uri}")
        if location is True:
            raise web.HTTPFound(location=uri)
        raise web.HTTPFound(uri)

    async def get_payload(self, request):
        ctype = request.content_type
        if request.method == "POST":
            if ctype in (
                "multipart/mixed",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
            ):
                data = await request.post()
            elif ctype == "application/json":
                try:
                    data = await request.json()
                except Exception:
                    self.logger.error(
                        "Oauth2: Error getting JSON data from request"
                    )
        else:
            ## getting data from query string.
            data = {
                key: val for (key, val) in request.query.items()
            }
        return data

    async def check_session(self, request):
        """Check if Session is Active and Authenticated."""
        try:
             session = request.get('session')
             if not session:
                 # If session is not in request (e.g. excluded from middleware), try to load it
                 try:
                    session = await get_session(request, None, new=False, ignore_cookie=False)
                 except Exception:
                    pass
             
             if session:
                  # Check for user in session
                  # We rely on 'user' key being present as set in auth_login
                  if 'user' in session:
                       return session['user']
        except Exception as e:
             self.logger.warning(f"Error checking session: {e}")
        return None

    async def validate_client(self, client_id, redirect_uri=None, request=None):
        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
             return None
        if redirect_uri:
             if redirect_uri not in client.redirect_uris:
                 return None
        return client

    async def authorize(self, request: web.Request):
        """Starts a Oauth2 Code Flow."""
        data = await self.get_payload(request)
        
        # 1. Validate Client
        client_id = data.get('client_id')
        if not client_id:
             raise web.HTTPBadRequest(reason="Missing Client ID")
             
        redirect_uri = data.get('redirect_uri')
        client = await self.validate_client(client_id, redirect_uri, request=request)
        if not client:
             raise web.HTTPBadRequest(reason="Invalid Client ID or Redirect URI")

        # 2. Check User Session
        session = await self.check_session(request)
        if not session:
             # Redirect to Login
             location = request.app.router['nav_oauth2_login'].url_for()
             payload = {
                 "action_url": str(location),
                 **data
             }
             url = location.with_query(**payload)
             self.redirect(url, location=True)
             
        # 3. User is authenticated. Show Consent.
        location = request.app.router['nav_oauth2_consent'].url_for()
        payload = {
             **data,
             "scope": data.get('scope', 'default'),
             "client_name": client.client_name
        }
        url = location.with_query(**payload)
        self.redirect(url, location=True)

    async def consent(self, request: web.Request):
        data = await self.get_payload(request)
        if request.method == 'GET':
             # Show Consent UI
             return await self._parser.view(
                 filename='oauth/consent.html',
                 params=data
             )
        elif request.method == 'POST':
             # Process Consent
             action = data.get('action')
             if action == 'approve':
                  client_id = data.get('client_id')
                  redirect_uri = data.get('redirect_uri')
                  
                  from .models import OauthAuthorizationCode
                  from uuid import uuid4
                  
                  auth_code = str(uuid4())
                  # We need the client object
                  client = await self.client_storage.get_client(client_id, request=request)
                  
                  code_obj = OauthAuthorizationCode(
                       client_id=client,
                       code=auth_code,
                       redirect_uri=redirect_uri,
                       scope=data.get('scope'),
                       state=data.get('state', ''),
                       response_type='code'
                  )
                  await self.code_storage.save_code(code_obj)
                  
                  payload = {
                     "code": auth_code,
                     "state": data.get('state')
                  }
                  # Redirect back to client
                  uri = self.prepare_url(redirect_uri, params=payload)
                  self.redirect(uri)
                  
             else:
                  # Denied
                  redirect_uri = data.get('redirect_uri')
                  uri = self.prepare_url(redirect_uri, params={"error": "access_denied"})
                  self.redirect(uri)

    async def get_login_form(self, request: web.Request):
        ctype = request.content_type
        if request.method == "POST":
            if ctype in (
                "multipart/mixed",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
            ):
                data = await request.post()
            elif ctype == "application/json":
                try:
                    data = await request.json()
                except Exception as err:
                    self.logger.error(
                        f"Oauth2: Error getting JSON data from request: {err}"
                    )
            # TODO: configurable username and password attributes
            username = data.get('username', None)
            password = data.get('password', None)
            if None in [username, password]:
                self.logger.error(
                    "Oauth2: Invalid username or password"
                )
                raise self.auth_error(
                    reason="Oauth2: Invalid username or password",
                    status=400
                )
            return (username, password, data)
        else:
            raise self.auth_error(
                reason=f'Invalid HTTP Form Data: {request.method}',
                status=400
            )

    async def auth_login(self, request: web.Request):
        """auth_login.
            Login Page for User Authentication.
        """
        if request.method == "GET":
            ## Render Login Page:
            data = {key: val for (key, val) in request.query.items()}
            return await self._parser.view(
                filename='oauth/login.html',
                params=data
            )
        elif request.method == "POST":
            ## User Authentication.
            username, password, data = await self.get_login_form(request)
            if not password and not username:
                raise web.HTTPBadRequest(
                    reason="Auth: Invalid Credentials"
                )
            try:
                user = await self._idp.authenticate_credentials(
                    login=username,
                    password=password
                )
            except (FailedAuth, UserNotFound) as exc:  # pylint: disable=W0706
                raise web.HTTPBadRequest(
                    reason=f"Auth: User not Found {exc}"
                )
            except (ValidationError, InvalidAuth) as exc:
                raise web.HTTPBadRequest(
                    reason=f"Auth: User Invalid {exc}"
                )
            except Exception as exc:
                raise web.HTTPBadRequest(
                    reason=f"Auth: Exception {exc}"
                )
            
            # Authenticated!
            # user is a OauthUser/AuthUser object.
            
            # 1. Prepare Redirect Response
            redirect_uri = data.get('redirect_uri')
            client_id = data.get('client_id')
            state = data.get('state')
            scope = data.get('scope')
            
            location = request.app.router['nav_oauth2_authorize'].url_for()
            payload = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "scope": scope,
                "response_type": "code"
            }
            url = location.with_query(**payload)
            response = web.HTTPFound(url)
            
            # 2. Create/Persist Session
            try:
                # We need to get the session handler from AuthHandler
                auth_handler = request.app.get('auth')
                if auth_handler:
                    # session storage expects a dict usually, but check implementation.
                    # AuthHandler checks 'user' in session.
                    # We can pass the user object if session backend supports pickling or dict.
                    # Usually we pass a dict of user data.
                    
                    if hasattr(user, 'to_dict'):
                        user_data = user.to_dict()
                    elif hasattr(user, 'model_dump'):
                         user_data = user.model_dump()
                    else:
                        user_data = user.__dict__

                    # We wrap it in a structure if needed, or just pass user_data.
                    # AuthHandler.get_session_user uses session.decode('user').
                    # So we should probably store {'user': user_data} or let storage handle it.
                    
                    # looking at auth.py: 
                    # await self._session.storage.load_session(request, userdata, response=response)
                    # And get_session_user does: user = session.decode(name) -> "user"
                    
                    # So we should probably pass the user data dict and let session store it? 
                    # Or does load_session take the whole session data?
                    # "load_session(request, data, response)"
                    
                    # Let's save the user object under 'user' key if possible, or usually just the user data.
                    # If we look at `api_login` in auth.py: `userdata` is passed to `load_session`.
                    # And `get_session` returns `userdata`.
                    
                    # It seems `load_session` saves `data`.
                    # And `get_session_user` expects to find "user" inside the session?
                    # Wait, `get_session_user` -> `session.decode(name)`.
                    
                    # If we save `user_data` (dict) as the session data.
                    # Then `session.decode('user')` would look for 'user' key in that dict?
                    
                    # Safest is to store {'user': user_data}.
                    # We MUST encode it because SessionData.decode expects a string/jsonpickle
                    # We encode the User Object (Pydantic Model) directly, not the dict
                    encoded_user = jsonpickle.encode(user)
                    session_data = {'user': encoded_user}
                    session = await auth_handler.session.storage.load_session(request, session_data, response=response, new=True)
                    if session:
                        session['user'] = encoded_user # Ensure session is updated
                    
            except Exception as e:
                self.logger.error(f"Error creating session: {e}")
                
            return response

        else:
            return self.auth_error(
                reason=f'Invalid HTTP Login Method: {request.method}',
                status=400
            )

    async def token_request(self, request):
        payload = await self.get_payload(request)
        grant_type = payload.get('grant_type')
        
        if grant_type == 'authorization_code':
            code = payload.get('code', None)
            if not code:
                return self.auth_error(reason='Access Denied', status=403)
                
            redirect_uri = payload.get('redirect_uri')
            client_id = payload.get('client_id')
            
            # Verify code
            auth_code = await self.code_storage.get_code(code)
            if not auth_code:
                 return self.auth_error(reason='Invalid Code', status=403)
            
            if auth_code.client_id.client_id != client_id:
                 return self.auth_error(reason='Invalid Client', status=403)
            
            if auth_code.redirect_uri != redirect_uri:
                 return self.auth_error(reason='Invalid Redirect URI', status=403)
                 
            # Consume Code
            await self.code_storage.delete_code(code)
            
            # Generate Tokens
            # Ensure payload is a dict (not MultiDictProxy) for mutability
            token_payload = dict(payload)
            access_token, exp, scheme = self._idp.create_token(token_payload)
            refresh_token_str = self._idp.create_refresh_token()
            
            # Save Refresh Token
            rt = OauthRefreshToken(
                 client_id=auth_code.client_id,
                 refresh_token=refresh_token_str,
                 scope=auth_code.scope,
                 expires_at=datetime.now() + timedelta(days=30),
                 issued_at=datetime.now()
            )
            await self.refresh_token_storage.save_token(rt)
            
            response = {
                "access_token": access_token,
                "refresh_token": refresh_token_str,
                "token_type": scheme,
                "expires_in": exp
            }
            return JSONResponse(response, status=200)
            
        elif grant_type == 'client_credentials':
            client_id = payload.get('client_id')
            client_secret = payload.get('client_secret')
            
            client = await self.client_storage.get_client(client_id, request=request)
            if not client:
                 return self.auth_error(reason='Invalid Client', status=403)
                 
            if client.client_secret != client_secret:
                 return self.auth_error(reason='Invalid Secret', status=403)
            
            # App-Only Token
            token_payload = {
                "user_id": client.user.user_id, # On behalf of user
                "client_id": client_id,
                "aud": "app" 
            }
            
            # TODO: Set duration to 2 hours
            access_token, exp, scheme = self._idp.create_token(token_payload)
            
            response = {
                "access_token": access_token,
                "token_type": scheme,
                "expires_in": exp
            }
            return JSONResponse(response, status=200)
            
        elif grant_type == 'refresh_token':
            refresh_token = payload.get('refresh_token')
            client_id = payload.get('client_id')
            client_secret = payload.get('client_secret')
            
            if not refresh_token:
                 return self.auth_error(reason='Missing Refresh Token', status=400)

            # Validate Client
            client = await self.client_storage.get_client(client_id, request=request)
            if not client:
                 return self.auth_error(reason='Invalid Client', status=403)
            
            if client_secret and client.client_secret != client_secret:
                 return self.auth_error(reason='Invalid Secret', status=403)
                 
            # Verify Refresh Token
            rt = await self.refresh_token_storage.get_token(refresh_token)
            if not rt:
                 return self.auth_error(reason='Invalid Refresh Token', status=403)

            if rt.client_id.client_id != client_id:
                 return self.auth_error(reason='Invalid Client for this Token', status=403)
                 
            if rt.revoked:
                 return self.auth_error(reason='Token Revoked', status=403)

            if rt.expires_at < datetime.now():
                 return self.auth_error(reason='Token Expired', status=403)
            
            # Generate New Access Token
            # We use the user_id from the original refresh token's user (if available) or scope
            # The refresh token model in models.py (OauthRefreshToken) has client_id which is OauthClient.
            # OauthClient has user (OauthUser).
            
            user = rt.client_id.user
            token_payload = {
                "user_id": user.user_id,
                "client_id": client_id,
                "scope": rt.scope
            }
            
            access_token, exp, scheme = self._idp.create_token(token_payload)
            
            # Optionally rotate refresh token
            # For now, we keep the same refresh token until it expires
            
            response = {
                "access_token": access_token,
                "token_type": scheme,
                "expires_in": exp,
                 # We can return the same refresh token or a new one. 
                 # If we don't return it, they use the old one.
                 "refresh_token": refresh_token
            }
            return JSONResponse(response, status=200)

        else:
             return self.auth_error(reason='Unsupported Grant Type', status=400)

    async def userinfo(self, request):
        pass

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
