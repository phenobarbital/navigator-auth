from typing import Any
from aiohttp import web
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error
from navconfig.logging import logging
from ..conf import (
    SAML_PATH,
    SAML_SETTINGS,
    SAML_MAPPING
)
from .external import ExternalAuth


class SAMLAuth(ExternalAuth):
    """SAMLAuth.

    Description: Authentication Backend using SAML 2.0.
    """

    _service_name: str = "saml"
    user_attribute: str = "user"
    username_attribute: str = "username"
    userid_attribute: str = "object_id"
    pwd_atrribute: str = "password"
    _description: str = "SAML 2.0 Authentication"
    user_mapping: dict = SAML_MAPPING

    def configure(self, app):
        super(SAMLAuth, self).configure(app)
        # Custom routes for SAML:
        router = app.router
        # Metadata route
        router.add_route(
            "GET",
            f"/api/v1/auth/{self._service_name}/metadata",
            self.metadata,
            name=f"{self._service_name}_metadata",
        )

    async def _prepare_flask_request(self, request: web.Request) -> dict:
        data = {}
        if request.method == 'POST':
            data = await request.post()
            data = dict(data)

        url_data = request.rel_url
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': request.url.port,
            'script_name': request.path,
            'get_data': request.query.copy(),
            'post_data': data,
            # 'query_string': request.query_string
        }

    def _init_saml_auth(self, req: dict) -> OneLogin_Saml2_Auth:
        if SAML_SETTINGS:
            auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH, old_settings=SAML_SETTINGS)
        else:
            auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
        return auth

    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials.
        """
        # 1. Prepare Request
        req = await self._prepare_flask_request(request)
        auth = self._init_saml_auth(req)

        # 2. Get Redirect URL
        try:
            return_to = self.redirect_uri.format(
                domain=self.get_domain(request),
                service=self._service_name
            )
            # Check for redirect_uri in query params to save it directly or use a state
            qs = self.queryparams(request)
            redirect = qs.get("redirect_uri")
            if redirect:
                 # TODO: We might want to pass this as RelayState or save in session
                 pass

            # 3. Login
            auth_url = auth.login(return_to)
            return self.redirect(auth_url)
        except Exception as err:
            self.logger.exception(err)
            raise web.HTTPForbidden(
                reason=f"SAML: Unable to Authenticate: {err}"
            )

    async def auth_callback(self, request: web.Request):
        """auth_callback, Finish method for authentication.
        """
        req = await self._prepare_flask_request(request)
        auth = self._init_saml_auth(req)

        # Process the SAML Response
        auth.process_response()
        errors = auth.get_errors()
        if not errors:
            if auth.is_authenticated():
                # Get User Data
                user_data = auth.get_attributes()
                name_id = auth.get_nameid()
                session_index = auth.get_session_index()

                # Flatten attributes (OneLogin returns lists)
                # We take the first element of the list for each attribute
                flat_data = {}
                for key, val in user_data.items():
                   if isinstance(val, list) and len(val) > 0:
                       flat_data[key] = val[0]
                   else:
                       flat_data[key] = val

                # Map attributes using user_mapping
                # Also include name_id as a fallback or primary ID
                flat_data['name_id'] = name_id
                flat_data['session_index'] = session_index

                self.logger.debug(f"SAML Attributes: {flat_data}")

                try:
                    # Build User Info
                    userdata, uid = self.build_user_info(
                        userdata=flat_data,
                        token=name_id, # SAML doesn't use tokens like OIDC, using NameID as token placeholder
                        mapping=self.user_mapping
                    )
                    
                    # Validate and Create Session
                    # We pass 'name_id' as token basically
                    data = await self.validate_user_info(
                        request, uid, userdata, token=name_id
                    )
                    
                    # Redirect User to HOME
                    # Check for RelayState if we used it for redirection
                    internal_redirect = None
                    if 'RelayState' in req['post_data']:
                        internal_redirect = req['post_data']['RelayState']
                        if internal_redirect == self.redirect_uri.format(domain=self.get_domain(request), service=self._service_name):
                             # Recursive redirect protection
                             internal_redirect = None

                    try:
                        token = data["token"]
                    except (KeyError, TypeError):
                        token = None

                    return self.home_redirect(
                        request,
                        token=token,
                        token_type="Bearer",
                        uri=internal_redirect
                    )

                except Exception as err:
                    self.logger.exception(f"SAML: Error getting User information: {err}")
                    return self.failed_redirect(
                        request, error="ERROR_USER_INFO",
                        message=f"Error processing user info: {err}"
                    )
            else:
                 return self.failed_redirect(
                    request, error="NOT_AUTHENTICATED",
                    message="User not authenticated in SAML response"
                )
        else:
            self.logger.error(f"SAML Errors: {errors}")
            reason = auth.get_last_error_reason()
            return self.failed_redirect(
                request, error="SAML_ERROR",
                message=f"SAML Error: {errors}, Reason: {reason}"
            )

    async def metadata(self, request: web.Request):
        """Expose SP Metadata."""
        req = await self._prepare_flask_request(request)
        auth = self._init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            return web.Response(text=metadata, content_type='text/xml')
        else:
            return web.Response(text=', '.join(errors), status=500)

    async def logout(self, request: web.Request):
        """logout, forgot credentials and remove the user session."""
        # TODO: Implement SAML Single Logout if needed
        # For now just clear local session (handled by super().logout usually?)
        # BaseAuthBackend doesn't implement logout logic, just the interface
        # ExternalAuth uses api/v1/logout, but doesn't actually clear session itself in `logout` method?
        # Let's check adfs.py logout.
        # adfs.py redirects to end_session_endpoint.

        req = await self._prepare_flask_request(request)
        auth = self._init_saml_auth(req)
        
        # We should ideally have the name_id and session_index from the user session
        # But for now, we can just initiate a logout without them (SP-initiated logout)
        # or just redirect to IdP logout.
        
        # Let's try to get user session to find name_id/session_index if we saved them.
        # But ExternalAuth doesn't easily expose the current session reading here.

        return_to = self.get_domain(request) + "/" 
        url = auth.logout(return_to=return_to)
        return web.HTTPFound(url)


    async def finish_logout(self, request: web.Request):
        """finish_logout, Finish Logout Method."""
        # Handles LogoutResponse from IdP
        pass

    async def check_credentials(self, request: web.Request):
        """Check the validity of the current issued credentials."""
        return True
