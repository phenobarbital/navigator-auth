"""Null Auth Backend.

Navigator Authentication using Anonymous Backend
"""
import logging
import uuid
from aiohttp import web
from navigator_session import AUTH_SESSION_OBJECT

# Authenticated Entity
from ..identities import AuthUser, Guest
from .abstract import BaseAuthBackend


class AnonymousUser(AuthUser):
    display_name: str = "Anonymous User"


class NoAuth(BaseAuthBackend):
    """Basic Handler for No authentication."""

    userid_attribute: str = "userid"
    user_attribute: str = "userid"
    _ident: AuthUser = AnonymousUser
    _description: str = "Anonymous authentication"
    _service_name: str = "anonymous"

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        return True

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""
        return True

    def get_userdata(self, user=None):
        key = uuid.uuid4().hex
        userdata = {
            AUTH_SESSION_OBJECT: {
                "session": key,
                self.user_property: key,
                self.username_attribute: f"Anonymous {key}",
                "display_name": "Anonymous User",
            }
        }
        return [userdata, key]

    async def authenticate(self, request):
        userdata, key = self.get_userdata()
        user = await self.create_user(userdata[AUTH_SESSION_OBJECT])
        user.id = key
        user.add_group(Guest)
        user.set(self.username_attribute, f"Anonymous {key}")
        logging.debug(
            f"User Created > {user}"
        )
        payload = {
            self.session_key_property: key,
            self.user_property: None,
            self.username_attribute: f"Anonymous {key}",
            **userdata,
        }
        token, exp, scheme = self._idp.create_token(data=payload, expiration=3600)
        user.access_token = token
        user.token_type = scheme
        user.expires_in = exp
        await self.remember(request, key, userdata, user)
        return {
            "token": token,
            self.session_key_property: key,
            self.username_attribute: f"Anonymous {key}",
            "expires_in": exp,
            "token_type": scheme,
            **userdata,
        }
