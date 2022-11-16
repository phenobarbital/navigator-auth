"""Django Session Backend.

Navigator Authentication using Anonymous Backend
"""
import logging
import uuid
from aiohttp import web
from navigator_session import (
    AUTH_SESSION_OBJECT
)
# Authenticated Entity
from navigator_auth.identities import AuthUser, Guest
from .abstract import BaseAuthBackend

class AnonymousUser(AuthUser):
    first_name: str = 'Anonymous'
    last_name: str = 'User'


class NoAuth(BaseAuthBackend):
    """Basic Handler for No authentication."""
    userid_attribute: str = "userid"
    user_attribute: str = "userid"
    _ident: AuthUser = AnonymousUser

    async def check_credentials(self, request):
        """ Authentication and create a session."""
        return True

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements.
        """
        return True

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection.
        """
        return True

    def get_userdata(self, user = None):
        key = uuid.uuid4().hex
        userdata = {
            AUTH_SESSION_OBJECT: {
                "session": key,
                self.user_property: key,
                self.username_attribute: "Anonymous",
                "first_name": "Anonymous",
                "last_name": "User"
            }
        }
        return [ userdata, key ]

    async def authenticate(self, request):
        userdata, key = self.get_userdata()
        user = await self.create_user(
            userdata[AUTH_SESSION_OBJECT]
        )
        user.id = key
        user.add_group(Guest)
        user.set(self.username_attribute, 'Anonymous')
        logging.debug(f'User Created > {user}')
        payload = {
            self.session_key_property: key,
            self.user_property: None,
            self.username_attribute: "Anonymous",
            **userdata
        }
        token = self.create_jwt(data=payload)
        user.access_token = token
        await self.remember(
            request, key, userdata, user
        )
        return {
            "token": token,
            self.session_key_property: key,
            self.username_attribute: "Anonymous",
            **userdata
        }
