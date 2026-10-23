from typing import Any
from asyncdb.exceptions import (
    NoDataFound
)
from asyncdb.exceptions import DriverError
from navigator_session import (
    get_session,
    AUTH_SESSION_OBJECT
)
from ..models import (
    UserAccount, UserIdentity, VwUserIdentity
)
from ..conf import (
    AUTH_USER_IDENTITY_MODEL
)
# from .model import ModelHandler
from .handler import ModelHandler


class UserAccountHandler(ModelHandler):
    model: Any = UserAccount
    name: str = "User Account"
    pk: str = "account_id"
    #: G9: the provider is bound as $1, never interpolated. The previous form
    #: inlined it inside a quoted literal, so a provider of ``x' OR 1=1 --``
    #: rewrote the statement.
    social_network: str = (
        "SELECT social_url FROM auth.social_networks "
        "WHERE social_network = $1"
    )

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    async def _set_address(self, value, column, data):
        try:
            userid = data['uid']
        except KeyError:
            return self.error(
                reason=f"Invalid User ID for {self.name}", status=410
            )
        try:
            provider = data['provider']
        except KeyError:
            provider = None
        if provider:
            try:
                async with await self.handler(request=self.request) as conn:
                    result = await conn.fetchval(
                        self.social_network, provider, column='social_url'
                    )
                    if result:
                        return result.format(uid=userid)
            except DriverError:
                pass
        return None

class UserIdentityHandler(ModelHandler):
    model: Any = UserIdentity
    model_name: str = AUTH_USER_IDENTITY_MODEL
    name: str = "User Identity"
    pk: str = "identity_id"

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)
