from asyncdb.models import Model
from navigator.views.model import ModelView, NotSet
from ...models import User
from ...conf import (
    AUTH_USER_MODEL,
    AUTH_USER_VIEW
)
from .passwd import set_basic_password


class UserManager(ModelView):
    """
    Main Class for Managing Users.
    TODO: Allow User editing own data.
    """

    model: Model = User
    get_model: Model = AUTH_USER_VIEW
    name: str = "Users"
    model_name: str = AUTH_USER_MODEL
    pk: str = "user_id"

    def required_by_put(self):
        return ['first_name', 'last_name', 'display_name', 'username', 'email']

    required_by_post = required_by_put

    async def _set_created_by(self, value, column, **kwargs):
        return await self.get_userid(session=self._session)

    async def _set_display_name(self, value, column, **kwargs):
        data = kwargs.get('data')
        if not value:
            try:
                return f"{data['first_name']} {data['last_name']}"
            except (KeyError, TypeError) as exc:
                raise NotSet(f"{exc}") from exc
        return value

    async def _set_password(self, value, column, **kwargs):
        # TODO: add checking complexity.
        if not value:
            raise NotSet()
        if value.startswith('pbkdf2_'):
            # already encrypted:
            return value
        return set_basic_password(value)

    async def _calculate_password(self, value, column, *args, **kwargs):
        """Used for Password Calculation when Update/Patch operations.
        """
        # TODO: add checking complexity.
        if not value:
            raise NotSet()
        if value.startswith('pbkdf2_'):
            # already encrypted:
            return value
        return set_basic_password(value)
