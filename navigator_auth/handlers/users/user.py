from typing import Optional

from asyncdb.models import Model
from navigator.views.model import NotSet
from ...models import User
from ...conf import AUTH_USER_MODEL, AUTH_USER_VIEW
from ..guard_hooks import GuardedModelViewHooks
from ..guards import OwnerOrSuperuserGuard
from ..handler import ModelHandler


class UserManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """User CRUD behind the owner-or-superuser guard (FEAT-107).

    Guard first in the MRO, as ``UserIdentityHandler`` (userattrs.py:363).

    * An owner may PATCH ``writable_by_owner`` on their own row.
    * A policy-approved superuser (``users_admin_access``) may PATCH/POST
      ``writable_by_admin`` and create through PUT with ``creatable_by_admin``.
    * ``privileged_columns`` are writable by NO CRUD path. Flags go through
      ``POST /api/v1/users/{id}/role`` (``users:grant_role``); passwords through
      ``UserSession.password_change`` / ``password_reset``. A user created here
      has no password until a superuser calls ``password_reset``.
    * Reads: a non-superuser sees only their own row.
    """

    model: Model = User
    get_model: Model = AUTH_USER_VIEW
    name: str = "Users"
    model_name: str = AUTH_USER_MODEL
    pk: str = "user_id"

    action_object: str = "user"
    owner_column: Optional[str] = "user_id"
    policy_name: str = "users_admin_access"
    superuser_actions = frozenset({"user:read", "user:create", "user:update", "user:delete"})
    writable_by_owner = frozenset({"first_name", "last_name", "display_name", "title", "avatar", "timezone"})
    writable_by_admin = writable_by_owner | frozenset({"is_active", "email", "alt_email"})
    #: username is set once, at creation, and never updated.
    creatable_by_admin = writable_by_admin | frozenset({"username"})
    privileged_columns = frozenset(
        {"is_superuser", "user_role", "is_staff", "password", "userid", "user_id", "created_at", "last_login"}
    )

    def required_by_put(self):
        """PUT creates on this base (navigator model.py:996-1007): subset creatable_by_admin."""
        return ["first_name", "last_name", "username", "email"]

    def required_by_post(self):
        """POST is an admin upsert (approved for create AND update): subset writable_by_admin."""
        return ["first_name", "last_name", "display_name"]

    async def _del_primary_data(self, args: dict):
        """Authorize the DELETE, then refuse deleting the acting user's own account.

        Account deletion through generic CRUD is destructive and can lock out
        the last administrator, so nobody (owner or admin) may remove their own
        row here (issue:36eea6f94200).
        """
        objid = await super()._del_primary_data(args)
        user_id, _ = await self.acting_user()
        if str(objid) == str(user_id):
            await self.audit_decision("user:delete", False, user_id, "self-delete through CRUD is not allowed")
            self._refuse()
        return objid

    async def _set_created_by(self, value, column, **kwargs):
        return await self.get_userid(session=self._session)

    async def _set_display_name(self, value, column, **kwargs):
        data = kwargs.get("data")
        if not value:
            try:
                return f"{data['first_name']} {data['last_name']}"
            except (KeyError, TypeError) as exc:
                raise NotSet(f"{exc}") from exc
        return value
