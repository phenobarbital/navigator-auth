from typing import Optional
from datamodel import BaseModel
from ..models import Permission
from ..conf import AUTH_PERMISSION_MODEL
from .guards import OwnerOrSuperuserGuard
from .model import ModelHandler


class PermissionHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Superuser-only CRUD over ``auth.permissions`` (FEAT-107).

    Sits on the LOCAL ``handlers/model.py`` base, which has no ``_pre_*``
    hooks — so, as in ``PartnerKeyHandler``, the guard is invoked at the top
    of every verb. No owner column: the superuser path is the only path.
    Stays on the plain ``superuser`` policy: nothing authorizes by permission
    name (spec §8).
    """

    model: BaseModel = Permission
    model_name: str = AUTH_PERMISSION_MODEL
    name: str = "Permissions"
    pk: str = "permission_id"

    owner_column: Optional[str] = None
    policy_name: str = "permissions_admin_access"
    superuser_actions = frozenset(
        {"permission:read", "permission:create", "permission:update", "permission:delete"}
    )
    writable_by_admin = frozenset({"permission", "description"})
    privileged_columns = frozenset({"permission_id", "created_at"})

    def _meta_requested(self) -> bool:
        try:
            return self.match_parameters(self.request).get("meta") == ":meta"
        except (AttributeError, KeyError, TypeError):
            return False

    async def _client_keys(self) -> frozenset[str]:
        """Raw body keys; 400 unless the body is a JSON object (the local base inserts ``model(**data)``)."""
        try:
            data = await self.json_data()
        except Exception:  # pylint: disable=W0703
            data = None
        if not isinstance(data, dict):
            self.error(response={"error": "A JSON object body is required"}, status=400)
        return frozenset(data)

    async def head(self):
        await self.authorize_row("permission:read", None)
        return await super().head()

    async def get(self):
        await self.authorize_row("permission:read", None)
        return await super().get()

    async def put(self):
        """The local base's put ALWAYS inserts (model.py:216-250)."""
        keys = await self._client_keys()
        await self.authorize_row("permission:create", None, payload=keys, creating=True)
        return await super().put()

    async def patch(self):
        if self._meta_requested():
            await self.authorize_row("permission:read", None)
            return await super().patch()
        keys = await self._client_keys()
        await self.authorize_row("permission:update", None, payload=keys)
        return await super().patch()

    async def post(self):
        """Upsert: approve BOTH verbs, with the same keys (partners.py:177-192)."""
        keys = await self._client_keys()
        await self.authorize_row("permission:create", None, payload=keys, creating=True)
        await self.authorize_row("permission:update", None, payload=keys)
        return await super().post()

    async def delete(self):
        await self.authorize_row("permission:delete", None, not_found_on_deny=True)
        return await super().delete()
