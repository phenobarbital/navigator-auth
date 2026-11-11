from typing import Any, Optional

from asyncdb.exceptions import NoDataFound
from datamodel import BaseModel
from datamodel.exceptions import ValidationError

from ..conf import AUTH_GROUP_MODEL, AUTH_USER_GROUP_MODEL
from ..models import Group, GroupPermission, UserGroup
from .guard_hooks import GuardedModelViewHooks
from .guards import OwnerOrSuperuserGuard
from .handler import ModelHandler


async def _stored_group_name(view: Any, group_id: Any) -> Optional[str]:
    """Return the stored group name for ``group_id``, or ``None``."""
    if group_id is None:
        return None
    try:
        async with await view.handler(request=view.request) as conn:
            Group.Meta.connection = conn
            row = await Group.get(group_id=group_id)
    except (NoDataFound, ValidationError):
        return None
    return getattr(row, "group_name", None)


class GroupManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Group definitions with protected-name checks on every write."""

    model: BaseModel = Group
    model_name: str = AUTH_GROUP_MODEL
    name: str = "Group"
    pk: str = "group_id"
    action_object: str = "group"
    owner_column: Optional[str] = None
    policy_name: str = "groups_admin_access"
    superuser_actions = frozenset({"group:read", "group:create", "group:update", "group:delete"})
    writable_by_admin = frozenset({"group_name", "description", "is_active", "client_id"})
    privileged_columns = frozenset({"group_id", "created_at", "created_by"})

    async def _payload_names(self) -> set:
        """Return ``group_name`` values supplied by the client."""
        data = await self.json_data()
        elements = data if isinstance(data, list) else [data]
        return {element.get("group_name") for element in elements if isinstance(element, dict)} - {None}

    async def _pre_put(self, *args, **kwargs) -> bool:
        await super()._pre_put(*args, **kwargs)
        await self.authorize_protected_group(await self._payload_names())
        return True

    async def _pre_post(self, *args, **kwargs) -> bool:
        await super()._pre_post(*args, **kwargs)
        await self.authorize_protected_group(await self._payload_names())
        return True

    async def _set_update(self, model, data) -> None:
        stored = getattr(model, "group_name", None)
        await super()._set_update(model, data)
        await self.authorize_protected_group({stored, (data or {}).get("group_name")} - {None})

    async def _del_primary_data(self, args: dict):
        objid = await super()._del_primary_data(args)
        await self.authorize_protected_group({await _stored_group_name(self, objid)} - {None})
        return objid


class UserGroupManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Membership is admin-only and protected memberships need grant-role access."""

    model: BaseModel = UserGroup
    model_name: str = AUTH_USER_GROUP_MODEL
    name: str = "User Group"
    pk: list = ["user_id", "group_id"]
    action_object: str = "user_group"
    owner_column: Optional[str] = None
    policy_name: str = "user_groups_admin_access"
    superuser_actions = frozenset({"user_group:read", "user_group:create", "user_group:delete"})
    writable_by_owner = frozenset()
    writable_by_admin = frozenset()
    creatable_by_admin = frozenset({"user_id", "group_id"})
    privileged_columns = frozenset()

    async def _pre_put(self, *args, **kwargs) -> bool:
        await super()._pre_put(*args, **kwargs)
        data = await self.json_data()
        elements = data if isinstance(data, list) else [data]
        for element in elements:
            if isinstance(element, dict):
                name = await _stored_group_name(self, element.get("group_id"))
                await self.authorize_protected_group({name} - {None}, member_id=element.get("user_id"))
        return True

    async def _del_primary_data(self, args: dict):
        objid = await super()._del_primary_data(args)
        group_id = objid.get("group_id") if isinstance(objid, dict) else None
        await self.authorize_protected_group({await _stored_group_name(self, group_id)} - {None})
        return objid


class GroupPermissionManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Group-permission grants are admin-only mapping rows."""

    model: BaseModel = GroupPermission
    name: str = "Group Permissions"
    pk: list = ["permission_id", "group_id"]
    action_object: str = "group_permission"
    owner_column: Optional[str] = None
    policy_name: str = "group_permissions_admin_access"
    superuser_actions = frozenset({"group_permission:read", "group_permission:create", "group_permission:delete"})
    writable_by_admin = frozenset()
    creatable_by_admin = frozenset({"group_id", "permission_id"})
    privileged_columns = frozenset()
