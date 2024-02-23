from datamodel import BaseModel
from ..models import (
    Group,
    UserGroup,
    GroupPermission
)
from ..conf import (
    AUTH_GROUP_MODEL,
    AUTH_USER_GROUP_MODEL
)
from .handler import ModelHandler


class GroupManager(ModelHandler):
    model: BaseModel = Group
    model_name: str = AUTH_GROUP_MODEL
    name: str = "Group"
    pk: str = "group_id"


class UserGroupManager(ModelHandler):
    model: BaseModel = UserGroup
    model_name: str = AUTH_USER_GROUP_MODEL
    name: str = "User Group"
    pk: list = ["user_id", "group_id"]


class GroupPermissionManager(ModelHandler):
    model: BaseModel = GroupPermission
    name: str = "Group Permissions"
    pk: list = ["permission_id", "group_id"]
