from datamodel import BaseModel
from navigator_auth.models import Group, UserGroup, GroupPermission
from navigator_auth.conf import AUTH_GROUP_MODEL, AUTH_USER_GROUP_MODEL
from .model import ModelHandler


class GroupHandler(ModelHandler):
    model: BaseModel = Group
    model_name: str = AUTH_GROUP_MODEL
    name: str = "Group"
    pk: str = "group_id"


class UserGroupHandler(ModelHandler):
    model: BaseModel = UserGroup
    model_name: str = AUTH_USER_GROUP_MODEL
    name: str = "User Group"
    pk: list = ["user_id", "group_id"]


class GroupPermissionHandler(ModelHandler):
    model: BaseModel = GroupPermission
    name: str = "Group Permissions"
    pk: list = ["permission_id", "group_id"]
