from datamodel import BaseModel
from navigator_auth.models import Group, UserGroup, GroupPermission
from .model import ModelHandler


class GroupHandler(ModelHandler):
    model: BaseModel = Group
    name: str = 'Group'
    pk: str = 'group_id'


class UserGroupHandler(ModelHandler):
    model: BaseModel = UserGroup
    name: str = 'User Group'
    pk: list = ['user_id', 'group_id']


class GroupPermissionHandler(ModelHandler):
    model: BaseModel = GroupPermission
    name: str = 'Group Permissions'
    pk: list = ['permission_id', 'group_id']
