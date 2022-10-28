from datamodel import BaseModel
from navigator_auth.models import Permission
from .model import ModelHandler

class PermissionHandler(ModelHandler):
    model: BaseModel = Permission
    name: str = 'Permissions'
    pk: str = 'permission_id'
