from datamodel import BaseModel
from navigator_auth.models import Permission
from navigator_auth.conf import AUTH_PERMISSION_MODEL
from .model import ModelHandler


class PermissionHandler(ModelHandler):
    model: BaseModel = Permission
    model_name: str = AUTH_PERMISSION_MODEL
    name: str = "Permissions"
    pk: str = "permission_id"
