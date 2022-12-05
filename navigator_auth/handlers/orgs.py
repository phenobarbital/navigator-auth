from typing import Any
from navigator_auth.models import Organization
from navigator_auth.conf import AUTH_ORGANIZATION_MODEL
from .model import ModelHandler

class OrganizationHandler(ModelHandler):
    model: Any = Organization
    model_name: str = AUTH_ORGANIZATION_MODEL
    name: str = 'Organization'
    pk: str = 'organization_id'
