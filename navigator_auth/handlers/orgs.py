from typing import Any
from navigator_auth.models import Organization
from .model import ModelHandler

class OrganizationHandler(ModelHandler):
    model: Any = Organization
    name: str = 'Organization'
    pk: str = 'organization_id'
