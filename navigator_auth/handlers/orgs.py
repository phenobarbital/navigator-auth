from datamodel import BaseModel
from typing import Any
from navigator_auth.models import Organization, OrganizationUser, OrganizationClient
from navigator_auth.conf import AUTH_ORGANIZATION_MODEL, AUTH_USER_ORGANIZATION_MODEL
from .model import ModelHandler


class OrganizationHandler(ModelHandler):
    model: Any = Organization
    model_name: str = AUTH_ORGANIZATION_MODEL
    name: str = "Organization"
    pk: str = "org_id"


class UserOrganizationHandler(ModelHandler):
    model: BaseModel = OrganizationUser
    model_name: str = AUTH_USER_ORGANIZATION_MODEL
    name: str = "User Organization"
    pk: list = ["org_id", "user_id"]


class OrganizationClientHandler(ModelHandler):
    model: BaseModel = OrganizationClient
    model_name: str = None
    name: str = 'Organization Clients'
    pk: list = ["org_id", "client_id"]
