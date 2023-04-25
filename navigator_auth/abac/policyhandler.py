from datamodel import BaseModel
from navigator_auth.handlers.model import ModelHandler
from navigator_auth.abac.storages.pg import ModelPolicy


class PolicyHandler(ModelHandler):
    """
    CRUD Handler for ABAC Policies.
    """
    model: BaseModel = ModelPolicy
    model_name: str = "policies"
    name: str = "Policies"
    pk: str = "policy_id"
