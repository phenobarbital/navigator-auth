from aiohttp import web
from datamodel import BaseModel
from navigator_auth.handlers.model import ModelHandler
from navigator_auth.abac.storages.pg import ModelPolicy
from navigator_auth.abac.decorators import groups_protected


class PolicyHandler(ModelHandler):
    """
    CRUD Handler for ABAC Policies.
    """
    model: BaseModel = ModelPolicy
    model_name: str = "policies"
    name: str = "Policies"
    pk: str = "policy_id"

    @groups_protected(groups=['superuser'])
    async def reload(self, request: web.Request) -> web.Response:
        """Hot-reload policies from Storage."""
        pdp = request.app.get('abac')
        if not pdp:
            return self.error(
                reason="ABAC System is not Installed.",
                status=503
            )
        try:
            count = await pdp.reload_policies()
            return self.json_response(
                response={
                    "message": "Policies reloaded successfully",
                    "reloaded": count
                },
                status=202
            )
        except Exception as exc:
            return self.error(
                reason=f"Failed to reload policies: {exc}",
                status=500
            )
