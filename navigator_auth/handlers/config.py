"""Configuration / Environment Debug Handler.

Exposes the current environment variables (resolved through ``navconfig``)
for debugging purposes. The endpoint is restricted to members of the
``superuser`` group and only answers GET requests.
"""
import os
from aiohttp import web
from navconfig import config
from navigator.views import BaseView
from navigator_auth.decorators import allowed_groups
from navigator_auth.responses import JSONResponse

# Variable names matching any of these markers carry sensitive values and
# must be partially redacted before being exposed.
SENSITIVE_MARKERS = ("PWD", "PASSWORD", "SECRET")


def _is_sensitive(key: str) -> bool:
    """Return True if the variable name denotes a sensitive value."""
    name = key.upper()
    return any(marker in name for marker in SENSITIVE_MARKERS)


def _redact(value) -> str:
    """Partially redact a sensitive value.

    - For values longer than 12 characters: keep the first 3 and last 3
      characters, masking the middle.
    - For shorter values: keep only the last 3 characters, masking the rest.
    """
    text = "" if value is None else str(value)
    length = len(text)
    if length > 12:
        return f"{text[:3]}{'*' * (length - 6)}{text[-3:]}"
    if length <= 3:
        # Too short to safely reveal 3 chars without exposing everything.
        return "*" * length
    return f"{'*' * (length - 3)}{text[-3:]}"


@allowed_groups(groups=["superuser"])
class ConfigHandler(BaseView):
    """ConfigHandler.

    Return the environment/configuration variables currently visible to the
    application. Values are retrieved through ``navconfig.config`` so that
    env, ini and vault sources are honored consistently.

    Security:
        Restricted to the ``superuser`` group via the ``allowed_groups``
        decorator. Only the ``GET`` method is exposed.
    """

    async def get(self) -> web.StreamResponse:
        """Expose the environment variables for debugging."""
        variables: dict = {}
        # Resolve each known environment key through navconfig, redacting
        # any value whose variable name denotes a secret/password:
        for key in sorted(os.environ.keys()):
            value = config.get(key, fallback=os.environ.get(key))
            variables[key] = _redact(value) if _is_sensitive(key) else value
        payload = {
            "environment": config.ENV,
            "debug": config.debug,
            "variables": variables,
        }
        return JSONResponse(payload, status=200)
