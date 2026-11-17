"""Registry of the ABAC policies an Application's handlers depend on.

Handlers that call :func:`navigator_auth.decorators.policy_allows` fail closed:
when their named policy is not loaded on the PDP, every request that needs it
is denied. That is safe but silent until the first request. Handlers declare
the policies they need here at setup time, and ``PDP.on_startup`` warns about
every declared policy that is not loaded once storage has been read.

The registry lives on the Application (``app[REQUIRED_POLICIES_KEY]``), so it
does not depend on the order in which the PDP and the handlers are set up.
"""

from typing import Any

#: Application key holding ``{policy_name: {required_by, ...}}``.
REQUIRED_POLICIES_KEY = "abac_required_policies"


def require_policy(app: Any, name: str, required_by: str) -> None:
    """Declare that ``required_by`` needs the ABAC policy ``name``.

    Args:
        app: The ``aiohttp`` Application the handler is registered on.
        name: Name of the ABAC policy the handler evaluates.
        required_by: Human-readable label for the dependant (e.g. a route),
            used in the startup warning.

    Raises:
        ValueError: ``name`` is empty.
    """
    if not name:
        raise ValueError("require_policy needs a policy name.")
    required = app.get(REQUIRED_POLICIES_KEY)
    if required is None:
        required = {}
        app[REQUIRED_POLICIES_KEY] = required
    required.setdefault(name, set()).add(required_by)


def required_policies(app: Any) -> dict[str, set[str]]:
    """Return the policies declared on ``app`` with :func:`require_policy`.

    Args:
        app: The ``aiohttp`` Application.

    Returns:
        A copy of ``{policy_name: {required_by, ...}}``; empty when nothing
        was declared.
    """
    return {name: set(users) for name, users in (app.get(REQUIRED_POLICIES_KEY) or {}).items()}
