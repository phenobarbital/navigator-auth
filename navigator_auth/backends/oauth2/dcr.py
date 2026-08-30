"""Dynamic Client Registration — RFC 7591.

FEAT-095 TASK-040 (Module 3, decision D1).

Pure validation/mapping: no aiohttp imports, no I/O, no storage.  The module
turns an untrusted registration body into a validated
:class:`~.models.ClientRegistrationRequest`, and that request into an
:class:`~.models.OAuthClient` ready for ``ClientStorage.save_client``.

**Registration is open by default (D1).**  Anyone may register a client; the
per-client access gate (TASK-042) is the actual access control.  Registration
by itself confers no privileges — it only mints an identifier.  The policy knob
``OAUTH_DCR_POLICY`` narrows this to ``allowlist`` (redirect URIs must match
``OAUTH_DCR_REDIRECT_ALLOWLIST``) or ``disabled``.

Wire-contract reference: the RFC 7591 request/response shapes proven against
Claude's connector client (ai-parrot ``parrot/mcp/oauth_server.py``
``ClientRegistry.register`` / ``_handle_registration``).  Only the shapes are
reused here — none of the logic.
"""

from fnmatch import fnmatch
from typing import Optional
import secrets
import time
from urllib.parse import urlparse

from pydantic import ValidationError

from .metadata import (
    DEFAULT_GRANT_TYPES_SUPPORTED,
    TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
)
from .models import (
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    OAuthClient,
)

__all__ = (
    "DCRError",
    "POLICY_ALLOWLIST",
    "POLICY_DISABLED",
    "POLICY_OPEN",
    "build_registration_response",
    "generate_client_secret",
    "generate_client_uid",
    "parse_rate_limit",
    "to_oauth_client",
    "validate_registration",
)


#: ``OAUTH_DCR_POLICY`` values.
POLICY_OPEN: str = "open"
POLICY_ALLOWLIST: str = "allowlist"
POLICY_DISABLED: str = "disabled"

#: Response types this AS can register (OAuth 2.1: code only).
SUPPORTED_RESPONSE_TYPES: frozenset = frozenset({"code"})

#: Hosts allowed to register an ``http://`` redirect URI (local development).
LOOPBACK_HOSTS: frozenset = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

#: Entropy of a generated ``client_uid`` — matches ``save_client`` (FEAT-093).
CLIENT_UID_BYTES: int = 18

#: Entropy of a generated ``client_secret`` (spec §3 Module 3).
CLIENT_SECRET_BYTES: int = 32

#: ``OAUTH_DCR_RATE_LIMIT`` window names → seconds.
RATE_LIMIT_WINDOWS: dict = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


class DCRError(Exception):
    """A registration request that must be refused.

    Carries the RFC 7591 §3.2.2 error body verbatim so the route layer can
    serialise it without re-deriving anything.
    """

    def __init__(self, error: str, description: str, status: int = 400):
        self.error = error
        self.description = description
        self.status = status
        super().__init__(f"{error}: {description}")


def generate_client_uid() -> str:
    """Mint an opaque public ``client_uid`` (the wire ``client_id``)."""
    return secrets.token_urlsafe(CLIENT_UID_BYTES)


def generate_client_secret() -> str:
    """Mint a ``client_secret`` for a confidential client."""
    return secrets.token_urlsafe(CLIENT_SECRET_BYTES)


def parse_rate_limit(spec: str) -> tuple:
    """Parse an ``OAUTH_DCR_RATE_LIMIT`` string into ``(count, window_seconds)``.

    Accepts ``"<count>/<window>"`` where window is ``second``/``minute``/
    ``hour``/``day`` (singular or plural).  An unparseable value disables rate
    limiting rather than failing closed on every registration — a malformed
    setting must not take the endpoint down.

    Returns:
        ``(count, seconds)``, or ``(0, 0)`` when limiting is off.
    """
    if not spec:
        return (0, 0)
    try:
        raw_count, _, raw_window = str(spec).partition("/")
        count = int(raw_count.strip())
        window = raw_window.strip().lower().rstrip("s") or "hour"
        seconds = RATE_LIMIT_WINDOWS[window]
    except (ValueError, KeyError):
        return (0, 0)
    if count <= 0:
        return (0, 0)
    return (count, seconds)


def _first_error(exc: ValidationError) -> str:
    """Render the first pydantic error as an ``error_description``."""
    try:
        err = exc.errors()[0]
        field = ".".join(str(p) for p in err.get("loc", ())) or "body"
        return f"{field}: {err.get('msg', 'invalid value')}"
    except Exception:  # pragma: no cover — defensive
        return "Invalid client metadata."


def _validate_redirect_uri(uri: str) -> None:
    """Enforce the redirect-URI rules of RFC 7591 §2 / OAuth 2.1.

    https everywhere, with an ``http://`` exemption for loopback hosts so local
    development still works.  Fragments are forbidden (RFC 6749 §3.1.2) and a
    URI must be absolute — a relative or wildcard value would make exact
    matching at ``/authorize`` meaningless.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise DCRError("invalid_client_metadata", "redirect_uris entries must be non-empty strings.")
    parsed = urlparse(uri)
    if not parsed.scheme or not parsed.netloc:
        raise DCRError(
            "invalid_client_metadata",
            f"redirect_uri '{uri}' must be an absolute URI.",
        )
    if parsed.fragment:
        raise DCRError(
            "invalid_client_metadata",
            f"redirect_uri '{uri}' must not contain a fragment.",
        )
    if "*" in uri:
        raise DCRError(
            "invalid_client_metadata",
            f"redirect_uri '{uri}' must not contain wildcards.",
        )
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (parsed.hostname or "") in LOOPBACK_HOSTS:
        return
    raise DCRError(
        "invalid_client_metadata",
        f"redirect_uri '{uri}' must use https (http is allowed only for loopback).",
    )


def _check_allowlist(uris: list, allowlist: list) -> None:
    """Every redirect URI must glob-match at least one allowlist pattern."""
    patterns = [p for p in (allowlist or []) if p]
    if not patterns:
        raise DCRError(
            "invalid_client_metadata",
            "Registration is restricted and no redirect URI patterns are configured.",
        )
    for uri in uris:
        if not any(fnmatch(uri, pattern) for pattern in patterns):
            raise DCRError(
                "invalid_client_metadata",
                f"redirect_uri '{uri}' is not permitted by this server's allowlist.",
            )


def validate_registration(
    req: dict,
    policy: str,
    allowlist: list,
) -> ClientRegistrationRequest:
    """Validate an RFC 7591 registration body against the server policy.

    Args:
        req: the raw JSON body as a dict.
        policy: ``open`` / ``allowlist`` / ``disabled`` (``OAUTH_DCR_POLICY``).
        allowlist: glob patterns consulted when ``policy == "allowlist"``.

    Returns:
        The validated registration request.

    Raises:
        DCRError: with ``registration_not_supported`` when DCR is disabled, or
            ``invalid_client_metadata`` for any rejected metadata.
    """
    normalised_policy = str(policy or POLICY_OPEN).strip().lower()
    if normalised_policy == POLICY_DISABLED:
        raise DCRError(
            "registration_not_supported",
            "Dynamic client registration is disabled on this server.",
        )

    if not isinstance(req, dict):
        raise DCRError(
            "invalid_client_metadata",
            "The registration request body must be a JSON object.",
        )

    try:
        reg = ClientRegistrationRequest(**req)
    except ValidationError as exc:
        raise DCRError("invalid_client_metadata", _first_error(exc)) from exc

    if not reg.redirect_uris:
        raise DCRError(
            "invalid_client_metadata",
            "At least one redirect_uri is required.",
        )
    for uri in reg.redirect_uris:
        _validate_redirect_uri(uri)

    unsupported = [
        g for g in reg.grant_types if g not in DEFAULT_GRANT_TYPES_SUPPORTED
    ]
    if unsupported:
        raise DCRError(
            "invalid_client_metadata",
            f"Unsupported grant_types: {', '.join(unsupported)}.",
        )

    bad_response_types = [
        r for r in reg.response_types if r not in SUPPORTED_RESPONSE_TYPES
    ]
    if bad_response_types:
        raise DCRError(
            "invalid_client_metadata",
            f"Unsupported response_types: {', '.join(bad_response_types)}.",
        )

    if reg.token_endpoint_auth_method not in TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED:
        raise DCRError(
            "invalid_client_metadata",
            (
                f"Unsupported token_endpoint_auth_method "
                f"'{reg.token_endpoint_auth_method}'."
            ),
        )

    if normalised_policy == POLICY_ALLOWLIST:
        _check_allowlist(reg.redirect_uris, allowlist)

    return reg


def _parse_scope(scope: Optional[str]) -> list:
    """Split an RFC 6749 space-delimited ``scope`` string into a list."""
    if not scope:
        return []
    return [s for s in str(scope).split() if s]


def to_oauth_client(
    reg: ClientRegistrationRequest,
    *,
    default_scopes: Optional[list] = None,
    gate_new_clients: bool = False,
    client_uid: Optional[str] = None,
) -> OAuthClient:
    """Map validated registration metadata onto a persistable client.

    Args:
        reg: validated registration request.
        default_scopes: ``OAUTH_DCR_DEFAULT_SCOPES``, applied when the client
            requested no scope of its own.
        gate_new_clients: ``OAUTH_DCR_GATE_NEW_CLIENTS`` — DCR clients are born
            gated by default, so registration alone grants nobody access.
        client_uid: pre-minted identifier (tests); generated when omitted.

    Returns:
        An :class:`OAuthClient` with ``registration_source='dcr'``.

    Note:
        ``token_endpoint_auth_method='none'`` designates a **public** client:
        no ``client_secret`` is generated or stored.  PKCE then becomes
        mandatory downstream through the existing ``OAUTH_REQUIRE_PKCE_PUBLIC``
        enforcement (FEAT-093) — nothing extra is needed here.
    """
    is_public = reg.token_endpoint_auth_method == "none"
    uid = client_uid or generate_client_uid()
    scopes = _parse_scope(reg.scope) or list(default_scopes or [])

    return OAuthClient(
        client_id=uid,
        client_name=reg.client_name or f"dcr-client-{uid[:8]}",
        # Never issue a secret to a public client (RFC 6749 §2.1).
        client_secret=None if is_public else generate_client_secret(),
        client_type="public" if is_public else "confidential",
        redirect_uris=list(reg.redirect_uris),
        client_logo_uri=reg.logo_uri,
        default_scopes=scopes,
        allowed_grant_types=list(reg.grant_types),
        token_endpoint_auth_method=reg.token_endpoint_auth_method,
        registration_source="dcr",
        enforce_access_gate=bool(gate_new_clients),
    )


def build_registration_response(
    reg: ClientRegistrationRequest,
    client: OAuthClient,
    *,
    issued_at: Optional[int] = None,
) -> ClientRegistrationResponse:
    """Build the RFC 7591 §3.2.1 success body.

    ``client_id`` on the wire is the opaque ``client_uid`` — the internal
    integer PK is never disclosed.  ``client_secret_expires_at`` is ``0``,
    meaning the secret does not expire.
    """
    return ClientRegistrationResponse(
        client_id=client.client_id,
        client_secret=client.client_secret,
        client_id_issued_at=int(issued_at if issued_at is not None else time.time()),
        client_secret_expires_at=0,
        # Echo of the registered metadata (RFC 7591 §3.2.1).
        redirect_uris=list(reg.redirect_uris),
        client_name=client.client_name,
        grant_types=list(reg.grant_types),
        response_types=list(reg.response_types),
        token_endpoint_auth_method=reg.token_endpoint_auth_method,
        scope=" ".join(client.default_scopes)
        if isinstance(client.default_scopes, list) and client.default_scopes
        else (reg.scope or None),
        client_uri=reg.client_uri,
        logo_uri=reg.logo_uri,
    )
