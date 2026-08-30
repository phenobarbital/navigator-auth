"""OAuth2 discovery documents — RFC 8414 and RFC 9728.

FEAT-095 TASK-039 (Module 2).

Pure builders: no aiohttp imports, no server context, no I/O.  They take plain
data and return plain dicts, mirroring the helper discipline of ``pkce.py`` and
``devicecode.py`` so the document shape can be exhaustively unit-tested without
standing up an application.

``build_protected_resource_metadata`` is deliberately importable standalone:
external resource servers (the ai-parrot MCP mounts, spec D6) serve *their own*
RFC 9728 document pointing back at this authorization server, and consume this
builder to do it::

    from navigator_auth.backends.oauth2.metadata import (
        build_protected_resource_metadata,
    )

    doc = build_protected_resource_metadata(
        resource="https://mcp.example.com",
        auth_servers=["https://auth.example.com"],
        scopes=["default", "profile"],
    )

Wire-contract reference: the RFC 8414 document shape proven against Claude's
connector client (ai-parrot ``parrot/mcp/oauth_server.py`` ``_handle_discovery``).
Only the shape is reused here — none of the logic.
"""

from typing import Optional

__all__ = (
    "DEFAULT_ENDPOINT_PATHS",
    "WELL_KNOWN_AS_PATH",
    "WELL_KNOWN_PRM_PATH",
    "build_as_metadata",
    "build_protected_resource_metadata",
)


#: RFC 8414 §3 / RFC 9728 §3 well-known locations (must live at the origin root).
WELL_KNOWN_AS_PATH: str = "/.well-known/oauth-authorization-server"
WELL_KNOWN_PRM_PATH: str = "/.well-known/oauth-protected-resource"

#: Endpoint paths exposed by :class:`Oauth2Provider` (FEAT-093/094 defaults).
DEFAULT_ENDPOINT_PATHS: dict = {
    "authorization_endpoint": "/oauth2/authorize",
    "token_endpoint": "/oauth2/token",
    "registration_endpoint": "/oauth2/register",
    "introspection_endpoint": "/oauth2/introspect",
    "revocation_endpoint": "/oauth2/revoke",
    "device_authorization_endpoint": "/oauth2/device_authorization",
    "userinfo_endpoint": "/oauth2/userinfo",
    "jwks_uri": "/oauth2/jwks",
}

#: PKCE transforms this AS accepts.  OAuth 2.1 forbids ``plain``.
CODE_CHALLENGE_METHODS_SUPPORTED: list = ["S256"]

#: Client authentication methods accepted at token/introspect/revoke.
TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED: list = [
    "client_secret_post",
    "client_secret_basic",
    "none",
]

#: Grants implemented by FEAT-093/094.
DEFAULT_GRANT_TYPES_SUPPORTED: list = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
]


def _endpoint(issuer: str, path: str) -> str:
    """Join an issuer identifier and an endpoint path into an absolute URL."""
    return f"{issuer.rstrip('/')}{path}"


def build_as_metadata(
    issuer: str,
    *,
    dcr_enabled: bool,
    jwks: bool,
    grant_types: list,
    scopes: list,
    paths: Optional[dict] = None,
) -> dict:
    """Build the RFC 8414 authorization-server metadata document.

    Args:
        issuer: the canonical https issuer identifier.  Per RFC 8414 §2 this
            MUST equal the origin the document is served from, minus the
            well-known suffix.
        dcr_enabled: when False the ``registration_endpoint`` is omitted —
            advertising an endpoint the deployment refuses to serve would make
            Claude's client fail mid-registration with no useful error.
        jwks: when False the ``jwks_uri`` is omitted.  Never advertise a JWK
            Set that carries no keys (spec §6 "HS256→RS256 migration").
        grant_types: value of ``grant_types_supported``.
        scopes: value of ``scopes_supported``; omitted entirely when empty
            (RFC 8414 §2 makes the field OPTIONAL and an empty list would
            read as "no scopes are supported").
        paths: optional override of the endpoint paths; defaults to
            :data:`DEFAULT_ENDPOINT_PATHS`.

    Returns:
        The metadata document as a plain dict, ready to be JSON-serialised.
    """
    ep = {**DEFAULT_ENDPOINT_PATHS, **(paths or {})}
    issuer = issuer.rstrip("/")

    metadata: dict = {
        "issuer": issuer,
        "authorization_endpoint": _endpoint(issuer, ep["authorization_endpoint"]),
        "token_endpoint": _endpoint(issuer, ep["token_endpoint"]),
        "introspection_endpoint": _endpoint(issuer, ep["introspection_endpoint"]),
        "revocation_endpoint": _endpoint(issuer, ep["revocation_endpoint"]),
        "device_authorization_endpoint": _endpoint(
            issuer, ep["device_authorization_endpoint"]
        ),
        "userinfo_endpoint": _endpoint(issuer, ep["userinfo_endpoint"]),
        "response_types_supported": ["code"],
        "grant_types_supported": list(grant_types),
        "code_challenge_methods_supported": list(CODE_CHALLENGE_METHODS_SUPPORTED),
        "token_endpoint_auth_methods_supported": list(
            TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
        ),
        "revocation_endpoint_auth_methods_supported": list(
            TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
        ),
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        # RFC 8707: this AS accepts (and reflects) the ``resource`` parameter.
        "authorization_response_iss_parameter_supported": False,
    }

    # Conditional: DCR (RFC 7591).
    if dcr_enabled:
        metadata["registration_endpoint"] = _endpoint(
            issuer, ep["registration_endpoint"]
        )

    # Conditional: asymmetric signing (FEAT-095 Module 6).
    if jwks:
        metadata["jwks_uri"] = _endpoint(issuer, ep["jwks_uri"])

    # Optional: scope registry.
    if scopes:
        metadata["scopes_supported"] = list(scopes)

    return metadata


def build_protected_resource_metadata(
    resource: str,
    auth_servers: list,
    scopes: list,
) -> dict:
    """Build the RFC 9728 protected-resource metadata document.

    Tells a client which authorization server(s) issue tokens for a resource,
    which is exactly what Claude's connector infrastructure follows out of the
    ``WWW-Authenticate: Bearer resource_metadata="…"`` challenge.

    Args:
        resource: the canonical resource identifier (an absolute URI).
        auth_servers: issuer identifiers of the authorization servers that
            protect this resource.
        scopes: scopes the resource understands; omitted when empty.

    Returns:
        The metadata document as a plain dict.
    """
    metadata: dict = {
        "resource": resource.rstrip("/"),
        "authorization_servers": [s.rstrip("/") for s in auth_servers],
        "bearer_methods_supported": ["header"],
    }
    if scopes:
        metadata["scopes_supported"] = list(scopes)
    return metadata
