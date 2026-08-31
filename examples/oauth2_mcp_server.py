"""OAuth 2.1 authorization server for MCP agents (FEAT-095) — runnable example.

Wires together everything FEAT-095 adds, in the shape a Claude custom connector
expects:

  * **RFC 8414 discovery** at ``/.well-known/oauth-authorization-server`` and
    **RFC 9728** at ``/.well-known/oauth-protected-resource``.
  * **RFC 7591 Dynamic Client Registration** at ``/oauth2/register`` — open, so
    Claude self-registers with no out-of-band setup.
  * **Upstream IdP proxy login** — the AS login page offers Google/Microsoft in
    addition to local credentials (set the provider env vars below to enable;
    with none set it falls back to local login, unchanged).
  * **Per-client access gate** — DCR clients are born gated, so registering
    grants nobody access until an administrator approves them. Denied attempts
    land in the approval queue.
  * A tiny **resource server** at ``/mcp/tools`` that serves its own RFC 9728
    document and emits the ``WWW-Authenticate`` challenge Claude follows.

Run it **from the repository root**::

    mkdir -p env/dev && touch env/dev/.env      # navconfig needs this once
    redis-server --daemonize yes                # sessions + flow state
    python examples/oauth2_mcp_server.py

Then either point a connector at ``http://localhost:5000/mcp`` or drive the
handshake by hand::

    curl -s localhost:5000/.well-known/oauth-authorization-server | jq .

    curl -s -X POST localhost:5000/oauth2/register \
      -H 'Content-Type: application/json' \
      -d '{"client_name":"Claude",
           "redirect_uris":["http://localhost:5000/callback"],
           "token_endpoint_auth_method":"none"}' | jq .

For a real deployment, ``AUTH_ISSUER_URL`` must be the public **https** origin
that serves the well-known documents — see ``documentation/mcp-connector.md``.

Notes
-----
* ``enable_authdb=False`` keeps the example free of PostgreSQL: clients, the
  access gate and users all live in memory. A real deployment drops this and
  applies ``navigator_auth/backends/oauth2/ddl.sql``.
* Demo credentials: ``demo`` / ``demo123``. The demo user is pre-activated on
  the gate at startup so the flow completes end to end; comment that out to
  watch the approval queue fill up instead.
"""
import os

# ---------------------------------------------------------------------------
# Environment MUST be set before navconfig / navigator_auth get imported.
# ---------------------------------------------------------------------------
HOST = os.getenv("EXAMPLE_HOST", "localhost")
PORT = int(os.getenv("EXAMPLE_PORT", "5000"))
BASE_URL = os.getenv("EXAMPLE_BASE_URL", f"http://{HOST}:{PORT}")

os.environ.setdefault(
    "AUTHENTICATION_BACKENDS",
    "navigator_auth.backends.oauth2.Oauth2Provider",
)
# Canonical issuer. In production this MUST be the public https origin.
os.environ.setdefault("AUTH_ISSUER_URL", BASE_URL)
# Keep clients and the access gate in memory: no auth.clients table needed.
os.environ.setdefault("OAUTH2_CLIENT_STORAGE", "memory")
# Dynamic Client Registration: open (D1), rate-limited, born gated.
os.environ.setdefault("OAUTH_DCR_POLICY", "open")
os.environ.setdefault("OAUTH_DCR_GATE_NEW_CLIENTS", "true")
os.environ.setdefault("OAUTH_DCR_RATE_LIMIT", "10/hour")
# Access gate: on for DCR clients, with the approval queue recording attempts.
os.environ.setdefault("OAUTH_ACCESS_GATE_QUEUE", "true")
# Upstream IdPs. Empty by default so the example runs with no provider secrets;
# set to "google,azure" (plus that backend's own credentials) to enable them.
os.environ.setdefault("OAUTH_UPSTREAM_IDP_BACKENDS", "")
os.environ.setdefault("OAUTH_UPSTREAM_FLOW_TTL", "600")
# Short-lived access tokens make the example easier to reason about.
os.environ.setdefault("OAUTH_ACCESS_TOKEN_TTL", "900")
os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me-please")

# Enable the upstream providers alongside the AS when configured.
_UPSTREAM = [s.strip() for s in os.environ["OAUTH_UPSTREAM_IDP_BACKENDS"].split(",") if s.strip()]
if _UPSTREAM:
    _BACKENDS = ["navigator_auth.backends.oauth2.Oauth2Provider"]
    if "google" in _UPSTREAM:
        _BACKENDS.append("navigator_auth.backends.GoogleAuth")
    if "azure" in _UPSTREAM:
        _BACKENDS.append("navigator_auth.backends.AzureAuth")
    os.environ["AUTHENTICATION_BACKENDS"] = ",".join(_BACKENDS)

import logging  # noqa: E402

from aiohttp import web  # noqa: E402

from navigator_auth import AuthHandler  # noqa: E402
from navigator_auth.backends.idp import IdentityProvider  # noqa: E402
from navigator_auth.backends.oauth2.metadata import (  # noqa: E402
    build_protected_resource_metadata,
)
from navigator_auth.backends.oauth2.models import OAuthClient  # noqa: E402
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY  # noqa: E402
from navigator_auth.exceptions import UserNotFound  # noqa: E402
from navigator_auth.models import User  # noqa: E402


MCP_RESOURCE = f"{BASE_URL}/mcp"

#: Pre-registered static client, so the example works without DCR too.
STATIC_CLIENT_UID = "example-mcp-client"

DEMO_USERS = {
    "demo": {
        "user_id": 1,
        "username": "demo",
        "password": "demo123",
        "first_name": "Demo",
        "last_name": "User",
        "email": "demo@example.com",
    },
}


# ---------------------------------------------------------------------------
# A minimal IdP so the example needs no auth.users table.
# ---------------------------------------------------------------------------

class DemoIdentityProvider(IdentityProvider):
    """Authenticates against DEMO_USERS instead of the database."""

    def __init__(self):  # noqa: D107 - intentionally skips the DB model lookup
        self.authorization_codes = {}
        self.app = None
        self.logger = logging.getLogger("Auth.IdP")
        self.user_model = User
        self.user_search = User

    def _build(self, record: dict) -> User:
        user = User(**{k: v for k, v in record.items() if k != "password"})
        user.password = record["password"]
        return user

    async def get_user(self, login: str) -> User:
        record = DEMO_USERS.get(login)
        if not record:
            raise UserNotFound(f"Unknown user {login}")
        return self._build(record)

    async def user_from_id(self, uid) -> User:
        for record in DEMO_USERS.values():
            if record["user_id"] == int(uid):
                return self._build(record)
        raise UserNotFound(f"Unknown user_id {uid}")

    async def authenticate_credentials(self, login: str = None, password: str = None):
        record = DEMO_USERS.get(login)
        if not record or record["password"] != password:
            raise UserNotFound("Invalid credentials")
        return self._build(record)

    def check_password(self, stored, given, **kwargs) -> bool:
        return stored == given


# ---------------------------------------------------------------------------
# Resource server: what Claude actually calls.
# ---------------------------------------------------------------------------

async def mcp_protected_resource_metadata(request: web.Request):
    """RFC 9728 document for THIS resource server.

    This is the half that, in production, ai-parrot serves for each MCP mount
    (spec D6) — consuming the same builder navigator-auth ships.
    """
    return web.json_response(
        build_protected_resource_metadata(
            resource=MCP_RESOURCE,
            auth_servers=[os.environ["AUTH_ISSUER_URL"]],
            scopes=["default"],
        )
    )


async def mcp_tools(request: web.Request):
    """A stand-in MCP tools endpoint, protected by a bearer token.

    An unauthenticated call answers with the challenge Claude follows to find
    the authorization server.
    """
    auth = request.app["auth"]
    challenge = {
        "WWW-Authenticate": (
            f'Bearer resource_metadata="{BASE_URL}'
            f'/.well-known/oauth-protected-resource"'
        )
    }
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return web.json_response(
            {"error": "invalid_token", "error_description": "A bearer token is required."},
            status=401,
            headers=challenge,
        )
    try:
        _, payload = auth._idp.decode_token(header[7:])
    except Exception:
        return web.json_response(
            {"error": "invalid_token"}, status=401, headers=challenge
        )
    if not payload:
        return web.json_response(
            {"error": "invalid_token"}, status=401, headers=challenge
        )
    return web.json_response(
        {
            "tools": [
                {"name": "echo", "description": "Echo a message back."},
                {"name": "now", "description": "Return the server time."},
            ],
            "principal": {
                "user_id": payload.get("user_id"),
                "client_id": payload.get("client_id"),
                "scope": payload.get("scope"),
                "aud": payload.get("aud"),
            },
        }
    )


async def index(request: web.Request):
    issuer = os.environ["AUTH_ISSUER_URL"]
    return web.json_response(
        {
            "message": "navigator-auth OAuth 2.1 authorization server for MCP agents",
            "give_this_url_to_claude": MCP_RESOURCE,
            "discovery": f"{issuer}/.well-known/oauth-authorization-server",
            "protected_resource": f"{BASE_URL}/.well-known/oauth-protected-resource",
            "registration": f"{issuer}/oauth2/register",
            "jwks": f"{issuer}/oauth2/jwks",
            "demo_credentials": {"username": "demo", "password": "demo123"},
            "static_client_id": STATIC_CLIENT_UID,
            "upstream_idps": _UPSTREAM or "none configured (local login only)",
        }
    )


# ---------------------------------------------------------------------------
# Startup: seed a static client and activate the demo user on the gate.
# ---------------------------------------------------------------------------

async def seed(app: web.Application):
    auth = app["auth"]
    provider = None
    for backend in auth.backends.values():
        if backend.__class__.__name__ == "Oauth2Provider":
            provider = backend
            break
    if provider is None:  # pragma: no cover - misconfiguration
        return

    client = OAuthClient(
        client_id=STATIC_CLIENT_UID,
        client_name="Example MCP Client",
        client_type="public",
        redirect_uris=[
            f"{BASE_URL}/callback",
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
        ],
        default_scopes=["default", "offline_access"],
        allowed_grant_types=["authorization_code", "refresh_token"],
        registration_source="static",
        # Gate this one too, to exercise the approval path.
        enforce_access_gate=True,
    )
    await provider.client_storage.save_client(client)

    # Pre-activate the demo user so the flow completes end to end.
    # Comment this out to watch denied attempts land in the approval queue,
    # then approve them via
    #   POST /api/v1/oauth2/clients/{client_uid}/access {"user_id":1,"action":"approve"}
    if provider.client_access_storage:
        await provider.client_access_storage.grant(
            user_id=1, client_uid=STATIC_CLIENT_UID, granted_by=1
        )

    logging.info("Seeded static client %s and activated the demo user.", STATIC_CLIENT_UID)


def build_app() -> web.Application:
    app = web.Application()

    auth = AuthHandler(
        identity=DemoIdentityProvider(),
        enable_authdb=False,
    )
    auth.setup(app)

    router = app.router
    router.add_get("/", index)
    router.add_get("/mcp/tools", mcp_tools)
    # The resource server's own RFC 9728 document (D6: ai-parrot's half).
    router.add_get(
        "/.well-known/oauth-protected-resource-mcp",
        mcp_protected_resource_metadata,
    )
    for path in ("/", "/mcp/tools", "/.well-known/oauth-protected-resource-mcp"):
        app[AUTH_EXCLUDE_LIST_KEY].append(path)

    app.on_startup.append(seed)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    application = build_app()
    print(f"\n  MCP OAuth2 example running at {BASE_URL}")
    print(f"  Give Claude this URL:  {MCP_RESOURCE}")
    print(f"  Discovery:             {BASE_URL}/.well-known/oauth-authorization-server")
    print("  Demo credentials:      demo / demo123\n")
    web.run_app(application, host=HOST, port=PORT)
