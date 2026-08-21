"""End-to-end OAuth2 Authorization-Code + PKCE (3LO) example.

A single aiohttp application that plays all three roles of the flow, so the
whole thing can be exercised from one browser tab without any external
infrastructure other than Redis (used for the session storage):

  * **Authorization Server** — ``navigator_auth``'s ``Oauth2Provider`` mounts
    ``/oauth2/authorize``, ``/oauth2/login``, ``/oauth2/consent``,
    ``/oauth2/token``, ``/oauth2/userinfo``, ``/oauth2/revoke``, ...
  * **Client application** — the HTML/JS single-page app served at ``/``
    (``examples/static/oauth2_3lo_app.html``). It generates the PKCE pair,
    sends the browser to ``/oauth2/authorize`` and exchanges the returned
    code at ``/oauth2/token``.
  * **Resource Server** — ``GET /api/v1/me``, a plain aiohttp handler
    protected with ``@is_authenticated()`` + ``@user_session()``. This is the
    endpoint the example calls with the ``Authorization: Bearer <token>``
    header once the code exchange succeeded.

Run it **from the repository root**::

    mkdir -p env/dev && touch env/dev/.env      # navconfig needs this once
    redis-server --daemonize yes                # sessions live in Redis
    python examples/oauth2_3lo_server.py

then open http://localhost:5000/ and press *Start OAuth2 login*.
Demo credentials: ``demo`` / ``demo123`` (see ``DEMO_USERS`` below).

The working directory matters: the login and consent pages are rendered by
``TemplateParser`` from ``<project>/templates/oauth/``.

Notes
-----
* ``enable_authdb=False`` keeps the example free of PostgreSQL: OAuth2
  clients live in memory (``OAUTH2_CLIENT_STORAGE=memory``) and users come
  from :class:`DemoIdentityProvider` instead of ``auth.users``. A real
  deployment drops both and uses the database-backed defaults.
* Everything else — code issuance, PKCE verification, consent, refresh
  tokens, the JWT access token and the session it is bound to — is the real
  ``navigator_auth`` implementation.
"""
import os

# ---------------------------------------------------------------------------
# Environment MUST be set before navconfig / navigator_auth get imported.
# ---------------------------------------------------------------------------
os.environ.setdefault(
    "AUTHENTICATION_BACKENDS",
    "navigator_auth.backends.oauth2.Oauth2Provider",
)
# Keep OAuth2 clients in memory: no auth.clients table needed.
os.environ.setdefault("OAUTH2_CLIENT_STORAGE", "memory")
# Short-lived access tokens make the example easier to reason about.
os.environ.setdefault("OAUTH_ACCESS_TOKEN_TTL", "900")
os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me")

import logging  # noqa: E402
from pathlib import Path  # noqa: E402

from aiohttp import web  # noqa: E402

from navigator_auth import AuthHandler  # noqa: E402
from navigator_auth.backends.idp import IdentityProvider  # noqa: E402
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY  # noqa: E402
from navigator_auth.decorators import is_authenticated, user_session  # noqa: E402
from navigator_auth.exceptions import UserNotFound  # noqa: E402
from navigator_auth.models import User  # noqa: E402


HERE = Path(__file__).parent
STATIC_DIR = HERE / "static"

HOST = os.getenv("EXAMPLE_HOST", "localhost")
PORT = int(os.getenv("EXAMPLE_PORT", "5000"))
BASE_URL = f"http://{HOST}:{PORT}"

#: The public (PKCE) client the SPA authenticates as.
CLIENT_ID = "nav_example_spa"
REDIRECT_URI = f"{BASE_URL}/callback"
SCOPES = "default profile email offline_access"


# ---------------------------------------------------------------------------
# Demo user directory (replaces the auth.users table for this example)
# ---------------------------------------------------------------------------

DEMO_USERS = [
    {
        "user_id": 1,
        "username": "demo",
        "password": "demo123",
        "first_name": "Demo",
        "last_name": "User",
        "email": "demo@example.com",
    },
    {
        "user_id": 2,
        "username": "alice",
        "password": "alice123",
        "first_name": "Alice",
        "last_name": "Liddell",
        "email": "alice@example.com",
    },
]


class DemoIdentityProvider(IdentityProvider):
    """In-memory :class:`IdentityProvider` for the example.

    Only the three database-bound lookups are overridden; password hashing and
    verification, token creation and token decoding all come from the real
    ``IdentityProvider``.
    """

    def __init__(self, users: list[dict]):
        super().__init__()
        self._users: dict[str, User] = {}
        for entry in users:
            data = dict(entry)
            raw_password = data.pop("password")
            user = User(
                **data,
                display_name=f"{data['first_name']} {data['last_name']}",
                is_active=True,
                is_superuser=False,
            )
            # store the password the same way navigator-auth does in the DB
            user.password = self.set_password(raw_password)
            self._users[user.username] = user

    async def get_user(self, login: str):
        try:
            return self._users[str(login)]
        except KeyError as exc:
            raise UserNotFound(f"Invalid Credentials for {login!r}") from exc

    async def user_from_id(self, uid):
        for user in self._users.values():
            if str(user.user_id) == str(uid):
                return user
        raise UserNotFound(f"Invalid Credentials for user_id={uid!r}")


# ---------------------------------------------------------------------------
# Application handlers
# ---------------------------------------------------------------------------

async def index(request: web.Request) -> web.StreamResponse:
    """Serve the single-page client application (also handles /callback)."""
    return web.FileResponse(STATIC_DIR / "oauth2_3lo_app.html")


async def client_config(request: web.Request) -> web.StreamResponse:
    """Expose the OAuth2 client registration to the SPA.

    A real client ships these values in its own configuration; the example
    serves them so the HTML page has no hard-coded copy to drift out of sync.
    """
    return web.json_response(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPES,
            "authorization_endpoint": "/oauth2/authorize",
            "token_endpoint": "/oauth2/token",
            "userinfo_endpoint": "/oauth2/userinfo",
            "revocation_endpoint": "/oauth2/revoke",
            "protected_endpoint": "/api/v1/me",
            "demo_users": [
                {"username": u["username"], "password": u["password"]}
                for u in DEMO_USERS
            ],
        }
    )


@is_authenticated()
@user_session()
async def me(request: web.Request, *, session=None, user=None) -> web.StreamResponse:
    """The protected resource this example is really about.

    Reached with ``Authorization: Bearer <access_token>``:

    * ``@is_authenticated()`` rejects the request (401) when the bearer token
      is missing, expired, revoked or does not resolve to a session.
    * ``@user_session()`` injects the ``session`` and ``user`` objects that
      the OAuth2 token is bound to.
    """
    userdata = request.get("userdata") or {}
    return web.json_response(
        {
            "message": f"Hello {getattr(user, 'username', 'anonymous')}!",
            "user": {
                "user_id": getattr(user, "user_id", None) or getattr(user, "id", None),
                "username": getattr(user, "username", None),
                "email": getattr(user, "email", None),
                "first_name": getattr(user, "first_name", None),
                "last_name": getattr(user, "last_name", None),
            },
            "session_id": getattr(session, "session_id", None),
            "token_claims": {
                "client_id": userdata.get("client_id"),
                "scope": userdata.get("scope"),
                "jti": userdata.get("jti"),
                "aud": userdata.get("aud"),
            },
        }
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def make_app() -> web.Application:
    app = web.Application()

    # No PostgreSQL for this example: memory client storage + demo IdP.
    auth = AuthHandler(enable_authdb=False)

    demo_idp = DemoIdentityProvider(DEMO_USERS)
    auth._idp = demo_idp
    for backend in auth.backends.values():
        backend._idp = demo_idp

    auth.setup(app)

    app.router.add_static("/static/", path=STATIC_DIR, name="static")
    app.router.add_get("/", index, name="index")
    app.router.add_get("/callback", index, name="callback")
    app.router.add_get("/client-config", client_config, name="client_config")
    app.router.add_get("/api/v1/me", me, name="me")

    # The SPA shell and its configuration are public; /api/v1/me is not.
    app[AUTH_EXCLUDE_LIST_KEY].extend(["/", "/callback", "/client-config"])

    app.on_startup.append(register_demo_clients)
    return app


async def register_demo_clients(app: web.Application) -> None:
    """Register the example OAuth2 clients in the in-memory client storage."""
    from navigator_auth.backends.oauth2.models import OAuthClient

    provider = app["auth"].backends["Oauth2Provider"]
    spa_client = OAuthClient(
        client_id=CLIENT_ID,
        client_pk=None,
        client_name="Navigator OAuth2 Example (SPA)",
        client_secret=None,          # public client -> PKCE S256 required
        client_type="public",
        redirect_uris=[REDIRECT_URI],
        policy_uri="",
        client_logo_uri="",
        default_scopes=["default", "profile", "email", "offline_access"],
        allowed_grant_types=["authorization_code", "refresh_token"],
    )
    await provider.client_storage.save_client(spa_client)
    logging.info("OAuth2 example: registered client %r", spa_client.client_id)
    print(f"\n  Open {BASE_URL}/ and press 'Start OAuth2 login'.")
    print("  Demo credentials: demo / demo123\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(make_app(), host=HOST, port=PORT)
