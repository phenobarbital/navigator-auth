"""Identity Vault example — login + linked external credentials.

One aiohttp application that shows the whole feature set added by the
Identity Vault (PR #582) end to end, from a single browser tab:

**Logging in** (creating a *Navigator* session), with every mechanism the
page can offer at once:

  * **Basic** — ``POST /api/v1/login`` with ``username`` / ``password``
    against ``auth.users`` (``BasicAuth`` backend).
  * **navigator-auth OAuth2 (3LO + PKCE)** — this same app is also the
    Authorization Server (``Oauth2Provider``): the page walks through
    ``/oauth2/authorize`` → ``/oauth2/token`` and ends up with a bearer
    token bound to the session.
  * **SSO with Microsoft Azure** (``AzureAuth``) and **Odoo**
    (``OdooAuth``, the new OCA ``oauth_provider`` backend) — the browser
    goes to ``/api/v1/auth/{azure,odoo}/`` and comes back logged in.

**Linking identities** — the point of the vault. Already authenticated,
the user runs a *second* OAuth2 flow against ``AzureAuth`` /
``GithubAuth`` (or any other enabled external backend) purely to capture
a credential (access + refresh token). It is stored ciphered in
``auth.user_identities`` and never creates or replaces the session:

  * ``GET /api/v1/user/identities/link/{provider}`` starts the flow,
  * ``GET /api/v1/user/identities`` lists what is linked (masked),
  * ``PUT|DELETE /api/v1/user/identities/{identity_id}`` renews / removes,
  * ``GET /api/v1/user/identities/{provider}/credential`` serves the
    decrypted credential (auto-refreshing when it expires),
  * ``GET /api/v1/user/identities/manage`` is the bundled HTML management
    page (``templates/identity/manage.html``).

All of those come from ``navigator_auth.handlers.setup_handlers``, which
``AuthHandler.setup(app)`` calls for you — there is nothing to register
by hand. The example prints the resulting route table at startup so you
can see exactly what got mounted.

**Using a credential** — ``GET /api/v1/demo/whoami/{provider}`` is the
"why": a plain server-side handler that asks the IdP for the user's
stored credential and calls the provider's API with it (Microsoft Graph,
GitHub, Odoo userinfo, Google userinfo).

Run it **from the repository root**::

    mkdir -p env/dev && touch env/dev/.env    # navconfig needs this once
    redis-server --daemonize yes              # sessions + OAuth2 flow state
    # PostgreSQL: the vault is a database feature, see DBHOST/DBNAME below
    python examples/identity_vault_server.py

then open http://localhost:5000/.

Requirements
------------
* **PostgreSQL** — unlike ``oauth2_3lo_server.py``, this example cannot run
  storage-less: linked identities live in ``auth.user_identities``. On
  startup it applies ``examples/sql/identity_vault_schema.sql`` (schema +
  a ``demo`` user) unless ``EXAMPLE_BOOTSTRAP_DB=false``. The credential
  columns and the Session Vault tables are added by the library's own
  startup migrations.
* **Redis** — sessions and per-flow OAuth2 state.
* **Vault master keys** — credentials are ciphered with the Session Vault
  keys (``VAULT_MASTER_KEY_v1`` + ``VAULT_ACTIVE_KEY_ID``). Without them
  login still works but every vault endpoint answers ``501``; the example
  prints a ready-to-paste key when they are missing.
* **Provider credentials** — each external backend is enabled *only* when
  its client id is configured (see ``PROVIDERS`` below), so you can try
  the example with just GitHub, or just Azure, or none at all.
"""
import os

# ---------------------------------------------------------------------------
# navconfig loads env/dev/.env into the environment on import; do that first
# so the provider detection below sees whatever is configured there, then set
# the example's own defaults BEFORE navigator_auth.conf is imported.
# ---------------------------------------------------------------------------
from navconfig import config  # noqa: E402

#: External backends this example can offer, and the setting that enables
#: each one. A backend is loaded only when configured — an unconfigured
#: provider would just fail mid-flow with an opaque error.
PROVIDERS = {
    "azure": ("navigator_auth.backends.AzureAuth", "AZURE_ADFS_CLIENT_ID"),
    "github": ("navigator_auth.backends.GithubAuth", "GITHUB_CLIENT_ID"),
    "odoo": ("navigator_auth.backends.OdooAuth", "ODOO_DOMAIN"),
    "google": ("navigator_auth.backends.GoogleAuth", "GOOGLE_CLIENT_ID"),
    "okta": ("navigator_auth.backends.OktaAuth", "OKTA_CLIENT_ID"),
}

CONFIGURED = {
    name: dotted
    for name, (dotted, setting) in PROVIDERS.items()
    if config.get(setting)
}

_BACKENDS = [
    "navigator_auth.backends.BasicAuth",          # username / password login
    "navigator_auth.backends.oauth2.Oauth2Provider",  # this app as OAuth2 AS
    *CONFIGURED.values(),                         # SSO + identity linking
]
# The list is passed to AuthHandler(backends=...) instead of being exported as
# AUTHENTICATION_BACKENDS: navigator_auth.conf ends with
# ``from settings.settings import *``, so when the example runs from the
# repository root (as documented above) the repo's own dev settings would win
# over the environment — and that list enables ``NoAuth``, which authenticates
# *every* request as an anonymous guest. The page would then show a logged-in
# but empty session, with no way to reach the login form.
os.environ.setdefault("AUTHENTICATION_BACKENDS", ",".join(_BACKENDS))

# OAuth2 clients in memory: no auth.clients table needed for the demo client.
os.environ.setdefault("OAUTH2_CLIENT_STORAGE", "memory")
os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me")
# Where an external (SSO) login lands once the callback succeeded.
os.environ.setdefault("AUTH_REDIRECT_URI", "/")
os.environ.setdefault("AUTH_LOGIN_FAILED_URI", "/?login_error=1")

import asyncio  # noqa: E402
import base64  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import secrets  # noqa: E402
from pathlib import Path  # noqa: E402

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from asyncdb import AsyncDB  # noqa: E402

from navigator_auth import AuthHandler  # noqa: E402
from navigator_auth.backends.idp import IdentityProvider  # noqa: E402
from navigator_auth.conf import (  # noqa: E402
    AUTH_EXCLUDE_LIST_KEY,
    ODOO_DOMAIN,
    ODOO_USERINFO_PATH,
    default_dsn,
)
from navigator_auth.decorators import is_authenticated, user_session  # noqa: E402
from navigator_auth.exceptions import ConfigError, UserNotFound  # noqa: E402
from navigator_auth.identity.crypto import IdentityCipher  # noqa: E402


HERE = Path(__file__).parent
STATIC_DIR = HERE / "static"
SCHEMA_FILE = HERE / "sql" / "identity_vault_schema.sql"

HOST = os.getenv("EXAMPLE_HOST", "localhost")
PORT = int(os.getenv("EXAMPLE_PORT", "5000"))
BASE_URL = f"http://{HOST}:{PORT}"

#: Create the demo schema + user at startup. Turn off once your database
#: already has the Navigator ``auth`` schema.
BOOTSTRAP_DB = os.getenv("EXAMPLE_BOOTSTRAP_DB", "true").lower() == "true"

#: The public (PKCE) OAuth2 client the page authenticates as when you pick
#: "Sign in with navigator-auth OAuth2".
CLIENT_ID = "nav_identity_example"
REDIRECT_URI = f"{BASE_URL}/callback"
SCOPES = "default profile email offline_access"

#: Demo account for the Basic login form.
#: The throwaway password this example seeds when nothing is configured. It is
#: a public constant, so the banner and the demo config endpoint may echo it.
DEFAULT_DEMO_PASSWORD = "demo123"

DEMO_USER = {
    "username": os.getenv("EXAMPLE_USER", "demo"),
    "password": os.getenv("EXAMPLE_PASSWORD", DEFAULT_DEMO_PASSWORD),
    "first_name": "Demo",
    "last_name": "User",
    "email": "demo@example.com",
}

#: True while the demo password is still the built-in constant. When an
#: operator overrides ``EXAMPLE_PASSWORD`` the value is a real secret: it is
#: used to seed the account, but never printed to the console and never served
#: over HTTP.
DEMO_PASSWORD_IS_DEFAULT = DEMO_USER["password"] == DEFAULT_DEMO_PASSWORD

#: What to show instead of an operator-supplied password.
DEMO_PASSWORD_DISPLAY = (
    DEFAULT_DEMO_PASSWORD if DEMO_PASSWORD_IS_DEFAULT else "<$EXAMPLE_PASSWORD>"
)

#: Where to ask "who am I?" with a linked credential. This is what a real
#: consumer (a Graph client, an Odoo RPC client, ...) would call.
PROVIDER_USERINFO = {
    "azure": "https://graph.microsoft.com/v1.0/me",
    "github": "https://api.github.com/user",
    "google": "https://www.googleapis.com/oauth2/v3/userinfo",
}


# ---------------------------------------------------------------------------
# Database bootstrap (example convenience — a real deployment has the schema)
# ---------------------------------------------------------------------------

async def bootstrap_database() -> None:
    """Apply the example schema and upsert the demo user.

    Runs *before* the application starts, on its own connection, so the
    library's own startup migrations (identity credential columns, Session
    Vault tables) find the tables they extend already in place. The
    password is hashed by the real ``IdentityProvider``, exactly as
    ``/api/v2/user/set_password`` would.
    """
    password = IdentityProvider().set_password(DEMO_USER["password"])
    db = AsyncDB("pg", dsn=default_dsn)
    async with await db.connection() as conn:
        await conn.execute(SCHEMA_FILE.read_text())
        await conn.execute(
            """
            INSERT INTO auth.users
                (username, password, first_name, last_name, email,
                 display_name, is_active, is_staff)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE, TRUE)
            ON CONFLICT (username) DO UPDATE
               SET password = EXCLUDED.password,
                   is_active = TRUE
            """,
            DEMO_USER["username"],
            password,
            DEMO_USER["first_name"],
            DEMO_USER["last_name"],
            DEMO_USER["email"],
            f"{DEMO_USER['first_name']} {DEMO_USER['last_name']}",
        )
    logging.info(
        "Identity example: schema ready, user %r usable for Basic login.",
        DEMO_USER["username"],
    )


# ---------------------------------------------------------------------------
# Application handlers
# ---------------------------------------------------------------------------

async def index(request: web.Request) -> web.StreamResponse:
    """Serve the single-page application (also handles /callback)."""
    return web.FileResponse(STATIC_DIR / "identity_vault_app.html")


async def example_config(request: web.Request) -> web.StreamResponse:
    """Describe this deployment to the page: backends, endpoints, client.

    The page renders itself from this payload instead of hard-coding a
    provider list, so it always matches the backends actually enabled.
    """
    auth = request.app["auth"]
    login_backends, link_providers = [], []
    for name, backend in auth.backends.items():
        info = backend.get_backend_info()
        login_backends.append(
            {
                "backend": name,
                "service": backend._service_name,
                "name": info.name,
                "uri": info.uri,
                "description": info.description,
                "external": info.external,
                # what to send as X-Auth-Method to target this backend
                # explicitly on /api/v1/login
                "headers": dict(info.headers or {}),
            }
        )
    for backend in auth.external_backends():
        link_providers.append(
            {
                "provider": backend._service_name,
                "description": backend._description,
                "login_uri": f"/api/v1/auth/{backend._service_name}/",
                "link_uri": (
                    f"/api/v1/user/identities/link/{backend._service_name}"
                ),
                "can_call_api": backend._service_name in PROVIDER_USERINFO
                or backend._service_name == "odoo",
            }
        )
    return web.json_response(
        {
            "backends": login_backends,
            "providers": link_providers,
            "vault_ready": request.app["vault_ready"],
            "oauth2": {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPES,
                "authorization_endpoint": "/oauth2/authorize",
                "token_endpoint": "/oauth2/token",
            },
            "endpoints": {
                "basic_login": "/api/v1/login",
                "logout": "/api/v1/logout",
                "session": "/api/v1/user/session",
                "me": "/api/v1/me",
                "identities": "/api/v1/user/identities",
                "manage_page": "/api/v1/user/identities/manage",
                "whoami": "/api/v1/demo/whoami",
            },
            "demo_user": {
                "username": DEMO_USER["username"],
                # Same rule as the console banner: an operator-supplied
                # EXAMPLE_PASSWORD is a real secret and is not handed out here.
                "password": DEMO_PASSWORD_DISPLAY,
            },
        }
    )


@is_authenticated()
@user_session()
async def me(request: web.Request, *, session=None, user=None) -> web.StreamResponse:
    """Who is logged in, and how — works for every login mechanism above."""
    userdata = request.get("userdata") or {}
    return web.json_response(
        {
            "user_id": getattr(user, "user_id", None) or getattr(user, "id", None),
            "username": getattr(user, "username", None),
            "email": getattr(user, "email", None),
            "display_name": getattr(user, "display_name", None),
            "auth_method": userdata.get("auth_method")
            or getattr(user, "auth_method", None),
            "session_id": getattr(session, "session_id", None),
        }
    )


@is_authenticated()
@user_session()
async def provider_whoami(
    request: web.Request, *, session=None, user=None
) -> web.StreamResponse:
    """Call a provider's API with the *linked* credential of this user.

    This is what the vault is for: no interactive flow, no token in the
    browser — the server asks the IdP for the credential it stored when
    the identity was linked (refreshing it if it expired) and uses it.
    """
    provider = request.match_info["provider"]
    user_id = getattr(user, "user_id", None) or getattr(user, "id", None)
    idp = request.app["auth"]._idp
    try:
        credential = await idp.get_user_identity_credential(user_id, provider)
    except UserNotFound as err:
        raise web.HTTPNotFound(
            text=json.dumps({"error": str(err), "provider": provider}),
            content_type="application/json",
        )
    url = PROVIDER_USERINFO.get(provider)
    if not url and provider == "odoo":
        url = f"{(ODOO_DOMAIN or '').rstrip('/')}{ODOO_USERINFO_PATH}"
    if not url:
        raise web.HTTPBadRequest(
            text=json.dumps(
                {"error": f"no demo API call defined for {provider}"}
            ),
            content_type="application/json",
        )
    headers = {
        "Authorization": f"{credential['token_type']} {credential['access_token']}",
        "Accept": "application/json",
    }
    async with aiohttp.ClientSession() as http:
        async with http.get(url, headers=headers) as response:
            body = await response.text()
            status = response.status
    return web.json_response(
        {
            "provider": provider,
            "called": url,
            "status": status,
            # the credential itself never leaves the server: only proof
            # that it was used, and when it expires.
            "credential": {
                "token_type": credential["token_type"],
                "expires_at": credential["expires_at"],
                "scopes": credential["scopes"],
                "has_refresh_token": bool(credential["refresh_token"]),
            },
            "response": body,
        },
        status=200 if status < 400 else 502,
    )


# ---------------------------------------------------------------------------
# Startup helpers
# ---------------------------------------------------------------------------

async def register_demo_client(app: web.Application) -> None:
    """Register the PKCE client used by the "OAuth2 login" button."""
    from navigator_auth.backends.oauth2.models import OAuthClient

    provider = app["auth"].backends["Oauth2Provider"]
    client = OAuthClient(
        client_id=CLIENT_ID,
        client_pk=None,
        client_name="Navigator Identity Vault Example",
        client_secret=None,           # public client -> PKCE S256 required
        client_type="public",
        redirect_uris=[REDIRECT_URI],
        policy_uri="",
        client_logo_uri="",
        default_scopes=["default", "profile", "email", "offline_access"],
        allowed_grant_types=["authorization_code", "refresh_token"],
    )
    await provider.client_storage.save_client(client)


def check_vault_keys() -> bool:
    """Warn (loudly) when credentials cannot be ciphered.

    Exactly the check the vault endpoints do before touching a credential
    (they answer 501 when it fails): the Session Vault master keys must be
    configured and ``navigator-session`` must ship the vault crypto. Login
    and SSO keep working either way.
    """
    try:
        IdentityCipher()
        return True
    except ConfigError as err:
        suggestion = base64.b64encode(secrets.token_bytes(32)).decode()
        print(
            f"\n  !! Identity Vault disabled: {err}\n"
            "     Add this to env/dev/.env (keep it — replacing the key makes\n"
            "     already-stored credentials unreadable):\n\n"
            f"       VAULT_MASTER_KEY_v1={suggestion}\n"
            "       VAULT_ACTIVE_KEY_ID=1\n"
        )
        return False


def print_banner(app: web.Application) -> None:
    """Show what got mounted — including the routes ``setup_handlers`` added."""
    print(f"\n  navigator-auth Identity Vault example — {BASE_URL}/\n")
    print(f"  Basic login .......... {DEMO_USER['username']} / {DEMO_PASSWORD_DISPLAY}")
    print(f"  OAuth2 client ........ {CLIENT_ID} (public, PKCE S256)")
    enabled = ", ".join(CONFIGURED) or "(none configured)"
    print(f"  External providers ... {enabled}")
    print(f"  Vault master keys .... {'configured' if app['vault_ready'] else 'MISSING (501)'}")
    print("\n  Identity Vault routes registered by AuthHandler.setup():")
    for resource in app.router.resources():
        path = getattr(resource, "canonical", "")
        if "identities" in path:
            print(f"    {path}")
    print()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def make_app() -> web.Application:
    app = web.Application()

    # enable_authdb defaults to True: the vault needs the PostgreSQL pool
    # (app["authdb"]) both for auth.user_identities and for the startup
    # migrations that add the credential columns. ``backends`` pins exactly
    # the backends this example demonstrates (see _BACKENDS above), and
    # ``authz_backends=[]`` disables *authorization* backends: an inherited
    # ``allow_hosts`` (ALLOWED_HOSTS defaults to ``localhost*``) would
    # authorize every request from the browser without a session, so the
    # endpoints would answer with an empty identity instead of 401.
    auth = AuthHandler(backends=_BACKENDS, authz_backends=[])

    # setup() mounts everything: /api/v1/login, the OAuth2 provider, one
    # login + callback pair per external backend, and — via setup_handlers —
    # the whole Identity Vault API and its management page.
    auth.setup(app)

    app["vault_ready"] = check_vault_keys()

    app.router.add_static("/static/", path=STATIC_DIR, name="static")
    app.router.add_get("/", index, name="index")
    app.router.add_get("/callback", index, name="oauth2_callback")
    app.router.add_get("/example-config", example_config, name="example_config")
    app.router.add_get("/api/v1/me", me, name="me")
    app.router.add_get(
        r"/api/v1/demo/whoami/{provider:[a-z0-9_]+}",
        provider_whoami,
        name="demo_whoami",
    )

    # the page shell and its configuration are public; everything else is not.
    app[AUTH_EXCLUDE_LIST_KEY].extend(["/", "/callback", "/example-config"])

    app.on_startup.append(register_demo_client)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if BOOTSTRAP_DB:
        # own event loop, before the app is built: AuthHandler's startup
        # migrations expect auth.users / auth.user_identities to exist.
        try:
            asyncio.run(bootstrap_database())
        except Exception as exc:  # pylint: disable=W0703
            raise SystemExit(
                f"\n  Database bootstrap failed: {exc}\n"
                "  Check DBHOST/DBPORT/DBNAME/DBUSER/DBPWD in env/dev/.env,\n"
                f"  or apply {SCHEMA_FILE} yourself and re-run with "
                "EXAMPLE_BOOTSTRAP_DB=false.\n"
            ) from exc
    application = make_app()
    print_banner(application)
    web.run_app(application, host=HOST, port=PORT)
