"""Example OAuth2 authorization-server application.

FEAT-093 production-grade 3LO demonstration:

  - client_id is an opaque string uid (never an integer).
  - PKCE S256 enforced for the public client.
  - Refresh token rotation with reuse-detection.
  - RFC 7009 /oauth2/revoke endpoint.
  - Per-app consent grants (/oauth2/grants).
  - Scope-gated /oauth2/userinfo claims.
  - Scope ↔ ABAC composition via @scope_required.

Run with:
    python examples/oauth2_server.py

Then open http://localhost:5000/login to start the 3LO flow.
"""

import os

# Set Environment Variables BEFORE importing navigator_auth or navconfig
os.environ["NAV_AUTHENTICATION_BACKENDS"] = "navigator_auth.backends.oauth2.Oauth2Provider"
os.environ["NAV_OAUTH2_CLIENT_STORAGE"] = "memory"
os.environ["NAV_API_HOST"] = "localhost"

import logging
from aiohttp import web
from navigator_auth import AuthHandler
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navconfig import BASE_DIR


async def home(request):
    path = BASE_DIR / 'examples' / 'static' / 'oauth2_index.html'
    return web.FileResponse(path)


app = web.Application()

# Static files
app.router.add_static('/static/', path=BASE_DIR / 'examples' / 'static', name='static')

# Auth System
auth = AuthHandler()
auth.setup(app)

app.add_routes([
    web.get('/login', home)
])
app[AUTH_EXCLUDE_LIST_KEY].append('/login')


if __name__ == '__main__':
    async def populate_clients(app):
        """Register test OAuth2 clients on startup.

        FEAT-093 3LO model:
          - public_client   : S256 PKCE required, no secret, authorization_code only.
          - confidential_client : has secret, supports authorization_code + client_credentials.

        Both use opaque string client_id values (never integers).
        client_pk is None for in-memory clients (no DB PK needed).
        """
        try:
            auth_handler = app.get('auth')
            if auth_handler and 'Oauth2Provider' in auth_handler.backends:
                provider = auth_handler.backends['Oauth2Provider']
                from navigator_auth.backends.oauth2.models import OauthUser, OAuthClient

                # Resource-owner placeholder — only used as metadata for the client,
                # NEVER as the source of user_id in 3LO tokens.
                resource_owner = OauthUser(
                    user_id=35,
                    username="testuser",
                    given_name="Test",
                    family_name="User",
                )

                # --- Public client (S256 PKCE required) ---
                public_client = OAuthClient(
                    client_id="nav_public_client",       # opaque uid — appears on wire
                    client_pk=None,                      # no int PK for in-memory store
                    client_name="Navigator Web App",
                    client_secret=None,                  # public: no secret
                    client_type="public",
                    redirect_uris=["http://localhost:5000/static/callback.html"],
                    policy_uri="",
                    client_logo_uri="",
                    user=resource_owner,
                    default_scopes=["default", "profile", "email", "offline_access"],
                    allowed_grant_types=["authorization_code"],
                )

                # --- Confidential client (authorization_code + client_credentials) ---
                confidential_client = OAuthClient(
                    client_id="nav_confidential_client",
                    client_pk=None,
                    client_name="Navigator Service",
                    client_secret="confidential_s3cr3t",
                    client_type="confidential",
                    redirect_uris=["http://localhost:5000/static/callback.html"],
                    policy_uri="",
                    client_logo_uri="",
                    user=resource_owner,
                    default_scopes=["default", "profile", "email", "offline_access"],
                    allowed_grant_types=[
                        "authorization_code",
                        "client_credentials",
                        "refresh_token",
                    ],
                )

                db = app.get('authdb')
                for client in (public_client, confidential_client):
                    if db:
                        async with await db.acquire() as conn:
                            from navigator_auth.models import Client as ClientModel
                            ClientModel.Meta.connection = conn
                            await provider.client_storage.save_client(client)
                    else:
                        await provider.client_storage.save_client(client)
                    print(
                        f"Registered client: {client.client_id!r} "
                        f"(type={client.client_type}, "
                        f"grants={client.allowed_grant_types})"
                    )

                print()
                print("3LO flow (public client + PKCE S256):")
                print(
                    "  GET http://localhost:5000/oauth2/authorize"
                    "?response_type=code"
                    "&client_id=nav_public_client"
                    "&redirect_uri=http://localhost:5000/static/callback.html"
                    "&scope=default+profile+email+offline_access"
                    "&state=test_state"
                    "&code_challenge=<S256_hash>&code_challenge_method=S256"
                )
        except Exception as e:
            print(f"Error populating clients: {e}")
            logging.exception("populate_clients failed")

    app.on_startup.append(populate_clients)
    web.run_app(app, host='localhost', port=5000)
