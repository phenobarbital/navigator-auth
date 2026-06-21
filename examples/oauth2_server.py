"""Example OAuth2 authorization-server application.

FEAT-093 TASK-023: Test client now uses a fixed opaque string ``client_uid``
(``nav_test_client``) instead of the integer ``client_id=1``.  This mirrors
the production model where the public identifier on the wire is always an
opaque string.
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
    async def populate_client(app):
        """Register a test OAuth2 client using an opaque string client_uid."""
        try:
            auth_handler = app.get('auth')
            if auth_handler and 'Oauth2Provider' in auth_handler.backends:
                provider = auth_handler.backends['Oauth2Provider']
                from navigator_auth.backends.oauth2.models import OauthUser, OAuthClient

                # Mock resource-owner user (used for client_credentials only).
                user = OauthUser(
                    user_id=35,
                    username="testuser",
                    given_name="Test",
                    family_name="User",
                )

                # FEAT-093 TASK-023: client_id is now the PUBLIC opaque uid.
                # Integer PK is irrelevant for in-memory / Redis stores.
                client = OAuthClient(
                    client_id="nav_test_client",          # opaque public uid
                    client_name="TROC Navigator",
                    client_secret="test_client_secret",
                    client_type="public",
                    redirect_uris=["http://localhost:5000/static/callback.html"],
                    policy_uri="",
                    client_logo_uri="",
                    user=user,
                    default_scopes=["default", "profile", "email", "offline_access"],
                    allowed_grant_types=["authorization_code", "client_credentials"],
                )

                db = app.get('authdb')
                if db:
                    async with await db.acquire() as conn:
                        from navigator_auth.models import Client as ClientModel
                        ClientModel.Meta.connection = conn
                        await provider.client_storage.save_client(client)
                else:
                    # Memory / Redis storage — no DB connection needed.
                    await provider.client_storage.save_client(client)

                print(f"Test Client Created: {client.client_id} / {client.client_secret}")
        except Exception as e:
            print(f"Error populating client: {e}")
            logging.exception("populate_client failed")

    app.on_startup.append(populate_client)
    web.run_app(app, host='localhost', port=5000)
