import os
# Set Environment Variables BEFORE importing navigator_auth or navconfig
os.environ["NAV_AUTHENTICATION_BACKENDS"] = "navigator_auth.backends.oauth2.Oauth2Provider"
os.environ["NAV_OAUTH2_CLIENT_STORAGE"] = "memory" 
os.environ["NAV_API_HOST"] = "localhost" # Ensure host is set

import logging
from aiohttp import web
from navigator_auth import AuthHandler
from navigator_auth.conf import exclude_list
from navconfig import BASE_DIR
# Configure other settings as needed

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
exclude_list.append('/login')

if __name__ == '__main__':
    async def populate_client(app):
        try:
            auth_handler = app.get('auth') 
            if auth_handler and 'Oauth2Provider' in auth_handler.backends:
                provider = auth_handler.backends['Oauth2Provider']
                from navigator_auth.backends.oauth2.models import OauthUser, OAuthClient
                # Mock User
                user = OauthUser(user_id="35", username="testuser", given_name="Test", family_name="User")
                
                # If using PostgresClientStorage, client_id is auto-increment.
                # However, for testing we want a known ID.
                # Since we are using an abstract storage, we might validly pass None for ID if it's auto-generated.
                # But for Memory/Redis we need an ID.
                
                # Let's try to assume we can set an ID for test purposes if the backend supports it,
                # or we just rely on the storage to give us one.
                
                # IMPORTANT: If DB has bigserial, we usually omit client_id on insert.
                # But here we are constructing the object.
                
                # For `PostgresClientStorage` we need to be careful.
                # Let's use ID 1 for testing.
                
                client = OAuthClient(
                    client_id="1", # Pydantic will handle string "1" -> DB might want int.
                    client_name="TROC Navigator",
                    client_secret="test_client_secret",
                    client_type="public",
                    redirect_uris=["http://localhost:5000/static/callback.html"],
                    policy_uri="",
                    client_logo_uri="",
                    user=user,
                    allowed_grant_types=["authorization_code", "client_credentials"]
                )
                
                # If using Postgres, we need an active connection.
                # In startup we don't have request, so we use app['authdb'] manually.
                
                db = app.get('authdb')
                if db:
                    # Provide connection to the Model
                    async with await db.acquire() as conn:
                         # We need the actual ClientModel to set connection, 
                         # or rely on provider.client_storage to use it? 
                         # But PostgresClientStorage.save_client(request=None) doesn't set connection.
                         # So we must set it on the Model class globally (context-local usually).
                         
                         from navigator_auth.models import Client as ClientModel
                         ClientModel.Meta.connection = conn
                         await provider.client_storage.save_client(client)
                else:
                    # Memory storage usage?
                    await provider.client_storage.save_client(client)

                print(f"Test Client Created: {client.client_id} / {client.client_secret}")
        except Exception as e:
            print(f"Error populating client: {e}")

    app.on_startup.append(populate_client)
    web.run_app(app, host='localhost', port=5000)
