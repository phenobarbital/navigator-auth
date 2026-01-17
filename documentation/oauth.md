# OAuth2 in Navigator-Auth

`navigator-auth` provides a robust OAuth2 Provider implementation, allowing you to secure your applications using standard OAuth2 flows. It supports multiple backends for client and token storage, and integrates seamlessly with `navigator-session`.

## 1. Definition of Clients

In OAuth2, a "Client" is the application attempting to access the user's account. In `navigator-auth`, a client is defined by:
-   **Client ID**: A unique identifier for the application.
-   **Client Secret**: A secret password known only to the application (confidential clients).
-   **Redirect URIs**: A whitelist of URIs where the user is redirected after authentication.
-   **Allowed Grant Types**: The OAuth2 flows the client is allowed to use.
-   **Scope**: The permissions the client is requesting.

## 2. How OAuth2 works at Navigator-Auth

`navigator-auth` acts as an Authorization Server. It validates the user's credentials (via `navigator-session` or direct login) and issues Access Tokens and Refresh Tokens.

-   **Endpoints**:
    -   `/oauth2/authorize`: The entry point for the Authorization Code flow (User Login & Consent).
    -   `/oauth2/token`: The endpoint for exchanging codes or credentials for tokens.
    -   `/oauth2/login`: The login page.
    -   `/oauth2/consent`: The user consent page.
    -   `/oauth2/userinfo`: (Optional) User profile information.

## 3. How to enable OAuth2 in Navigator-Auth

Settings in your configuration (e.g., `settings.py` or `.env` via `navconfig`):

```python
# Enable OAuth2
OAUTH2_CLIENT_STORAGE = 'redis'  # Options: 'postgres', 'redis', 'memory'

# Customize URIs (Optional - defaults shown)
AUTH_OAUTH2_REDIRECT_URL = '/'
```

In your application code:

```python
from navigator_auth import AuthHandler

auth = AuthHandler()
# ... register auth routes ...
```

The OAuth2 routes are automatically set up by the `Oauth2Provider` backend.

## 4. Backends

Navigator-Auth supports different storage backends for persisting OAuth2 Clients, Authorization Codes, and Refresh Tokens.

-   **Memory**: Best for testing/development. Data is lost on restart.
    -   Config: `OAUTH2_CLIENT_STORAGE = 'memory'`
-   **Redis**: High performance, good for production.
    -   Config: `OAUTH2_CLIENT_STORAGE = 'redis'`
    -   Requires `REDIS_URL` to be configured.
-   **Postgres**: Persistent relational storage.
    -   Config: `OAUTH2_CLIENT_STORAGE = 'postgres'`
    -   Requires `DBHOST`, `DBUSER`, `DBPWD`, etc.

## 5. Authorization Flows

### Authorization Code Flow
Best for server-side applications (web apps).
1.  **User Authorization**: Redirect user to `/oauth2/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...`.
2.  **Login & Consent**: User logs in and approves access.
3.  **Code Exchange**: Server redirects back to `redirect_uri` with a `code`.
4.  **Token Request**: Client creates a POST request to `/oauth2/token` with `grant_type=authorization_code`, `code`, `client_id`, `client_secret`.
5.  **Response**: Receives `access_token` and `refresh_token`.

### Client Credentials Flow
Best for machine-to-machine communication (services, daemons).
1.  **Token Request**: Client makes a POST request to `/oauth2/token` with `grant_type=client_credentials`, `client_id`, `client_secret`.
2.  **Response**: Receives an `access_token` (app-level token).

### Refresh Token Flow
Used to get a new Access Token when the old one expires.
1.  **Token Request**: Client makes a POST request to `/oauth2/token` with `grant_type=refresh_token`, `refresh_token`, `client_id`, `client_secret`.
2.  **Response**: Receives a new `access_token`.

## 6. Usage of Refresh Tokens

Refresh tokens are long-lived credentials used to obtain new access tokens.
-   **Expiration**: Default is 30 days.
-   **Revocation**: If a refresh token is revoked (e.g., user logout, security breach), it can no longer be used.
-   **Security**: Refresh tokens must be stored securely by the client.

## 7. FAQ

**Q: What is the duration of a Session?**
A: Controlled by `SESSION_TIMEOUT`. If using Redis, it matches the configured `max_age` (default is often session-based or configurable).

**Q: What is the duration of an Access Token?**
A: Access tokens default to `OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS` (default 4 days) or the `SESSION_TIMEOUT`, depending on the flow settings.

**Q: What is the duration of a Refresh Token?**
A: Currently defaulted to 30 days.

**Q: Where is User data stored?**
A: User data is linked to the Access Token (via JWT claims) and the Session (stored in Redis/Cookie). The `userinfo` endpoint can retrieve current user details.
