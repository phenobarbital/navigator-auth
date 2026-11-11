---
kind: inline
jira_key: null
fetched_at: 2026-11-11T14:30:00Z
summary_oneline: "OAuth2 3LO example: /api/v1/me 500s, session bind fails for user 35, anonymous passes, grants 401, userinfo empty"
---

oauth2-3lo-issues -- Oauth2 3lo issues:

When executed `python examples/oauth2_3lo_server.py` for testing Oauth2 3LO support at navigator-auth we got these issues:

* When clicked "/api/v1/me" we got a 500 internal server error:
```
[WARNING] 2026-11-11 14:19:05,480 Auth.Oauth2Provider(backend.py:700) :: Oauth2: cannot bind a session to the token for user_id=35: Invalid Credentials for user_id=35
/home/jesuslara/proyectos/navigator-auth/.venv/lib/python3.11/site-packages/jwt/api_jwt.py:147: InsecureKeyLengthWarning: The HMAC key is 6 bytes long, which is below the minimum recommended length of 32 bytes for SHA256. See RFC 7518 Section 3.2.
  return self._jws.encode(
/home/jesuslara/proyectos/navigator-auth/.venv/lib/python3.11/site-packages/jwt/api_jwt.py:368: InsecureKeyLengthWarning: The HMAC key is 6 bytes long, which is below the minimum recommended length of 32 bytes for SHA256. See RFC 7518 Section 3.2.
  decoded = self.decode_complete(
[DEBUG] 2026-11-11 14:19:14,680 Auth.IdP(__init__.py:494) :: Decoded Token: {'exp': 1794404045.480366, 'iat': 1794403145, 'iss': 'Mobileinsight', 'jti': '43bd9438-4094-4159-be28-348be19e3e35', 'user_id': 35, 'client_id': 'nav_example_spa', 'scope': 'default profile email offline_access', 'aud': 'user'}
[DEBUG] 2026-11-11 14:19:14,680 Auth.TrocToken(troc.py:213) :: MIDDLEWARE: TrocToken
[DEBUG] 2026-11-11 14:19:14,680 Auth.IdP(__init__.py:494) :: Decoded Token: {'exp': 1794404045.480366, 'iat': 1794403145, 'iss': 'Mobileinsight', 'jti': '43bd9438-4094-4159-be28-348be19e3e35', 'user_id': 35, 'client_id': 'nav_example_spa', 'scope': 'default profile email offline_access', 'aud': 'user'}
[DEBUG] 2026-11-11 14:19:14,682 root(external.py:253) :: DOMAIN: http://localhost:5000
[NOTICE] 2026-11-11 14:19:14,682 :: Redirect URL: http://localhost:5000/
[DEBUG] 2026-11-11 14:19:14,683 root(external.py:253) :: DOMAIN: http://localhost:5000
[NOTICE] 2026-11-11 14:19:14,683 :: Redirect URL: http://localhost:5000/auth/azure/callback/
/home/jesuslara/proyectos/navigator-auth/.venv/lib/python3.11/site-packages/msal/oauth2cli/oauth2.py:461: UserWarning: response_mode='form_post' is recommended for better security. See https://www.rfc-editor.org/rfc/rfc9700.html#section-4.3.1
  warnings.warn(
[DEBUG] 2026-11-11 14:19:14,917 root(external.py:288) :: AzureAuth URI: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize?client_id=<azure-client-id>&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fauth%2Fazure%2Fcallback%2F&scope=...&state=...&code_challenge=...&code_challenge_method=S256&nonce=...&client_info=1&domain_hint=mobileinsight.com&max_age=120
[DEBUG] 2026-11-11 14:19:14,917 Auth.IdP(__init__.py:494) :: Decoded Token: {'exp': 1794404045.480366, 'iat': 1794403145, 'iss': 'Mobileinsight', 'jti': '43bd9438-4094-4159-be28-348be19e3e35', 'user_id': 35, 'client_id': 'nav_example_spa', 'scope': 'default profile email offline_access', 'aud': 'user'}
[ERROR] 2026-11-11 14:19:14,918 aiohttp.server(web_protocol.py:546) :: Error handling request from ::1
Traceback (most recent call last):
  File ".../aiohttp/web_protocol.py", line 575, in _handle_request
  File ".../aiohttp/web_app.py", line 559, in _handle
  File ".../aiohttp/web_middlewares.py", line 117, in impl
  File ".../navigator_session/middleware.py", line 38, in middleware
  File "navigator_auth/backends/api.py", line 292, in auth_middleware
    return await handler(self.sanitize(request))
  File "navigator_auth/backends/token.py", line 200, in auth_middleware
    return await handler(request)
  File "navigator_auth/backends/troc.py", line 218, in auth_middleware
    return await handler(request)
  File "navigator_auth/auth.py", line 1040, in auth_middleware
    return await self._auth_middleware(request, handler)
  File "navigator_auth/auth.py", line 1073, in _auth_middleware
    return await handler(request)
  File "navigator_auth/middlewares/csrf.py", line 81, in csrf_middleware
  File "navigator_auth/middlewares/security.py", line 26, in security_middleware
  File "navigator_auth/middlewares/version.py", line 31, in version_middleware
  File "navigator_auth/decorators.py", line 217, in _wrap
    result = await backend.authenticate(request)
  File "navigator_auth/backends/api.py", line 154, in authenticate
    device_id = str(data["device_id"])
                    ~~~~^^^^^^^^^^^^^
TypeError: 'bool' object is not subscriptable
```

* When clicked at userinfo we got:
```
[DEBUG] 2026-11-11 14:20:24,370 Auth.Oauth2Provider(backend.py:490) :: Redirect URI: http://localhost:5000/callback?code=...&state=...
[WARNING] 2026-11-11 14:20:24,671 Auth.Oauth2Provider(backend.py:700) :: Oauth2: cannot bind a session to the token for user_id=35: Invalid Credentials for user_id=35
[WARNING] 2026-11-11 14:20:31,241 Auth.Oauth2Provider(backend.py:700) :: Oauth2: cannot bind a session to the token for user_id=35: Invalid Credentials for user_id=35
```

* When clicked at "Refresh Token" we got a token but a warning in log:
```
[WARNING] 2026-11-11 14:24:29,713 Auth.Oauth2Provider(backend.py:700) :: Oauth2: cannot bind a session to the token for user_id=35: Invalid Credentials for user_id=35
```

* When clicked at "Call it without credentials (expect 401)", instead of 401, a 200 OK with anonymous dict:
```
{
  "message": "Hello Anonymous 3031c458b03942fbaed29aa961e5e4d5!",
  "user": {"user_id": "3031c458...", "username": "Anonymous 3031c458...", "email": null, "first_name": null, "last_name": null},
  "session_id": "a897b54fb7eb4b599b0eaa4d9a9109fb",
  "token_claims": {"client_id": null, "scope": null, "jti": null, "aud": null}
}
```

Log:
```
[NOTICE] 2026-11-11 14:21:01,940 :: Redirect URL: http://localhost:5000/
[DEBUG] 2026-11-11 14:21:01,940 root(external.py:288) :: ADFSAuth URI: https://sso.<adfs-host>/adfs/oauth2/authorize/?client_id=navigator_dev.adfs.client_id&...
[DEBUG] 2026-11-11 14:21:01,940 Auth.NoAuth(abstract.py:179) :: User Created > Anonymous 3031c458b03942fbaed29aa961e5e4d5
[DEBUG] 2026-11-11 14:21:01,940 root(noauth.py:60) :: User Created > AnonymousUser(id='3031c458...', is_authenticated=False, groups=[Group(group='guest')], ...)
[DEBUG] 2026-11-11 14:21:01,941 SessionHandler(redis.py:311) :: :::::: CREATING A NEW SESSION FOR a897b54fb7eb4b599b0eaa4d9a9109fb :::::
```

* When click on "List my grants":
```
[DEBUG] 2026-11-11 14:22:02,343 Auth.IdP(__init__.py:494) :: Decoded Token: {..., 'user_id': 35, 'client_id': 'nav_example_spa', 'scope': 'default profile email offline_access', 'aud': 'user'}
[DEBUG] 2026-11-11 14:22:02,343 Auth.TrocToken(troc.py:213) :: MIDDLEWARE: TrocToken
[DEBUG] 2026-11-11 14:22:02,343 Auth.IdP(__init__.py:494) :: Decoded Token: {..., 'user_id': 35, ...}
```
a 401 with "unauthorized":
{"error":"unauthorized","error_description":"Not authenticated."}

* When clicked "oauth2/userinfo" we got a 200 OK with:
```
{"sub":"35","username":"","given_name":"","family_name":"","email":""}
```

> Note: Azure tenant/client ids, ADFS host and auth codes were redacted from the
> original paste before committing; they carry no diagnostic value. The full
> paste is in the /sdd-proposal invocation of 2026-11-11.

---

## Addendum (2026-11-11, reported mid-run)

new issue in Oauth:

- When `examples/oauth2_server.py` is running and launch the 3LO flow:
```
3LO flow (public client + PKCE S256):
  GET http://localhost:5000/oauth2/authorize?response_type=code&client_id=nav_public_client&redirect_uri=http://localhost:5000/static/callback.html&scope=default+profile+email+offline_access&state=test_state&code_challenge=<S256_hash>&code_challenge_method=S256
```

I got "Callback Received / Code: <redacted>"

but when clicked on button "Exchange code for token: Get Token", I got:
```
{
  "error": "invalid_grant",
  "error_description": "code_verifier required."
}
```
