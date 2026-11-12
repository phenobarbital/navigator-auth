---
id: FW-005
query_id: Q004
type: read
intent: "Follow-up: which examples pass AuthHandler(backends=...) and what the README says about the settings.settings override."
executed_at: 2026-11-11T14:40:00Z
duration_ms: 400
parent_id: FW-004
depth: 1
---

# FW-005 — identity_vault example already fixed the settings override; the 3LO example did not

## Summary

`examples/README.md` documents that `navigator_auth.conf` ends with
`from settings.settings import *`, so a `settings/settings.py` in the working directory
(the repo root, where the 3LO example must run) overrides the environment, enabling
`NoAuth` (anonymous for every request) and `allow_hosts`/`allowed_ips` authorization.
`examples/identity_vault_server.py` works around it with
`AuthHandler(backends=_BACKENDS, authz_backends=[])`, with a comment explaining that
`os.environ.setdefault("AUTHENTICATION_BACKENDS", ...)` is not enough. `examples/oauth2_3lo_server.py`
still relies only on `os.environ.setdefault(...)` and calls `AuthHandler(enable_authdb=False)`
— so the backend list it asked for (Oauth2Provider only) is not the one that runs. That
matches the report's log: TrocToken, NoAuth, AzureAuth, ADFSAuth and APIKeyAuth all active.

## Citations

- path: `examples/README.md`
  lines: 140-147
  symbol: "`AUTHENTICATION_BACKENDS` including `NoAuth`" (identity-vault section)
  wiki: `file:examples/README.md` (score 0.36 in Q001-orientation)
  excerpt: |
    * **`AUTHENTICATION_BACKENDS` including `NoAuth`** — `navigator_auth.conf` ends
      with `from settings.settings import *`, so a `settings/settings.py` in the
      working directory overrides whatever the environment says. `NoAuth`
      authenticates *every* request as an anonymous guest.
    * **`AUTHORIZATION_BACKENDS=allow_hosts,allowed_ips`** — an authorization
      backend lets a request *through* without authenticating it ...

- path: `examples/identity_vault_server.py`
  lines: 108-119
  symbol: `_BACKENDS`
  excerpt: |
    # The list is passed to AuthHandler(backends=...) instead of being exported as
    # AUTHENTICATION_BACKENDS: navigator_auth.conf ends with
    # ``from settings.settings import *``, so when the example runs from the
    # repository root (as documented above) the repo's own dev settings would win
    # over the environment — and that list enables ``NoAuth``, ...

- path: `examples/identity_vault_server.py`
  lines: 722
  symbol: `AuthHandler(backends=_BACKENDS, authz_backends=[])`

- path: `examples/oauth2_3lo_server.py`
  lines: 218
  symbol: `make_app`
  excerpt: |
    auth = AuthHandler(enable_authdb=False)

## Notes

- Grep of `AuthHandler(` across `examples/*.py`: only `identity_vault_server.py:722` passes
  `backends=`; `oauth2_mcp_server.py:290` passes kwargs (not inspected); `oauth2_server.py:55`,
  `policy_server.py:532`, `test_*.py` use the bare constructor.
- The 3LO section of the README (lines ~10-75) does not carry the NoAuth warning.
- The same override plausibly explains the 6-byte HMAC key and `iss: 'Mobileinsight'` in the
  decoded token (example's `AUTH_SECRET_KEY` setdefault also lost) — unverified here.
- [cross-lane: type=read, intent=Does settings/settings.py exist at repo root and what AUTHENTICATION_BACKENDS / AUTHORIZATION_BACKENDS / AUTH_SECRET_KEY / issuer does it set?]
- [cross-lane: type=read, intent=Does any other enabled backend (TrocToken/TokenAuth/BasicAuth via DB) explain how /oauth2/login produced user_id=35 while DemoIdentityProvider only knows 1 and 2?]
