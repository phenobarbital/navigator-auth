---
id: FC-003
query_id: Q016
type: grep
intent: "How AUTHENTICATION_BACKENDS and AUTH_SECRET_KEY are read (navconfig vs os.environ precedence)."
executed_at: 2026-11-11T14:42:00Z
duration_ms: 2500
parent_id: null
depth: 1
---

# FC-003 — The example's os.environ defaults lose to the developer's local settings and env file

## Summary

`navigator_auth/conf.py` reads `AUTHENTICATION_BACKENDS`, `AUTHORIZATION_BACKENDS`
and `AUTH_SECRET_KEY` through navconfig, then star-imports `settings.settings` LAST
(913-915), which overrides any of them. Run from the repo root, the gitignored
`settings/settings.py` defines 8 backends (Azure, APIKey, Token, TrocToken, ADFS,
Oauth2Provider, Basic, NoAuth). navconfig loads `env/.env` (ENV unset), whose values
win over `os.environ.setdefault`: AUTH_SECRET_KEY resolves to a 6-byte value (the
InsecureKeyLengthWarning), and `AUTHORIZATION_BACKENDS=allow_hosts,allowed_ips` with
`ALLOWED_HOSTS` defaulting to `localhost*`. `AuthHandler` already accepts
`backends=` / `authz_backends=` precisely to make examples independent of this
(docstring), and `examples/identity_vault_server.py` uses them — the 3LO example
does not (`AuthHandler(enable_authdb=False)` only).

## Citations

- path: `navigator_auth/conf.py`
  lines: 190-196
  symbol: `AUTHENTICATION_BACKENDS`
  excerpt: |
    AUTHENTICATION_BACKENDS = tuple(
        e.strip() for e in config.get("AUTHENTICATION_BACKENDS", fallback="").split(",") if e.strip()
    )
    AUTHORIZATION_BACKENDS = [e.strip() for e in config.get("AUTHORIZATION_BACKENDS", fallback="").split(",") if e.strip()]

- path: `navigator_auth/conf.py`
  lines: 152
  symbol: `ALLOWED_HOSTS`
  excerpt: |
    ALLOWED_HOSTS = [e.strip() for e in list(config.get("ALLOWED_HOSTS", fallback="localhost*").split(","))]

- path: `navigator_auth/conf.py`
  lines: 305-308
  symbol: `SECRET_KEY`
  excerpt: |
    SECRET_KEY = config.get("AUTH_SECRET_KEY")
    if not SECRET_KEY:
        fernet_key = fernet.Fernet.generate_key()

- path: `navigator_auth/conf.py`
  lines: 912-915
  symbol: `settings override`
  excerpt: |
    with contextlib.suppress(ImportError):
        from settings.settings import *  # noqa
    with contextlib.suppress(ImportError):
        from settings import *  # noqa

- path: `settings/settings.py`
  lines: 19-32
  symbol: `AUTHENTICATION_BACKENDS`
  excerpt: |
    AUTHENTICATION_BACKENDS = (
        'navigator_auth.backends.AzureAuth',
        'navigator_auth.backends.APIKeyAuth',
        'navigator_auth.backends.TokenAuth',
        'navigator_auth.backends.TrocToken',
        'navigator_auth.backends.ADFSAuth',
        'navigator_auth.backends.Oauth2Provider',
        'navigator_auth.backends.BasicAuth',
        'navigator_auth.backends.NoAuth',
    )

- path: `navigator_auth/auth.py`
  lines: 116-132
  symbol: `AuthHandler.__init__`
  excerpt: |
    backends: explicit list of dotted paths to the authentication
        backends to enable, overriding ``AUTHENTICATION_BACKENDS``.
        Use it when the enabled backends are a property of the
        application itself (the bundled examples do) ...
    authz_backends: ... Pass an empty list to require authentication for every request
    self._backend_list: tuple = tuple(backends) if backends is not None else AUTHENTICATION_BACKENDS

- path: `examples/identity_vault_server.py`
  lines: 722
  symbol: `AuthHandler(...)`
  excerpt: |
    auth = AuthHandler(backends=_BACKENDS, authz_backends=[])

- path: `examples/oauth2_3lo_server.py`
  lines: 44-53, 218
  symbol: `os.environ.setdefault / make_app`
  excerpt: |
    os.environ.setdefault("AUTHENTICATION_BACKENDS", "navigator_auth.backends.oauth2.Oauth2Provider")
    os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me")
    ...
    auth = AuthHandler(enable_authdb=False)

## Notes

Runtime probe (venv, repo root, same setdefault as the example):
`conf.AUTHENTICATION_BACKENDS` → AzureAuth, APIKeyAuth, TokenAuth, TrocToken, ADFSAuth,
Oauth2Provider, BasicAuth, NoAuth; `conf.AUTHORIZATION_BACKENDS` → ['allow_hosts',
'allowed_ips']; `ALLOWED_HOSTS` → ['localhost*']; `config.get("AUTH_SECRET_KEY")`
length 6 and != the example default. `settings/settings.py` and `env/` are gitignored
(.gitignore:11, :113) — local developer files, not in the repo. Only lengths/names
were read from env files, no secret values.
The 6-byte key comes from `env/.env` line 1; `AUTHORIZATION_BACKENDS` from `env/.env:381`.
