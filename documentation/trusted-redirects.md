# Trusted Redirect Domains (open-redirect protection)

Navigator Auth lets the **frontend** decide where the browser lands once
authentication finishes: `?redirect_uri=` on the login/authorize routes,
`RelayState` on SAML, `?redirect_uri=` on the identity-link endpoint. One
backend (for example `api.trocdigital.io`) serves dozens of sub-apps on many
sub-domains, so that target cannot be a fixed setting.

Honouring it verbatim, however, is a classic **open redirect**: a link such as
`https://api.example.com/auth/login?redirect_uri=https://evil.com` would send
a freshly minted token straight to an attacker's page. Every user-supplied
redirect target now goes through one gate, `navigator_auth.libs.redirect
.safe_redirect_url`, before a `302` is issued.

## Rules

| Target                                    | Verdict                                                        |
|-------------------------------------------|----------------------------------------------------------------|
| `/dashboard`, `dashboard?x=1`             | **Accepted**, resolved on the current request's own domain     |
| `//evil.com`, `/\evil.com`                | **Rejected** (protocol-relative and backslash variants)         |
| `https://app.example.com/home`            | **Accepted** when `example.com` (or `app.example.com`) is trusted |
| `https://example.com.evil.com/`           | **Rejected** (suffix must be a full label boundary)            |
| `https://example.com@evil.com/`           | **Rejected** (the real host is `evil.com`; only `hostname` is compared, never the raw `netloc`) |
| `navigator://cb`, `com.example.app:/cb`   | **Accepted** (mobile deep link), see schemes below             |
| `javascript:`, `data:`, `file:` ...       | **Always rejected**                                            |

A rejected target is logged at `WARNING` and replaced by `AUTH_REDIRECT_URI`
on the current domain (or by the caller's own fallback), so a tampered link
degrades to the default landing page instead of breaking the login.

The host that is serving the current request is always trusted, in addition to
the configured list.

Backends that need a verdict rather than a resolved URL (ADFS relay, SAML
`RelayState` / `redirect_uri`) use `BaseAuthBackend.validate_redirect_host`,
which applies the same rules and lets the caller vouch for extra hosts (for
example a SAML Service Provider's ACS host).

## Settings

```ini
[auth]
# Base domains the browser may be sent to. Every sub-domain of an entry is
# trusted too. Entries may be written as example.com, *.example.com,
# https://example.com:8443 or localhost:5000 — they are normalised to the
# bare host name.
AUTH_TRUSTED_DOMAINS: trocdigital.io,localhost

# Optional: restrict custom (non-HTTP) redirect schemes to this list.
# Empty (default) accepts any custom scheme except browser-executable ones,
# because the set of Android/iOS apps served by the API is open-ended.
AUTH_TRUSTED_REDIRECT_SCHEMES: navigator,com.example.app
```

| Setting                         | Default                                 |
|---------------------------------|-----------------------------------------|
| `AUTH_TRUSTED_DOMAINS`          | `localhost`, `DOMAIN`, host of `DOMAIN_HOST` |
| `AUTH_TRUSTED_REDIRECT_SCHEMES` | empty (any non-executable custom scheme) |

Production deployments that serve several applications should set
`AUTH_TRUSTED_DOMAINS` explicitly; the default only covers the single domain
the API itself is configured with.

`AUTH_TRUSTED_DOMAINS` is unrelated to `ALLOWED_HOSTS`: the latter decides which
*origins may call* the API (authorization backend `allow_hosts`, glob
patterns), the former decides where the API may *send the browser*.
