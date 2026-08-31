# MCP Connector Setup Guide

How to expose a navigator-auth-protected MCP server to Claude Web/Desktop as a
custom connector, administer who may reach it, and rotate signing keys.

> Reference implementation: `examples/oauth2_mcp_server.py`.
> API reference: the FEAT-095 section of `documentation/oauth.md`.

---

## 1. What URL do I give Claude?

**The MCP server URL** — not the authorization server URL.

Claude discovers the authorization server by itself:

1. It calls your MCP server and gets a `401` carrying
   `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`.
2. It fetches that protected-resource document and reads `authorization_servers`.
3. It fetches `{issuer}/.well-known/oauth-authorization-server` (RFC 8414).
4. It self-registers at `registration_endpoint` (RFC 7591).
5. It runs authorization_code + PKCE and exchanges the code for a token.

Everything in steps 2–5 is what FEAT-095 adds. Your job is to make steps 1 and 3
resolve correctly.

---

## 2. Minimum viable configuration

```bash
# The single most important setting. Must be the public https origin that
# serves /.well-known/oauth-authorization-server.
AUTH_ISSUER_URL=https://auth.example.com

# Let Claude self-register (default).
OAUTH_DCR_POLICY=open

# Control who may actually use it. DCR clients are born gated.
OAUTH_DCR_GATE_NEW_CLIENTS=true
OAUTH_ACCESS_GATE_QUEUE=true

# Optional: let corporate users sign in with Google/Microsoft.
OAUTH_UPSTREAM_IDP_BACKENDS=google,azure
```

Apply the DDL once:

```bash
psql "$AUTH_DB_DSN" -f navigator_auth/backends/oauth2/ddl.sql
```

Verify discovery before touching Claude:

```bash
curl -s https://auth.example.com/.well-known/oauth-authorization-server | jq .
```

The `issuer` in the response **must** equal `https://auth.example.com`. If it
does not, Claude will show "Disconnected" with no further explanation.

---

## 3. Reverse proxies and `.well-known` at the origin root

RFC 8414 §3 requires the metadata document at the **origin root**, not under a
path prefix. navigator-auth registers the route at the root and also aliases it
under `/oauth2/.well-known/…` for prefix-mounted deployments.

If navigator-auth is mounted under a prefix, rewrite at the proxy:

```nginx
location /.well-known/oauth-authorization-server {
    proxy_pass http://navigator-auth/oauth2/.well-known/oauth-authorization-server;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /.well-known/oauth-protected-resource {
    proxy_pass http://navigator-auth/oauth2/.well-known/oauth-protected-resource;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`X-Forwarded-Proto` and `X-Forwarded-Host` are what let the issuer be derived
correctly when `AUTH_ISSUER_URL` is not set. **Setting `AUTH_ISSUER_URL`
explicitly is strongly recommended** — it removes an entire class of
misconfiguration, and it also pins the discovery-document cache to a single
entry instead of one per distinct `Host` value seen.

### Trusted proxies (required for the DCR rate limit to mean anything)

`X-Forwarded-For` is client-supplied, so it is only honoured when the direct
TCP peer is listed here:

```bash
ALLOWED_IP_TRUSTED_PROXIES=10.0.0.1,10.0.0.2
```

Leave it unset and the registration rate limit keys on the direct peer — which
behind a proxy is the proxy itself, so every client shares one bucket. Set it
and the chain is walked right-to-left, so values a client injects on the left
are ignored.

### Common failure modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Disconnected", no error | `issuer` ≠ document location | Set `AUTH_ISSUER_URL` to the public origin. |
| 404 on `.well-known` | Prefix mount, no proxy rewrite | Add the rewrites above. |
| Issuer is `http://…` | Proxy not sending `X-Forwarded-Proto` | Add the header, or set `AUTH_ISSUER_URL`. |
| Registration fails | `OAUTH_DCR_POLICY=disabled`, or allowlist | Use `open`, or allowlist the Claude callbacks. |
| Token exchange 415 | Client sent JSON | Expected — the endpoint requires form-urlencoded. |
| DCR rate limit ineffective | `ALLOWED_IP_TRUSTED_PROXIES` unset behind a proxy | Set it (below), or every request looks like it comes from the proxy. |
| User gets `access_denied` | Gate: not activated | Approve them (§4). |

---

## 4. Administering the access gate

DCR clients are born gated, so a freshly registered Claude connector grants
nobody access until an administrator says so. This is the point of open
registration: minting a `client_id` is not an authorization decision.

All endpoints require a **superuser** session.

### The approval queue

A denied attempt records one `pending` row per (user, client). Repeated attempts
do not create duplicates.

```bash
# Who is waiting?
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://auth.example.com/api/v1/oauth2/clients/$CLIENT_UID/access?status=pending" | jq .

# Approve them.
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 42, "action": "approve"}' \
  "https://auth.example.com/api/v1/oauth2/clients/$CLIENT_UID/access"

# Or reject.
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 42, "action": "reject"}' \
  "https://auth.example.com/api/v1/oauth2/clients/$CLIENT_UID/access"
```

### Direct activation and revocation

```bash
# Activate without waiting for the user to try first.
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 42, "action": "grant"}' \
  "https://auth.example.com/api/v1/oauth2/clients/$CLIENT_UID/access"

# Revoke — cascades grant + refresh chain + live jtis.
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://auth.example.com/api/v1/oauth2/clients/$CLIENT_UID/access?user_id=42"
```

Revocation is immediate for refresh and introspection. Access tokens already
minted stay syntactically valid until they expire, but every revocation-aware
path reports them revoked — budget one `OAUTH_ACCESS_TOKEN_TTL` for full effect.

To gate **every** client, not just DCR ones, set `OAUTH_ACCESS_GATE_ENABLED=true`.

### Auditing self-registered clients

```sql
SELECT client_uid, client_name, registration_source, enforce_access_gate, created_at
FROM auth.clients
WHERE registration_source = 'dcr'
ORDER BY created_at DESC;
```

Clients that never completed a token exchange are reaped after
`OAUTH_DCR_UNUSED_TTL` via `Oauth2Provider.reap_unused_dcr_clients()` — wire it
to your scheduler; it is deliberately not run on the request path.

---

## 5. RS256 key generation and rotation runbook

Asymmetric signing lets third parties validate tokens from the JWK Set alone.
It is entirely optional — HS256 remains the default and is unchanged.

### Generate a key pair

```bash
KID="$(date +%Y-q%q 2>/dev/null || date +%Y-%m)"
install -d -m 0700 /etc/navigator/keys

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "/etc/navigator/keys/${KID}.key"
openssl rsa -pubout \
  -in  "/etc/navigator/keys/${KID}.key" \
  -out "/etc/navigator/keys/${KID}.pub"

chmod 0600 /etc/navigator/keys/*.key
chmod 0644 /etc/navigator/keys/*.pub
```

ES256 instead:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out "/etc/navigator/keys/${KID}.key"
openssl ec -pubout -in "/etc/navigator/keys/${KID}.key" -out "/etc/navigator/keys/${KID}.pub"
```

### Enable

```bash
OAUTH_JWT_SIGNING_ALG=RS256
OAUTH_JWT_KEYS='[{"kid":"2026-q3","algorithm":"RS256","private_key_file":"/etc/navigator/keys/2026-q3.key","public_key_file":"/etc/navigator/keys/2026-q3.pub","active":true}]'
```

Verify:

```bash
curl -s https://auth.example.com/oauth2/jwks | jq .
# Must contain kid + kty + use:"sig" — and NEVER "d", "p" or "q".

curl -s https://auth.example.com/.well-known/oauth-authorization-server | jq .jwks_uri
```

### Rotate without downtime

The rule: **publish first, sign later, retire last.**

1. **Publish** the new key as verify-only (`"active": false`) and reload. It is
   now in the JWK Set; relying parties can cache it.
2. **Wait** for downstreams to refresh their JWKS cache (usually minutes).
3. **Promote**: set the new key `"active": true` and the old one `"active":
   false`. Only the new key signs; the old one still verifies.
4. **Wait** at least one `OAUTH_ACCESS_TOKEN_TTL` so every token signed by the
   old key has expired.
5. **Retire**: remove the old entry and delete its files.

```json
// Step 1 — publish
[
  {"kid": "2026-q2", "algorithm": "RS256", "private_key_file": "…/2026-q2.key",
   "public_key_file": "…/2026-q2.pub", "active": true},
  {"kid": "2026-q3", "algorithm": "RS256", "public_key_file": "…/2026-q3.pub",
   "active": false}
]

// Step 3 — promote
[
  {"kid": "2026-q2", "algorithm": "RS256", "public_key_file": "…/2026-q2.pub",
   "active": false},
  {"kid": "2026-q3", "algorithm": "RS256", "private_key_file": "…/2026-q3.key",
   "public_key_file": "…/2026-q3.pub", "active": true}
]
```

Exactly one key may be `active`. Migrating from HS256 needs no coordination:
tokens without a known `kid` keep verifying against `SECRET_KEY` throughout.

**Never** commit private keys, put them in `OAUTH_JWT_KEYS` inline in a
version-controlled file, or log them. The registry holds them in `SecretStr` and
the JWK Set serialises public parameters only.

---

## 6. Resource indicators (RFC 8707)

Clients may send `resource=https://mcp.example.com` at authorize and token. The
value is validated (absolute URI, no fragment), carried through the code, and
reflected into the token `aud` alongside the `'user'` / `'app'` marker:

```json
{"aud": ["user", "https://mcp.example.com"], "user_id": 42, "...": "..."}
```

navigator-auth validates and propagates; it does **not** enforce audience.
Enforcement belongs to the resource server, which knows its own canonical URI.
Configure each MCP mount's validator with its resource URI so a token minted for
one mount is refused at another.

---

## 7. Cross-repo follow-up (D6)

**This half is not done and lives in the ai-parrot repository.**

Each ai-parrot MCP mount must serve its **own** RFC 9728
`/.well-known/oauth-protected-resource` document, pointing at this
authorization server. navigator-auth ships the builder; ai-parrot serves the
document:

```python
from navigator_auth.backends.oauth2.metadata import (
    build_protected_resource_metadata,
)

async def protected_resource_metadata(request):
    return web.json_response(
        build_protected_resource_metadata(
            resource="https://mcp.example.com",
            auth_servers=["https://auth.example.com"],
            scopes=["default"],
        )
    )
```

A follow-up spec in the ai-parrot repository must cover:

- serving PRM per MCP mount using this builder;
- `resolve_principal` and MCP tool exposure;
- configuring `ExternalOAuthValidator` with each mount's canonical
  `resource_server_url` so `aud` is actually enforced (D5);
- emitting the `WWW-Authenticate: Bearer resource_metadata="…"` challenge from
  the MCP mount's own `401`s.

This spec closes ai-parrot's spike gate **S1**; the "Agent Methods as MCP Tools"
feature is unblocked once the above lands.

---

## 8. Verifying the whole thing

```bash
pytest tests/test_oauth2_mcp_conformance.py -v
```

`test_claude_replay_dcr` and `test_claude_replay_static_client` replay Claude's
exact handshake — discovery → DCR → authorize with PKCE S256 → form-urlencoded
token → refresh rotation → introspection — and assert every leg lands inside the
10 s (30 s refresh) budget.
