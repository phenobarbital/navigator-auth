---
id: F017
query_id: Q040
type: read
intent: "Follow-up (user report mid-run): why does examples/oauth2_server.py's 3LO walk-through end in 'invalid_grant: code_verifier required.'?"
executed_at: 2026-11-11T15:10:00Z
duration_ms: 4000
parent_id: null
depth: 0
merged_from: [parent-sequential]
---

# F017 — oauth2_server.py's 3LO walk-through cannot complete PKCE: no page generates or sends a code_verifier

## Summary

The provider behaves correctly: when the stored authorization code carries a
`code_challenge`, the token endpoint requires `code_verifier` (RFC 7636) and answers
`invalid_grant / code_verifier required.` without it (backend.py:1800-1803). The
example is what is broken. `examples/oauth2_server.py` prints a 3LO URL with a literal
`code_challenge=<S256_hash>` placeholder and no way to produce the matching verifier;
`examples/static/callback.html` posts `grant_type/code/client_id/redirect_uri` only —
no `code_verifier`, since nothing in the browser ever generated or stored one; and the
"Authorize" link in `examples/static/oauth2_index.html` sends no `code_challenge` at
all, so that path would fail the public-client PKCE requirement instead. The 3LO
example (`examples/static/oauth2_3lo_app.html`) already does PKCE in the browser and
is the pattern to follow. Last touched by d3f85ba / TASK-031 / TASK-037.

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 1799-1808
  symbol: `Oauth2Provider._handle_authorization_code`
  excerpt: |
    # TASK-025 PKCE: verify if a challenge was stored.
    if auth_code.code_challenge:
        code_verifier = payload.get("code_verifier", "")
        if not code_verifier:
            return self._error_response("invalid_grant", "code_verifier required.")
        ...
    elif client.client_type == "public" and OAUTH_REQUIRE_PKCE_PUBLIC:
        # Public client must have used PKCE — reject if no challenge stored.

- path: `examples/oauth2_server.py`
  lines: 172-182
  symbol: `startup hint (3LO flow)`
  excerpt: |
    print("3LO flow (public client + PKCE S256):")
    print(
        "  GET http://localhost:5000/oauth2/authorize"
        ...
        "&code_challenge=<S256_hash>&code_challenge_method=S256"
    )

- path: `examples/static/callback.html`
  lines: 30-41
  symbol: `exchangeToken`
  excerpt: |
    async function exchangeToken() {
        const formData = new URLSearchParams();
        formData.append('grant_type', 'authorization_code');
        formData.append('code', code);
        formData.append('client_id', 'nav_public_client');
        formData.append('redirect_uri', 'http://localhost:5000/static/callback.html');

- path: `examples/static/oauth2_index.html`
  lines: 54
  symbol: `Authorize link`
  excerpt: |
    href="/oauth2/authorize?client_id=nav_public_client&redirect_uri=http://localhost:5000/static/callback.html&response_type=code&state=xyz123&scope=default+profile"

- path: `examples/oauth2_server.py`
  lines: 90-97
  symbol: `nav_public_client registration`
  excerpt: |
    # --- Public client (S256 PKCE required) ---
        client_id="nav_public_client",
        redirect_uris=["http://localhost:5000/static/callback.html"],

## Notes

- Git (`git log -- examples/static/callback.html examples/oauth2_server.py`): d3f85ba,
  f2ebe33 (TASK-037), 9c37589 (TASK-031), dba98ce (TASK-023) — PKCE enforcement for
  public clients predates the static pages' last edit, so the pages never matched it.
- `examples/static/oauth2_3lo_app.html` generates the PKCE pair in JS — `crypto.subtle`
  S256 at line 182, verifier kept in `sessionStorage` (186-188), `code_challenge` sent at
  210-211, `code_verifier` sent at 226 — reuse that approach, or point `oauth2_server.py`
  users at the 3LO example.
- The device-grant hint has the same `<S256_hash>` / `<verifier>` placeholders, but
  there the operator drives each step by hand (curl), so placeholders are acceptable.
- Budget: 3 file reads, 2 greps, 1 git call, 1 wiki query (run in the parent session).
