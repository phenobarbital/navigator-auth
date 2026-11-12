---
id: FG-005
query_id: Q031
type: git_log
intent: "Recent commits on decorators.py and api.py — follow-up on af51e88."
executed_at: 2026-11-11T14:42:00Z
duration_ms: 400
parent_id: FG-002
depth: 1
---

# FG-005 — af51e88 (TASK-044): bearer requests in APIKeyAuth

## Summary

af51e88 (2026-08-31, Jesus Lara) — OAuth 2.1 / Claude conformance hardening — touched `auth.py` (+54),
`api.py` (+14), `oauth2/backend.py` (+175), `oauth2/models.py`, `templates/oauth/consent.html` and added
`tests/test_oauth2_conformance.py` (+360). In `api.py` it added `BEARER_CHALLENGE_KEY` and, in the
`mech == "bearer"` branch of the token-info path, marks the request so a later 401 carries the RFC 9728
`WWW-Authenticate: Bearer resource_metadata=...` challenge. It confirms `APIKeyAuth` decodes OAuth2
bearer JWTs via `self._idp.decode_token` — i.e. `APIKeyAuth` also acts on 3LO bearer tokens.

## Citations

- commit: `af51e88` — 2026-08-31 01:47 +0200 — Jesus Lara
  message: "feat(oauth2-for-mcp-agents): TASK-044 — OAuth 2.1 / Claude conformance hardening"
  files: navigator_auth/auth.py, navigator_auth/backends/api.py, navigator_auth/backends/oauth2/backend.py,
    navigator_auth/backends/oauth2/models.py, templates/oauth/consent.html, tests/test_oauth2_conformance.py

- path: `navigator_auth/backends/api.py`
  symbol: `BEARER_CHALLENGE_KEY`
  excerpt: |
    BEARER_CHALLENGE_KEY: str = "_oauth2_bearer_challenge"

- path: `navigator_auth/backends/api.py`
  symbol: `APIKeyAuth` (bearer branch, hunk @@ -93; exact method name not verified in this lane — wiki lists both `check_token_info` and `get_token_info`)
  excerpt: |
    if mech == "bearer":
        try:
            request[BEARER_CHALLENGE_KEY] = True
        except TypeError:
            pass
        try:
            _, payload = self._idp.decode_token(token)

## Notes

- [cross-lane: type=read, intent=read APIKeyAuth.check_token_info/authenticate (api.py ~100-160) to see what it returns for a 3LO bearer with no device_id — source of the bool at api.py:154]
