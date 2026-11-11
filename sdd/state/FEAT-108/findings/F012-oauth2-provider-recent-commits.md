---
id: F012
query_id: Q030
type: git_log
intent: "Recent commits on the OAuth2 provider (regression window)."
executed_at: 2026-11-11T14:40:00Z
duration_ms: 300
parent_id: null
depth: 0
merged_from: [FG-001]
---

# F012 — OAuth2 provider: commits in the last 90 days

## Summary

20 commits touched `navigator_auth/backends/oauth2/` since 2026-08-13, all by Jesus Lara. Most are the
FEAT-095 oauth2-for-mcp-agents series (TASK-040..044, 2026-08-31), passkey-related edits to
`backend.py` (2026-10-02/03, plus black-formatting commits) and two DCR-reaper lint fixes (2026-10-08).
The only post-3LO-example change to request authentication in this package is 416a5f8 (records
`AUTH_MECHANISM_BEARER`). No commit in the window names session binding, `user_from_id` or the
`cannot bind a session` path — the regression window for that code is d3f85ba (2026-08-21, see FG-003).

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  commits: |
    35d4f99 2026-10-08 fix(oauth2): silence pylint not-callable false positive on the DCR reaper
    617aa55 2026-10-08 fix(oauth2): guard list_by_client with callable() (pylint E1102 on the DCR reaper)
    416a5f8 2026-10-08 fix(csrf): scope the check by authentication mechanism, not by Authorization header
    e919298 2026-10-02 fix(passkey-support-backend): scope session to the ceremony origin, validate PASSKEY_USER_VERIFICATION, drop formatting churn
    604defe 2026-10-02 feat(passkey-support-backend): TASK-91 — is_active enforcement
    f4a4b1a 2026-09-05 feat(oauth2): TASK-069 — close Oauth2Provider Redis-backed storages on cleanup
    89470c9 2026-08-31 fix(oauth2-for-mcp-agents): stop X-Forwarded-For spoofing of the DCR rate limit; gate the refresh grant
    2eb4a24 2026-08-31 fix(oauth2-for-mcp-agents): close access-gate bypass, bound metadata cache, ...
    af51e88 2026-08-31 feat(oauth2-for-mcp-agents): TASK-044 — OAuth 2.1 / Claude conformance hardening
    97a416e 2026-08-31 TASK-043 asymmetric signing + JWKS; 57016b7 TASK-042 per-client access gate;
    ddce36d TASK-041 upstream IdP proxy login; 4ffacd9 TASK-040 DCR (RFC 7591)

- path: `navigator_auth/backends/oauth2/backend.py`
  symbol: `Oauth2Provider._token_session_claims`
  note: |
    `git log -L` over the function region lists only d3f85ba (introduced), aa40f72 (TASK-024,
    2026-06-22), and the passkey/style commits e919298, 11e1a85, 5f0b34c and black passes
    (2026-10-02/03). No functional 3LO fix after d3f85ba.

## Notes

*From FG-001:*
- e919298 ("scope session to the ceremony origin") sits inside the traced region of
  `_token_session_claims` / `_create_user_session`; whether it changed session creation for
  OAuth2 tokens was not checked in this lane.
- [cross-lane: type=read, intent=check whether e919298 changed Oauth2Provider._create_user_session in a way that affects 3LO token sessions]
