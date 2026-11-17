---
kind: brief
slug: limiter-client-ip
key: limiter-client-ip
base_branch: main
source:
  type: text
  ref: "Qué IP mira navigator-auth: limitadores de MFA y recuperación usan request.remote"
  url: null
jira_issue_key: null
ledger_issue: null
created: "2026-11-12T21:44:15Z"
---

# Brief: IP rate limiters must key on the real client IP (`get_client_ip`)

## Problem

Source (text, verbatim):

> Qué IP mira navigator-auth:
>   - El limitador de MFA (mfa/login.py:80) y el de recuperación
>     (recovery/handler.py:205) usan request.remote. que los limitadores de MFA
>     y de recuperación usen get_client_ip.

Behind a reverse proxy / load balancer / `cloudflared` tunnel, `request.remote`
is the proxy's address, not the user's. Every IP-keyed limiter that reads it
therefore puts **all users in one bucket**:

- one attacker exhausting the bucket locks every user out of MFA verification,
  MFA management, password recovery and passkey login (a cheap DoS), and
- the per-IP limit stops limiting any single source, because the budget is
  shared by everybody.

The owner widened the scope in Q&A (see Decisions) to the two other limiters
with the same defect.

## Root cause

The limiters build their key from the raw TCP peer instead of the shared,
proxy-aware resolver `get_client_ip` that the authorization backends, the
probe tracker and the OAuth2 DCR limiter already use:

| Limiter | Key source today | Anchor (verified) |
|---|---|---|
| MFA verify (login 2nd factor) | `_remote()` → `getattr(request, "remote", None) or "unknown"` | `navigator_auth/mfa/login.py:80`, call at `navigator_auth/mfa/login.py:187` |
| MFA management / enrollment (same `services.ip_limiter`) | `_remote()` → `request.remote or "unknown"` | `navigator_auth/handlers/mfa.py:60`, calls at `:229`, `:251`, `:299`, `:347`, `:410` |
| Password recovery step 1 | `self.request.remote or "unknown"` | `navigator_auth/handlers/recovery/handler.py:205` |
| Passkey `login/options` | `f"passkey_rl_{request.remote}"` (deliberately raw, per its docstring) | `navigator_auth/backends/passkey.py:191` |
| OAuth2 device-code lockout | `request.headers.get("X-Forwarded-For", request.remote)`, leftmost hop, **unconditionally** | `navigator_auth/backends/oauth2/backend.py:3268` |

The device-code case is the inverse bug and is worse: it trusts a
client-supplied header from any peer, so an attacker rotates
`X-Forwarded-For` on every attempt and never trips the brute-force lockout on
the `user_code` entry form.

`get_client_ip(request, proxies)` (`navigator_auth/authorizations/_client_ip.py:80`)
honours `X-Forwarded-For` / `CF-Connecting-IP` **only** when the direct peer
is in `ALLOWED_IP_TRUSTED_PROXIES` (`navigator_auth/conf.py:212`), walks the
chain right-to-left, and otherwise returns `request.remote`. With the setting
empty (the default) it returns exactly `request.remote`, so the fix changes
nothing for deployments without a configured proxy.

## Research findings

- **Resolver and config.** `get_client_ip` (`_client_ip.py:80`) and
  `parse_proxies` (`_client_ip.py:41`) are the single source of truth.
  `get_client_ip` returns `None` when the peer is missing or not an IP
  (unix socket, test doubles) — callers must keep a fallback.
- **Prior art (pattern to copy).** `Oauth2Provider._client_source_ip`
  (`navigator_auth/backends/oauth2/backend.py:1426`) is already the limiter
  identity for DCR: `get_client_ip(request, self._trusted_proxies) or
  request.remote or "unknown"`, with `self._trusted_proxies =
  parse_proxies(ALLOWED_IP_TRUSTED_PROXIES)` at `backend.py:345`. The probe
  tracker does the same at module level (`navigator_auth/middlewares/probes.py:184`).
- **Shared bucket.** `navigator_auth/mfa/login.py` and
  `navigator_auth/handlers/mfa.py` both feed `services.ip_limiter`
  (built at `navigator_auth/mfa/services.py:258`). Changing only one of the two
  `_remote` helpers would key the same limiter on two different identities,
  so both change together.
- **Recovery limiter** is built at `navigator_auth/handlers/recovery/handler.py:167`
  (`RateLimiter(cls._pool, AUTH_RECOVERY_RATE_IP, "ip")`); only the key at
  `:205` changes.
- **Test doubles.** `tests/test_mfa_verify.py:153`,
  `tests/test_mfa_review_followups.py:99` and `tests/test_mfa_admin_disenroll.py:82`
  pass `SimpleNamespace(remote=...)` without `headers`; `get_client_ip` only
  reads headers when the peer is a trusted proxy, so they keep working with
  the default empty proxy set. `tests/test_device_verification.py:110` builds
  `Oauth2Provider` via `__new__`, so it has no `_trusted_proxies` attribute —
  the fake builder must set it once the device-code path calls
  `_client_source_ip`.
- **Wiki.** `wikitoolkit query` surfaced the same sites
  (`PasswordRecoveryHandler._step1_request`, `navigator_auth/mfa/limiter.py`,
  `Oauth2Provider._client_source_ip`). `wikitoolkit symbols lookup|blast`
  failed in this environment (structural-tools import error), so blast radius
  was taken from direct reads: every helper changed here is module-private.
- **Base.** The five anchors are byte-identical on `origin/main` (6e4c454) and
  `origin/dev` (3a72385).

## Decisions

- **Scope (owner, Q&A):** fix all four limiter families — MFA (both
  `_remote` helpers), password recovery, OAuth2 device-code lockout and passkey
  `login/options`.
- **One fallback rule everywhere:** limiter key =
  `get_client_ip(request, proxies)`, else the raw `request.remote`, else
  `"unknown"`. Implemented once as `limiter_client_ip()` in
  `navigator_auth/authorizations/_client_ip.py`; the device-code path reuses the
  existing `Oauth2Provider._client_source_ip` (same rule).
- **Trusted proxies** are parsed once per module at import time from
  `ALLOWED_IP_TRUSTED_PROXIES`, as `probes.py:184` does, so tests can patch a
  module attribute.
- **Passkey design change:** the docstring that says "behind a proxy enforce the
  limit there (`X-Forwarded-*` is never trusted)" becomes "honours
  `ALLOWED_IP_TRUSTED_PROXIES`". Forwarding headers stay untrusted unless the
  peer is a configured proxy.
- **Base branch:** `main` (configured `hotfix_base`; text source).
- **Out of scope:** `navigator_auth/abac/context.py:188` (`ip_addr` attribute for
  policies) — not a limiter.

## Fix plan

1. **HOTFIX-limiter-client-ip-1** — add `limiter_client_ip()` to
   `_client_ip.py`; route the MFA `_remote` helpers (`mfa/login.py`,
   `handlers/mfa.py`) and the recovery step-1 key through it; new tests.
2. **HOTFIX-limiter-client-ip-2** — OAuth2 device-code lockout keys on
   `self._client_source_ip(request)` instead of the raw leftmost
   `X-Forwarded-For`; fix the test builder; spoofing regression test.
   Independent of task 1.
3. **HOTFIX-limiter-client-ip-3** — passkey `login/options` limiter keys on
   `limiter_client_ip()`; docstring updated; test. Depends on task 1.

## Validation commands

- `pytest tests/test_limiter_client_ip.py -q`
- `pytest tests/test_mfa_verify.py -q`
- `pytest tests/test_mfa_review_fixes_management.py -q`
- `pytest tests/test_mfa_enrollment_security.py -q`
- `pytest tests/test_mfa_admin_disenroll.py -q`
- `pytest tests/test_mfa_review_followups.py -q`
- `pytest tests/test_password_recovery.py -q`
- `pytest tests/test_device_verification.py -q`
- `pytest tests/test_oauth2_dcr.py -q`
- `pytest tests/test_passkey_backend_unit.py -q`

Do not run `tests/test_oauth2_passkey_session.py` as part of this brief: it
hangs at baseline.
