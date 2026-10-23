# TASK-109: Split `AZURE_SESSION_TIMEOUT` into `AZURE_FLOW_TTL` + `max_age`

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 8, §8 Q4 (resolved), G7, §7 Known Risks.

One setting serves two unrelated jobs:

- `max_age=int(AZURE_SESSION_TIMEOUT)` on `initiate_auth_code_flow`
  (`azure.py:212`) — an OIDC **freshness** requirement MSAL enforces on the
  callback with a hardcoded 120 s skew (`msal/oauth2cli/oidc.py:310-328`,
  verified in `.venv`).
- `redis.setex(f"azure_auth_{state}", AZURE_SESSION_TIMEOUT, ...)`
  (`azure.py:217`) — the **Redis TTL of the login-flow record**.

At the `conf.py:430` fallback of 120 s the second job is a **5× outlier**
against every sibling flow TTL in `conf.py`, all of which are 600:
`AUTH_CODE_EXPIRATION` (`:350`), `SAML_FLOW_TTL` (`:506`),
`IDENTITY_LINK_TTL` (`:543`), `OAUTH_CODE_TTL` (`:726`),
`OAUTH_DEVICE_CODE_TTL` (`:785`), `OAUTH_UPSTREAM_FLOW_TTL` (`:854`)
(`PASSKEY_CHALLENGE_TTL` at `:590` is 300). A user who lingers on the Microsoft
login screen for two minutes loses the flow record and gets
*"Lost Authentication Flow, please try again."*

`AZURE_SESSION_TIMEOUT` is also declared with `config.get` — i.e. a **string** —
which is why `azure.py:212` has to wrap it in `int()`.

This task also **unblocks** the §8 Q1 experiment (TASK-113), which needs
`max_age` adjustable independently of the flow TTL.

---

## Scope

- `navigator_auth/conf.py`: add
  `AZURE_FLOW_TTL = config.getint("AZURE_FLOW_TTL", fallback=600)`; convert
  `AZURE_SESSION_TIMEOUT` (`:430`) from `config.get` to `config.getint` with
  its existing fallback of 120, leaving it as the `max_age` value only.
- `navigator_auth/backends/azure.py`: use `AZURE_FLOW_TTL` in the `setex`
  (`:217`); drop the now-redundant `int()` around `AZURE_SESSION_TIMEOUT` at
  `:212`; import the new name.
- Document both settings where this repo documents settings (check
  `docs/` and `.env.example`/`etc/` for an existing settings list; if none
  covers the Azure block, say so in the Completion Note rather than inventing
  a new doc file — TASK-113 owns `docs/`).

**NOT in scope**: removing `max_age` (explicit spec Non-Goal — the freshness
requirement may be deliberate and changing it is a separate security
decision); changing the 120 s `max_age` value itself; running the Q1
experiment (TASK-113); anything else in `azure.py` (TASK-105 and TASK-108 own
their own edits there — sequence, do not parallelize).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | new `AZURE_FLOW_TTL`; `AZURE_SESSION_TIMEOUT` → `getint` |
| `navigator_auth/backends/azure.py` | MODIFY | `setex` TTL; drop `int()`; import |

---

## Codebase Contract

### Verified Imports
```python
from ..conf import (..., AZURE_SESSION_TIMEOUT, ...)   # verified: azure.py imports it; add AZURE_FLOW_TTL
# conf.py uses a module-level `config` object (navconfig) with .get/.getint/.getboolean
```

### Verified Signatures
```python
# navigator_auth/conf.py — the line to change
AZURE_SESSION_TIMEOUT = config.get("AZURE_SESSION_TIMEOUT", fallback=120)   # verified: :430  (config.get -> str!)

# the sibling flow TTLs that justify 600 (all config.getint, all fallback=600)
AUTH_CODE_EXPIRATION      # verified: :350
SAML_FLOW_TTL             # verified: :506
IDENTITY_LINK_TTL = config.getint("IDENTITY_LINK_TTL", fallback=600)        # verified: :543
IDENTITY_CACHE_TTL = config.getint("IDENTITY_CACHE_TTL", fallback=3600)     # verified: :544
IDENTITY_REFRESH_LEEWAY = config.getint("IDENTITY_REFRESH_LEEWAY", fallback=120)  # verified: :545
OAUTH_CODE_TTL            # verified: :726
OAUTH_DEVICE_CODE_TTL     # verified: :785
OAUTH_UPSTREAM_FLOW_TTL   # verified: :854
PASSKEY_CHALLENGE_TTL     # verified: :590  (300, the one exception)

# navigator_auth/backends/azure.py — the two call sites
                flow = app.initiate_auth_code_flow(
                    scopes=SCOPE,
                    redirect_uri=redirect_uri,
                    domain_hint=AZURE_ADFS_DOMAIN,
                    max_age=int(AZURE_SESSION_TIMEOUT),                     # verified: :212
                )
                async with aioredis.Redis(connection_pool=self._pool) as redis:
                    state = flow["state"]
                    flow["internal_redirect"] = redirect
                    await redis.setex(f"azure_auth_{state}",
                                      AZURE_SESSION_TIMEOUT,
                                      json_encoder(flow))                   # verified: :217
```

### Verified third-party behaviour (`msal 1.38.0`, in `.venv`)
```python
# msal/oauth2cli/oidc.py
def obtain_token_by_auth_code_flow(self, auth_code_flow, auth_response, **kwargs):  # verified: :290
    if auth_code_flow.get("max_age") is not None:                                   # verified: :310
        skew = 120
        if now - skew > auth_time + auth_code_flow["max_age"]:
            raise RuntimeError("13. auth_time ... too much time has elapsed")       # verified: :315-328
#  => max_age is enforced on the CALLBACK, with a hardcoded 120s skew. Keeping it
#     is a deliberate decision (spec Non-Goals); only the TTL concern moves out.
```

### Does NOT Exist (do not reference)
- **No** `AZURE_FLOW_TTL` setting today — you add it.
- **No** other *consumer* of `AZURE_SESSION_TIMEOUT`. Verified
  (`grep -rn "AZURE_SESSION_TIMEOUT" navigator_auth/ tests/ docs/ examples/`,
  2026-10-22): `conf.py:430` (the declaration), `azure.py:25` (import),
  `azure.py:212`, `azure.py:217`, and `adfs.py:29` — which **imports it and
  never uses it**. Nothing relies on it being a `str`, so the `getint`
  conversion is safe. Consider removing the dead `adfs.py` import, or leave it
  and say so; do not start using it there.
- **No** per-flow TTL override parameter on `initiate_auth_code_flow` — the
  flow record's lifetime is entirely ours (the `setex`), MSAL does not know
  about it.

---

## Implementation Blueprint

### Steps (in order)
1. Run `grep -rn "AZURE_SESSION_TIMEOUT" navigator_auth/ tests/ docs/ examples/`
   **first** — the type change from `str` to `int` is the only part of this task
   that can break something outside `azure.py`.
2. Block A: `conf.py`. Put `AZURE_FLOW_TTL` next to `AZURE_SESSION_TIMEOUT` so
   the two related knobs are read together, with the comment explaining why
   they are separate — because the next person to see two Azure timeouts will
   otherwise re-merge them.
3. Block B: `azure.py` — the import and the two call sites.
4. Run `pytest tests/test_azure_token_verifier.py -v` plus any test the grep in
   step 1 turned up.

### Block A — `navigator_auth/conf.py`
```python
# REPLACE — the AZURE_SESSION_TIMEOUT declaration
# occurrences: 1 (verified: grep -c 'AZURE_SESSION_TIMEOUT = config' navigator_auth/conf.py)
# FEAT-103 Module 8 — two unrelated jobs, two settings.
#
# AZURE_SESSION_TIMEOUT is the OIDC `max_age` freshness requirement sent to
# Entra and enforced by MSAL on the callback (with its own hardcoded 120s skew,
# msal/oauth2cli/oidc.py:310-328). It is NOT a TTL.
AZURE_SESSION_TIMEOUT = config.getint("AZURE_SESSION_TIMEOUT", fallback=120)
# AZURE_FLOW_TTL is the Redis lifetime of the login-flow record written at
# azure.py:217. 600 matches every sibling flow TTL in this file
# (AUTH_CODE_EXPIRATION, SAML_FLOW_TTL, IDENTITY_LINK_TTL, OAUTH_CODE_TTL,
# OAUTH_DEVICE_CODE_TTL, OAUTH_UPSTREAM_FLOW_TTL); at the old shared 120s a
# user who lingered on the Microsoft login screen lost the flow record and got
# "Lost Authentication Flow, please try again."
AZURE_FLOW_TTL = config.getint("AZURE_FLOW_TTL", fallback=600)
```
**Why `getint` for `AZURE_SESSION_TIMEOUT`**: it is declared with `config.get`
today, so it is a **string**, which is why `azure.py:212` wraps it in `int()`.
Every sibling TTL/leeway in this file uses `getint`; making it consistent
removes the wrapper and the class of bug where `"120"` is passed somewhere
expecting a number.

### Block B — `navigator_auth/backends/azure.py`
```python
# AFTER — insert below the line `    AZURE_ADFS_TENANT_ID,` inside the
#   parenthesized `from ..conf import (` block at azure.py:20-28
# occurrences: 1 (verified: grep -c '    AZURE_ADFS_TENANT_ID,' navigator_auth/backends/azure.py -> 1;
#   the block is: AZURE_ADFS_CLIENT_ID, AZURE_ADFS_CLIENT_SECRET,
#   AZURE_ADFS_DOMAIN, AZURE_ADFS_TENANT_ID, AZURE_SESSION_TIMEOUT,
#   AZURE_MAPPING, AZURE_TRUSTED_APPIDS — i.e. NOT alphabetical, so place the
#   new name where it reads naturally next to AZURE_SESSION_TIMEOUT)
    AZURE_FLOW_TTL,
```
```python
# REPLACE — the max_age argument (the int() wrapper is now redundant)
# occurrences: 1 (verified: grep -c 'max_age=int(AZURE_SESSION_TIMEOUT)' navigator_auth/backends/azure.py)
                    max_age=AZURE_SESSION_TIMEOUT,
```
```python
# REPLACE — the flow-record setex
# occurrences: 1 (verified: grep -c 'await redis.setex(f"azure_auth_{state}"' navigator_auth/backends/azure.py)
                    await redis.setex(f"azure_auth_{state}", AZURE_FLOW_TTL, json_encoder(flow))
```
**Why the two must move independently**: the `max_age` half stays as-is on
purpose (spec Non-Goals — the freshness requirement may be deliberate), while
the TTL half is simply a 5× outlier. Splitting them is also the precondition
for the §8 Q1 experiment (TASK-113), which raises or removes `max_age` and
measures the Graph token's lifetime — impossible while one knob drives both.

### FILL IN checklist
- [ ] The settings-documentation location, if one exists (see Scope).
- [ ] Whether to drop the dead `AZURE_SESSION_TIMEOUT` import at `adfs.py:29`
      — bounded by "NOT in scope: anything else in azure.py"; `adfs.py` is a
      different file, so this is a judgement call, not a scope breach. Either
      way, record it.

---

## Implementation Notes

### Key Constraints
- `azure.py` is shared with TASK-105 (capture wiring) and TASK-108
  (redaction). Spec Worktree Strategy: *"sequence it with 3 rather than
  running it concurrently"*.
- Do not change the `max_age` **value**. The acceptance criterion is that
  `initiate_auth_code_flow` still receives `max_age=AZURE_SESSION_TIMEOUT` and
  that the two settings move independently — not that the login's freshness
  requirement changes.
- `config.getint` raises on a non-numeric environment value where `config.get`
  silently passed a string through. That is the intended strictness, but it
  means a deployment with `AZURE_SESSION_TIMEOUT=2m` in its env now fails at
  import. Worth a line in the Completion Note.

### References in Codebase
- `navigator_auth/conf.py:543-545` — `IDENTITY_LINK_TTL` /
  `IDENTITY_REFRESH_LEEWAY`, the `getint` + fallback style to copy.

---

## Acceptance Criteria

- [ ] `setex` on `azure_auth_<state>` uses `AZURE_FLOW_TTL` (600 by default)
- [ ] `initiate_auth_code_flow` still receives
      `max_age=AZURE_SESSION_TIMEOUT`, and the two settings move independently
- [ ] `AZURE_SESSION_TIMEOUT` is an `int` from `conf.py`, so `azure.py` no
      longer needs the `int()` wrapper
- [ ] No remaining reader of `AZURE_SESSION_TIMEOUT` expects a `str`
      (re-run the step-1 grep and record it; the 2026-10-22 result is in the
      Codebase Contract above — `adfs.py:29` is a dead import)
- [ ] `pytest tests/test_azure_token_verifier.py -v` passes
- [ ] `ruff check navigator_auth/conf.py navigator_auth/backends/azure.py` clean

---

## Test Specification

Tests live in TASK-111: `test_azure_flow_ttl_is_independent_of_max_age`,
`test_azure_session_timeout_is_int` (spec §4).

---

## Agent Instructions

1. **Read the spec** §3 Module 8 and §8 Q4.
2. **Check dependencies** — none; but if TASK-105/TASK-108 are in flight on
   `azure.py`, land after them.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve both `FILL IN`s.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-109-azure-flow-ttl-split.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**, including the step-1 grep result.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: conf.py: AZURE_SESSION_TIMEOUT -> getint (120); new AZURE_FLOW_TTL getint (600). azure.py: max_age=AZURE_SESSION_TIMEOUT (int() dropped), setex uses AZURE_FLOW_TTL. Step-1 grep (navigator_auth/ tests/ docs/ examples/ env/ etc/): only conf.py decl, azure.py import+2 uses (now changed) and adfs.py:29 dead import -- no str reader. Runtime check printed `120 600`. pytest test_azure_token_verifier: 7 passed; ruff clean on both files. Settings docs: no existing settings list covers the Azure block (none under docs/, env/, etc/), so none invented -- TASK-113 owns docs. adfs.py:29 dead import LEFT in place (different file, not in task's list). Note: `AZURE_SESSION_TIMEOUT=2m`-style non-numeric env values now fail at import (getint strictness).
**Deviations from spec**: none
