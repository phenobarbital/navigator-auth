# TASK-108: Stop leaking provider tokens through `check_credentials`

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-103
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 6, G6, §5 ("The raw provider refresh token appears in no
session value and in **no** HTTP response body").

`check_credentials` builds its JSON body as `sessioninfo = {**data, **userdata}`
and returns it verbatim — `azure.py:585`, `github.py:314`, `google.py:333`.
`userdata` carries `auth_token` (the provider access token, written by
`build_user_info` at `external.py:696`) and, after TASK-103, `id_token` as
well. Both are handed to the caller in clear.

`mask_value` (`identity/types.py:93`) already exists for exactly this and is
what `IdentityStore.masked` (`store.py:301`) uses.

---

## Scope

- Redact `auth_token` and `id_token` in the `sessioninfo` dict at all three
  sites, using `mask_value`.
- Ensure no refresh token of any kind reaches the body: `userdata` must not
  contain a provider refresh token at all (TASK-103 guarantees this — assert
  it, do not re-filter it), and `data["refresh_token"]` is **Navigator's own**
  token, which this task must decide about explicitly (see the FILL IN).
- Keep the three sites' behaviour otherwise identical, including status codes
  and the `RuntimeError` → 402 branch.

**NOT in scope**: the `home_redirect` branch (it passes only
`data["token"]`, Navigator's own JWT, as a query/fragment value — unchanged);
`validate_user_info`'s return shape (TASK-107 owns `expires_in`/`expires_at`
there); the session contents themselves (the session legitimately holds
`auth_token`; that is what `get_live_provider_token` reads); the other
backends' `check_credentials` (ADFS/Okta/Odoo/SAML are out of scope per spec
§1 Non-Goals — verify whether they build a `sessioninfo` dict at all and say so
in the Completion Note); tests (TASK-111).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/azure.py` | MODIFY | redact at `:585` |
| `navigator_auth/backends/github.py` | MODIFY | redact at `:314` |
| `navigator_auth/backends/google.py` | MODIFY | redact at `:333` |

---

## Codebase Contract

### Verified Imports
```python
mask_value                                   # verified: defined at navigator_auth/identity/types.py:93
# each target file already imports from that module (1 occurrence each,
# verified) but NOT `mask_value` — extend the existing import line:
#   azure.py, github.py, google.py: `from ..identity.types import ...`
```

### Verified Signatures
```python
# navigator_auth/identity/types.py
def mask_value(value: Any) -> Optional[str]:                       # verified: :93
    if not value: return None                                      # verified: :95-96
    return f"***{len(str(value))}"                                 # verified: :97
#  => returns None for falsy input, else a length hint like "***1243"

# navigator_auth/identity/store.py
def masked(self, identity) -> dict:                                # verified: :301  (the existing consumer)

# the three leak sites — identical shape in all three files
            try:
                session = await get_session(request)
                if not session:
                    session = {}
                sessioninfo = {**data, **userdata}     # verified: azure.py:585, github.py:314, google.py:333
                return JSONResponse(sessioninfo, status=200)   # verified: azure.py:586, github.py:315, google.py:334
            except RuntimeError as err:
                response = {"message": "Session Error", "error": str(err)}
                return JSONResponse(response, status=402)

# what lands in `userdata` (build_user_info, external.py:693-698 + TASK-103)
userdata["auth_token"]                    # provider ACCESS token — in clear today
userdata["token_type"], ["auth_method"]   # not secret
userdata["id_token"]                      # provider ID token — NEW in TASK-103
userdata["has_refresh_token"]             # bool, safe by construction
userdata["external_expires_at"], ["external_provider_user_id"]   # not secret

# what lands in `data` (validate_user_info return, external.py:766)
data["token"]            # NAVIGATOR's own JWT — the caller legitimately needs it
data["refresh_token"]    # NAVIGATOR's own refresh token — see FILL IN
data["type"], data["expires_in"]  (+ data["expires_at"] after TASK-107)
```

### Does NOT Exist (do not reference)
- **No** `mask_value` import in `azure.py`, `github.py` or `google.py` today.
- **No** central response serializer or redaction middleware — the three sites
  build their dict inline, so the fix is three edits, not one.
- **No** provider refresh token in `userdata` — TASK-103 guarantees only
  `has_refresh_token` is written. Do not add a defensive `pop("refresh_token")`
  on `userdata`: that key, if present, is **Navigator's** token merged in from
  `data`, and popping it silently would change the response contract.
- **No** existing test asserting the current (leaky) body shape — verify with
  `grep -rn "sessioninfo" tests/` before assuming a test will break.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: add the `mask_value` import to each of the three files.
2. Block B: replace the `sessioninfo` construction at each site with the
   redacting version. The three blocks are textually identical apart from the
   file; the anchor is unique within each file (1 occurrence each, verified).
3. Resolve the `data["refresh_token"]` FILL IN **before** writing the blocks —
   it changes what Block B looks like.
4. Run `pytest tests/test_azure_token_verifier.py tests/test_github_token_verifier.py tests/test_google_token_verifier.py -v`.

### Block A — the import (same edit in three files)
```python
# EXTEND — each file already has exactly one `from ..identity.types import ...`
#   line; add `mask_value` to it rather than adding a second import line.
# occurrences: 1 per file (verified: grep -c 'from ..identity.types import'
#   navigator_auth/backends/{azure,github,google}.py -> 1, 1, 1)
# e.g. `from ..identity.types import TokenResponse`
#   ->  `from ..identity.types import TokenResponse, mask_value`
# All three are currently exactly `from ..identity.types import TokenResponse`
# (verified: azure.py:19, github.py:17, google.py:14), so each becomes:
from ..identity.types import TokenResponse, mask_value
```
**Why**: `mask_value` lives in `identity/types.py`, not in a `libs/` helper, and
`IdentityStore.masked` (`store.py:301`) already imports it from there — one
source for redaction, so a future change to the mask format applies everywhere.

### Block B — `navigator_auth/backends/azure.py` (and the same in github.py, google.py)
```python
# REPLACE — the sessioninfo construction
# occurrences: 1 (verified: grep -c 'sessioninfo = {\*\*data, \*\*userdata}' navigator_auth/backends/azure.py)
                # FEAT-103 Module 6: never return the provider's tokens in the
                # response body. `auth_token` is the provider ACCESS token
                # (build_user_info, external.py:696) and `id_token` is the
                # provider's OIDC token; both are secrets to the caller.
                # The session keeps them — get_live_provider_token reads them —
                # this only redacts the HTTP body.
                sessioninfo = {**data, **userdata}
                for key in ("auth_token", "id_token"):
                    if key in sessioninfo:
                        sessioninfo[key] = mask_value(sessioninfo[key])
                return JSONResponse(sessioninfo, status=200)
```
**Why**: redact in place rather than `pop`, so a client that currently keys off
the presence of `auth_token` still sees the key (now carrying `"***1243"`
instead of a usable token) rather than a `KeyError`. `mask_value` returns
`None` for a falsy value, which JSON-serializes as `null` — an honest
representation of "nothing there".

```python
# FILL IN: `data["refresh_token"]` — NAVIGATOR's own refresh token, merged into
# this body from validate_user_info (external.py:766). Decide and apply one of:
#   (a) leave it in clear — it is the caller's own credential, and auth.py:505-513
#       indexes it in Redis for 90 days precisely so the caller can use it; or
#   (b) redact it too, in which case check_credentials callers lose the ability
#       to refresh and that is a deliberate API change.
# Bounded by spec §5: the criterion is about the PROVIDER's refresh token ("the
# raw provider refresh token appears in no session value and in no HTTP response
# body") — Navigator's own is not named — and by the criterion that
# `session["refresh_token"]`, where present, must still be Navigator's token and
# still resolve through `auth:refresh_token:<tok>`.
# Record the decision and its reason in the Completion Note either way.
```

### FILL IN checklist
*(Block A has no gap: all three import lines are identical and verified.)*
- [ ] Block B: the `data["refresh_token"]` decision, applied identically in all
      three files and recorded in the Completion Note.

---

## Implementation Notes

### Key Constraints
- Three files, identical change. Divergence between them is the defect this
  task is most likely to introduce — apply the same block, in the same place,
  in all three.
- `azure.py` is also edited by TASK-105 and TASK-109. Sequence, do not
  parallelize (spec Worktree Strategy).
- Never log the unredacted value while debugging this; `mask_value` is also the
  right tool for a log line (spec §7).

### References in Codebase
- `navigator_auth/identity/store.py:301` — `masked()`, the existing redaction
  consumer and the pattern to echo.
- `navigator_auth/identity/types.py:93-97` — `mask_value` itself.

---

## Acceptance Criteria

- [ ] The `check_credentials` JSON body contains neither the raw provider
      access token nor the raw `id_token`, at all three sites
- [ ] The keys are still present (masked), not removed
- [ ] Status codes and the `RuntimeError` → 402 branch are unchanged
- [ ] The three implementations are textually identical apart from the file
- [ ] `pytest tests/test_azure_token_verifier.py tests/test_github_token_verifier.py tests/test_google_token_verifier.py -v` passes, including
      `test_check_credentials_audience_bound_regression` (`tests/test_azure_token_verifier.py:241`)
- [ ] `ruff check navigator_auth/backends/` clean

---

## Test Specification

Test lives in TASK-111: `test_check_credentials_redacts_provider_tokens`
(spec §4).

---

## Agent Instructions

1. **Read the spec** §3 Module 6 and the G6 criterion in §5.
2. **Check dependencies** — TASK-103 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve both `FILL IN`s.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-108-redact-check-credentials.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note** — including the `data["refresh_token"]`
   decision and its reason.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Same block applied in azure.py, github.py, google.py (indent adapted). `auth_token` and `id_token` are masked in place via mask_value (keys retained). FILL IN decision: `data["refresh_token"]` (NAVIGATOR's own) is left in clear -- it is the caller's own credential, indexed in Redis (auth:refresh_token:<tok>) so the caller can use it, spec §5 names only the PROVIDER refresh token, and redacting would silently break callers' refresh. Other backends (adfs, okta, odoo, saml): none builds a `{**data, **userdata}` check_credentials body (grep of `**userdata` in backends/ shows only these three plus unrelated login-return dicts in basic/django/api/troc/noauth) so nothing else to redact. pytest azure+github+google verifier tests: 27 passed (artifacts/logs/TASK-108.log); ruff clean on the 3 files. Redaction test is TASK-111's.
**Deviations from spec**: none
