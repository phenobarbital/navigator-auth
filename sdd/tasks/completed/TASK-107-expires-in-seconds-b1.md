# TASK-107: Extend convention B1 — `expires_in` is seconds, `expires_at` is the epoch

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 5, §8 Q2 (resolved), G5, §7 Known Risks.

`IdentityProvider.create_token` returns an **absolute epoch float** as its
third tuple element (`backends/idp/__init__.py:407` computes
`exp = (iat + timedelta(seconds=expiration)).timestamp()`; returned at `:436`).
Six publishers hand that float to clients under the key **`expires_in`**, and
four sites assign it to `usr.expires_in`. Nothing can correctly consume a value
whose name promises a duration and whose content is a timestamp.

**This is not a new convention — it is the repo's existing one.** The OAuth2
provider backend already does the right thing under a *named* decision:
`backends/oauth2/backend.py:9` reads literally *"B1: expires_in is seconds
(int)"*, implemented at `:1863`, `:1953` and `:2056` as
`expires_in = int(exp_abs - now_utc.timestamp())`, with the inline note at
`:1861`. The legacy login publishers simply never received B1. This task
extends it to them and adds an additive `expires_at` carrying the absolute
epoch.

Resolved §8 Q2 extended the scope to the dynamic `usr.expires_in` attribute,
accepting a real risk: it is **not** declared on `Identity`/`AuthUser`
(`identities.py` declares `access_token` at `:164` but no `expires_in`), so it
has no contract to version, and it reaches consumers via
`save_encoded_data(request, "user", user)` (`abstract.py:304`). Anything
reading `request.user.expires_in` as a timestamp breaks.

---

## Scope

- Create `navigator_auth/libs/expiry.py` with
  `expiry_fields(exp: float) -> dict` returning
  `{"expires_in": int(...), "expires_at": int(exp)}`, `expires_in` never below 0.
- Apply it at the six **response** publishers:
  `external.py:766`, `auth.py:437`, `auth.py:457`, `basic.py:261`,
  `troc.py:150`, `noauth.py:76`.
- Apply it at the four **user-object attribute** sites, each gaining a sibling
  `expires_at`: `basic.py:259`, `troc.py:148`, `noauth.py:69`, `token.py:144`.
- `CHANGELOG.md`: record **both** the response-shape change and the attribute
  change as client-visible.

**NOT in scope**: `create_token` itself (`idp/__init__.py:379-436`) — its
4-tuple contract is depended on by `basic.py:231`, `auth.py:428`,
`oauth2/backend.py:1855,1946,2050` and must not change; `oauth2/backend.py` —
it is already B1-conformant and is the *precedent*, not a target; declaring
`expires_in` on `Identity` (spec §7 accepts it as undeclared); the provider's
`external_expires_at` (TASK-103 — a different value); `docs/` (TASK-113).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/libs/expiry.py` | CREATE | `expiry_fields(exp)` helper |
| `navigator_auth/backends/external.py` | MODIFY | `:766` response dict |
| `navigator_auth/auth.py` | MODIFY | `:437` refresh response, `:457` ephemeral-token response |
| `navigator_auth/backends/basic.py` | MODIFY | `:259` attribute, `:261` response |
| `navigator_auth/backends/troc.py` | MODIFY | `:148` attribute, `:150` response |
| `navigator_auth/backends/noauth.py` | MODIFY | `:69` attribute, `:76` response |
| `navigator_auth/backends/token.py` | MODIFY | `:144` attribute only (no `expires_in` in its response) |
| `CHANGELOG.md` | MODIFY | client-visible change notes |

---

## Codebase Contract

### Verified Imports
```python
import time                                  # stdlib; needed by the new helper
from ..libs.expiry import expiry_fields      # the new helper, from backends/*.py
from .libs.expiry import expiry_fields       # the new helper, from auth.py (one level up)
```

### Verified Signatures — the source of the value
```python
# navigator_auth/backends/idp/__init__.py
class IdentityProvider:
    session_timeout: int = int(SESSION_TIMEOUT)                        # verified: :49
    def create_ephemeral_token(self, data=None, expiration: int = 1800):  # verified: :310
    def create_token(self, data=None, issuer=None, expiration=None,
                     audience=None) -> tuple:                          # verified: :379
        exp = (iat + timedelta(seconds=expiration)).timestamp()        # verified: :407  ABSOLUTE float
        return jwt_token, refresh_token, exp, self.scheme              # verified: :436
```

### The existing B1 precedent (copy this, do not invent)
```python
# navigator_auth/backends/oauth2/backend.py
#      * B1: expires_in is seconds (int).                              # verified: :9
        # B1: expires_in is seconds (not an absolute timestamp).       # verified: :1861
        now_utc = _now_utc()
        expires_in = int(exp_abs - now_utc.timestamp())                # verified: :1863
        now_utc = _now_utc(); expires_in = int(exp_abs - now_utc.timestamp())   # verified: :1952-1953
        now_utc = _now_utc(); expires_in = int(exp_abs - now_utc.timestamp())   # verified: :2055-2056
```

### Verified target sites
```python
# navigator_auth/backends/external.py
            return {"token": token, "refresh_token": refresh_token, "type": scheme,
                    "expires_in": exp, **userdata}                     # verified: :766

# navigator_auth/auth.py
            return JSONResponse({"token": token, "refresh_token": new_refresh_token,
                                 "expires_in": exp, "token_type": scheme}, status=200)   # verified: :437
            token, _, exp, scheme = self._idp.create_ephemeral_token(data=payload)       # verified: :456
            return JSONResponse({"token": token, "expires_in": exp,
                                 "token_type": scheme}, status=200)                      # verified: :457

# navigator_auth/backends/basic.py
        token, refresh_token, exp, scheme = self._idp.create_token(data=payload,
                                                                   expiration=expiration)  # verified: :231
                        expires_at=datetime.fromtimestamp(exp),        # verified: :250  (OauthAccessTokenRecord — LEAVE AS IS)
                    ttl = max(int(exp - time.time()), 1)               # verified: :256  (already seconds-remaining!)
        usr.access_token = token                                       # verified: :257
        usr.token_type = scheme                                        # verified: :258
        usr.expires_in = exp                                           # verified: :259
        userdata["refresh_token"] = refresh_token                      # verified: :260
        userdata["expires_in"] = exp                                   # verified: :261
        userdata["token_type"] = scheme                                # verified: :262
        _JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at", "mfa", "amr")  # verified: :152

# navigator_auth/backends/troc.py
                token, refresh_token, exp, scheme = self._idp.create_token(data=payload)  # verified: :145
                usr.expires_in = exp                                   # verified: :148
                userdata["expires_in"] = exp                           # verified: :150

# navigator_auth/backends/noauth.py
        token, refresh_token, exp, scheme = self._idp.create_token(data=payload,
                                                                   expiration=3600)       # verified: :66
        user.expires_in = exp                                          # verified: :69   (NOTE: `user`, not `usr`)
            "expires_in": exp,                                         # verified: :76

# navigator_auth/backends/token.py
                token, refresh_token, exp, scheme = self._idp.create_token(data=user)     # verified: :141
                usr.expires_in = exp                                   # verified: :144
                return {"token": f"{tenant}:{token}", "refresh_token": refresh_token, **user}  # verified: :145
                #  ^^ no "expires_in" key in this response — attribute site only
```

### Does NOT Exist (do not reference)
- **No** `navigator_auth/libs/expiry.py` — you create it. Note `libs/` is
  mostly Cython (`.pyx`/`.so`); the pure-Python precedents there are
  `redirect.py`, `csrf.py` and `sanitize.py`. A plain `.py` module is correct;
  do **not** write a `.pyx`.
- **No** `expires_at` key in any login/refresh/token response today.
- **No** `expires_in` declaration on `Identity`/`AuthUser`
  (`navigator_auth/identities.py` declares `access_token` at `:164`). It is a
  dynamic attribute; `usr.expires_at` will be too.
- **No** `_now_utc()` helper outside `backends/oauth2/backend.py` — do not
  import it across package boundaries; the new helper uses `time.time()`.
- **No** `expires_in` in `token.py`'s response dict — only the attribute.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: create the helper. One place computes the pair, so the ten sites
   cannot drift apart (which is how B1 came to be observed in one backend and
   not the others).
2. Block B: the six response publishers.
3. Block C: the four attribute sites.
4. Block D: `CHANGELOG.md`.
5. Run `pytest tests/ -v` and diff against the `dev` baseline — this task
   touches six modules and its whole risk profile is "did something read the
   old shape".

### Block A — `navigator_auth/libs/expiry.py` (CREATE)
```python
"""Published token-expiry fields (FEAT-103 Module 5).

``IdentityProvider.create_token`` returns an ABSOLUTE epoch (a float) as its
third tuple element (``backends/idp/__init__.py:407``). Publishing that under
the key ``expires_in`` is wrong: RFC 6749 §4.2.2 defines ``expires_in`` as
"the lifetime in seconds of the access token".

This module holds the single conversion used by every publisher, extending the
repo's existing **B1** decision — *"expires_in is seconds (int)"*,
``backends/oauth2/backend.py:9`` — from the OAuth2 provider backend to the
legacy login publishers.
"""
import time


def expiry_fields(exp: float) -> dict:
    """Map an absolute epoch ``exp`` onto the published expiry pair.

    Args:
        exp: Absolute expiry as a UNIX epoch, as returned by
            ``IdentityProvider.create_token`` / ``create_ephemeral_token``.

    Returns:
        ``{"expires_in": <int seconds remaining, never < 0>,
           "expires_at": <int absolute epoch>}``

    Example:
        >>> fields = expiry_fields(time.time() + 3600)
        >>> 3595 <= fields["expires_in"] <= 3600
        True
    """
    remaining = int(exp - time.time())
    return {
        "expires_in": max(remaining, 0),
        "expires_at": int(exp),
    }
```
**Why**: `max(remaining, 0)` because an already-expired token must publish `0`,
not a negative duration — a client doing `now + expires_in` on a negative value
silently computes a past deadline. `int(exp)` truncates the float epoch
(`create_token` produces e.g. `1793050179.051082`); seconds granularity is what
every consumer of an epoch here needs, and `float` in JSON invites the same
"is this seconds or an instant" confusion the task is removing.

### Block B — the six response publishers
```python
# navigator_auth/backends/external.py
# AFTER — insert below `from .abstract import BaseAuthBackend`
# occurrences: 1 (verified: grep -c 'from .abstract import BaseAuthBackend' navigator_auth/backends/external.py)
from ..libs.expiry import expiry_fields
```
```python
# REPLACE — the validate_user_info return
# occurrences: 1 (verified: grep -c '"expires_in": exp, \*\*userdata' navigator_auth/backends/external.py)
            return {
                "token": token,
                "refresh_token": refresh_token,
                "type": scheme,
                **expiry_fields(exp),
                **userdata,
            }
```
```python
# navigator_auth/auth.py
# AFTER — insert below `from .backends.idp import IdentityProvider`
# occurrences: 1 (verified: grep -c 'from .backends.idp import IdentityProvider' navigator_auth/auth.py)
from .libs.expiry import expiry_fields
```
```python
# REPLACE — the refresh-token response (auth.py:437)
# occurrences: 1 (verified: grep -c '"refresh_token": new_refresh_token' navigator_auth/auth.py)
            return JSONResponse(
                {
                    "token": token,
                    "refresh_token": new_refresh_token,
                    **expiry_fields(exp),
                    "token_type": scheme,
                },
                status=200,
            )
```
```python
# REPLACE — the ephemeral-token response (auth.py:457)
# occurrences: 1 (verified: grep -c 'JSONResponse({"token": token, "expires_in": exp, "token_type": scheme}' navigator_auth/auth.py)
            return JSONResponse(
                {"token": token, **expiry_fields(exp), "token_type": scheme},
                status=200,
            )
```
```python
# navigator_auth/backends/noauth.py
# REPLACE — the `"expires_in": exp,` entry in the returned dict
# occurrences: 1 (verified: grep -c '"expires_in": exp,' navigator_auth/backends/noauth.py)
            **expiry_fields(exp),
```
**Why `**expiry_fields(exp)` instead of two explicit keys**: the helper is the
single definition of the pair; splatting it makes a site that forgets
`expires_at` impossible. Key order inside the dict is irrelevant to JSON
consumers but `**userdata` stays **last** at `external.py:766` — it does today,
and a reordering would change which value wins on a key collision.

### Block C — the four attribute sites
```python
# navigator_auth/backends/basic.py
# REPLACE — the usr attribute assignment and the userdata response key
# occurrences: 1 each (verified: grep -c 'usr.expires_in = exp' navigator_auth/backends/basic.py -> 1;
#                      grep -c 'userdata\["expires_in"\] = exp' navigator_auth/backends/basic.py -> 1)
        _expiry = expiry_fields(exp)
        usr.access_token = token
        usr.token_type = scheme
        usr.expires_in = _expiry["expires_in"]
        usr.expires_at = _expiry["expires_at"]
        userdata["refresh_token"] = refresh_token
        userdata.update(_expiry)
        userdata["token_type"] = scheme
```
```python
# navigator_auth/backends/troc.py
# REPLACE — the attribute + response pair
# occurrences: 1 each (verified: grep -c 'usr.expires_in = exp' navigator_auth/backends/troc.py -> 1)
                _expiry = expiry_fields(exp)
                usr.access_token = token
                usr.token_type = scheme
                usr.expires_in = _expiry["expires_in"]
                usr.expires_at = _expiry["expires_at"]
                userdata["refresh_token"] = refresh_token
                userdata.update(_expiry)
                userdata["token_type"] = scheme
```
```python
# navigator_auth/backends/noauth.py
# REPLACE — the attribute assignment (NOTE: the variable is `user`, not `usr`)
# occurrences: 1 (verified: grep -c 'user.expires_in = exp' navigator_auth/backends/noauth.py)
        _expiry = expiry_fields(exp)
        user.expires_in = _expiry["expires_in"]
        user.expires_at = _expiry["expires_at"]
```
```python
# navigator_auth/backends/token.py
# REPLACE — the attribute assignment (this backend's response has NO expires_in key)
# occurrences: 1 (verified: grep -c 'usr.expires_in = exp' navigator_auth/backends/token.py)
                _expiry = expiry_fields(exp)
                usr.expires_in = _expiry["expires_in"]
                usr.expires_at = _expiry["expires_at"]
```
**Why**: `_expiry` is computed once per site so the attribute and the response
key cannot disagree by a second — and `basic.py:256` already computes
`ttl = max(int(exp - time.time()), 1)` a few lines above for the jti index,
which is the same arithmetic. **Leave `basic.py:250`'s
`expires_at=datetime.fromtimestamp(exp)` alone**: that is
`OauthAccessTokenRecord.expires_at`, a `datetime` whose naive-ness is
load-bearing (see the comment at `:246-249`).
Each modified backend needs the import — **FILL IN: add
`from ..libs.expiry import expiry_fields` to `basic.py`, `troc.py`,
`noauth.py` and `token.py` next to their existing relative imports** (bounded
by: match each file's existing import style and ordering; `external.py` and
`auth.py` are already covered by Block B).

### Block D — `CHANGELOG.md`
```markdown
# FILL IN: add a bullet under the existing `# Unreleased` heading (verified:
# CHANGELOG.md:1 — this file uses a single `# Unreleased` section with bold
# lead-ins and nested bullets, not per-version headings) — bounded by that
# format, and it MUST state both client-visible changes:
#   - `expires_in` in every login / refresh / token response is now an integer
#     number of seconds remaining (RFC 6749 §4.2.2), not an absolute epoch.
#     Extends the existing B1 decision (backends/oauth2/backend.py) to the
#     legacy login publishers. The absolute instant is published alongside as
#     the new `expires_at`.
#   - `request.user.expires_in` changes the same way and gains
#     `request.user.expires_at`. This attribute is undeclared on `Identity`, so
#     there is no version to bump — any consumer reading it as a timestamp must
#     switch to `expires_at`.
```

### FILL IN checklist
- [ ] Block C: the `expiry_fields` import in each of `basic.py`, `troc.py`,
      `noauth.py`, `token.py`.
- [ ] Block D: the `CHANGELOG.md` entry, in this repo's existing format.

---

## Implementation Notes

### Key Constraints
- `create_token`'s 4-tuple is **not** changed. Five call sites unpack it
  (`basic.py:231`, `troc.py:145`, `noauth.py:66`, `token.py:141`,
  `auth.py:428`, plus `oauth2/backend.py:1855,1946,2050`); spec §5 has an
  explicit acceptance criterion for this.
- This task shares `external.py` with TASK-103/104/106 and `auth.py` with
  nothing else in this feature. **Coordinate the `external.py` edits** — spec
  Worktree Strategy says Modules 5 and 6 share files with 1-4 and must run
  sequentially, not concurrently.
- The change is observably client-visible. That is accepted (spec §7, §8 Q2):
  clients receiving an absolute epoch under a duration key are already broken,
  and `expires_at` ships alongside so they have a correct migration target.

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py:1861-1863` — the B1 implementation
  this extends. The new helper must produce the same shape for the same `exp`
  (TASK-111's `test_expires_in_matches_oauth2_b1_convention` pins it).
- `navigator_auth/backends/basic.py:256` — `max(int(exp - time.time()), 1)`,
  the same arithmetic already in use for a TTL.

---

## Acceptance Criteria

- [ ] `expires_in` in every login/refresh/token response is an `int` of seconds
      remaining, and `0 < expires_in <= SESSION_TIMEOUT`
- [ ] `expires_at` carries the absolute epoch, ≈ `now + expires_in` (±2 s)
- [ ] `usr.expires_in` is `int` seconds-remaining and `usr.expires_at` carries
      the epoch at **all four** set sites
- [ ] The legacy publishers and `oauth2/backend.py`'s B1 path produce the same
      shape for the same `exp`
- [ ] No change to the `create_token` 4-tuple contract
- [ ] `CHANGELOG.md` records both changes as client-visible
- [ ] `pytest tests/ -v` shows no new failures versus the `dev` baseline
- [ ] `ruff check navigator_auth/` clean

---

## Test Specification

Tests live in TASK-111: `test_expires_in_is_seconds_remaining`,
`test_expires_at_is_absolute_epoch`, `test_user_object_expires_in_is_seconds`,
`test_expires_in_matches_oauth2_b1_convention` (spec §4).

---

## Agent Instructions

1. **Read the spec** §3 Module 5 and §8 Q2.
2. **Check dependencies** — none, but coordinate `external.py` with
   TASK-103/104/106 if they are in flight.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve both `FILL IN`s.
5. **Verify** all acceptance criteria, including the full-suite baseline diff.
6. **Move this file** to `sdd/tasks/completed/TASK-107-expires-in-seconds-b1.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Helper `navigator_auth/libs/expiry.py` + 6 response publishers (external, auth x2, basic, troc, noauth) + 4 attribute sites (basic, troc, noauth, token) + CHANGELOG entries for both client-visible changes. Smoke: expiry_fields(now+3600) -> {'expires_in': 3599, ...}; expired -> expires_in 0. Full suite `pytest tests`: 37 failed / 1520 passed vs baseline (origin/dev 8897024, same machine, same shared DB) 37 failed / 1519 passed; the FAILED sets are byte-identical (artifacts/logs/baseline_failures_dev.txt vs TASK-107_failures.txt). No new failures.
**Out-of-list file touched**: `tests/test_identity_id_token.py::test_migration_runs_002_after_001` asserted exactly 3 migration statements; TASK-102's 004 made it red, so its count was bumped 3 -> 4 (+ an assertion on the 4th). Not listed in TASK-102; flagged here.
**Repo-wide ruff**: `ruff check navigator_auth/` reports 37 pre-existing errors (so the AC "clean" is unattainable repo-wide); touched files add none.
**IMPORTANT side effect**: the existing suite talks to the shared dev DB (nav-api.dev.local). In the baseline-vs-new run, vault writes failed with `null value in column "uid" ... violates not-null constraint` rather than `column "identity_id" does not exist`, which implies migration 004 got applied to that DB by the test run (setup_identity_columns). It also shows legacy `uid` is NOT NULL with no default, so model INSERTs still fail on that table even with 004 -- see report.
**Deviations from spec**: none in behaviour.
