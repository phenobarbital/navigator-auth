# TASK-103: Additive capture kwargs on `ExternalAuth.build_user_info`

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 1, §2 items 2-3, §2 "New Public Interfaces", §2 "Data Models".

`build_user_info` writes only `auth_method`, `auth_token` and `token_type`
into the session payload (`external.py:694-697`; the method starts at `:668`
and returns at `:698`). The provider's `id_token`,
its real expiry, and the fact that a refresh token exists are all thrown away.
This task adds four **keyword-only, defaulted** capture arguments and the four
new session keys they produce.

"Optional is mandatory here": `build_user_info` has **eleven** call sites
across seven backends (spec §6 blast radius) and every one of them must keep
working untouched. This task is the foundation TASK-104 (vaulting),
TASK-105 (Azure wiring) and TASK-108 (redaction) build on.

The key names are deliberate, not cosmetic — see the Key Constraints below:
`refresh_token` is already **Navigator's own** refresh token in this same
dict, and `external_expires_at` is an existing name reused for consistency.

---

## Scope

- `navigator_auth/backends/external.py`: add keyword-only `id_token`,
  `refresh_token`, `expires_at`, `provider_user_id` to `build_user_info`
  (`:668`), each defaulting to `None`.
- Write `userdata["id_token"]`, `userdata["external_expires_at"]` (ISO-8601
  string), `userdata["has_refresh_token"]` (bool) and
  `userdata["external_provider_user_id"]` — **only** when the corresponding
  capture argument was supplied, so the old 3-argument call produces a
  byte-identical dict.
- Never write the refresh token itself into `userdata`; it is used *only* to
  compute `has_refresh_token`.
- Update the method docstring (Google style) to document the four arguments
  and the "presence only" rule for `refresh_token`.

**NOT in scope**: passing these arguments from any backend (TASK-105 does
Azure; Google/GitHub/Okta/ADFS/Odoo/SAML are explicit Non-Goals in spec §1);
the vault write (TASK-104); `validate_user_info` (`:700`) — it is untouched by
this task; redaction in `check_credentials` (TASK-108); the tests, which live
in TASK-111.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/external.py` | MODIFY | `build_user_info` signature + four new session keys |

---

## Codebase Contract

### Verified Imports
```python
from typing import Any, Optional            # verified: navigator_auth/backends/external.py:8
from datetime import datetime               # DOES NOT EXIST in external.py today — you add it
from navigator_session import AUTH_SESSION_OBJECT   # verified: external.py:21
from ..identity.types import TokenResponse  # verified: external.py:27
```

### Verified Signatures
```python
# navigator_auth/backends/external.py
class ExternalAuth(BaseAuthBackend):                                   # verified: :80
    def build_user_info(self, userdata: dict, token: str, mapping: dict) -> tuple:   # verified: :668
        userdata = self.get_user_mapping(user=userdata, mapping=mapping)             # verified: :682
        userid = userdata[self.userid_attribute]; userdata["id"] = userid            # verified: :685-686
        # KeyError -> falls back to self.username_attribute, else raises ValueError  # verified: :687-693
        userdata[self.session_key_property] = userid                                 # verified: :693
        userdata["auth_method"] = self._service_name                                 # verified: :694
        userdata["auth_token"] = token                                               # verified: :696
        userdata["token_type"] = self.scheme                                         # verified: :697
        return (userdata, userid)                                                    # verified: :698

    async def validate_user_info(self, request, user_id, userdata, token) -> dict:   # verified: :700
        return {"token": token, "refresh_token": refresh_token, "type": scheme,
                "expires_in": exp, **userdata}                                       # verified: :766
        #        ^^^^^^^^^^^^^ NAVIGATOR's refresh token — indexed in Redis by auth.py:512

# navigator_auth/backends/basic.py
_JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at", "mfa", "amr")  # verified: :152
#  -> `external_expires_at` is an EXISTING key name; reuse it, do not invent another

# navigator_auth/identity/types.py
@dataclass
class TokenResponse:                                                   # verified: :8
    expires_at: Optional[datetime] = None                              # verified: :21
    def __post_init__(self):   # derives expires_at from expires_in     # verified: :26-30
```

### Call sites that MUST keep working with the unchanged 3-arg call
`adfs.py:171`, `azure.py:135`, `azure.py:223`, `azure.py:534`, `github.py:102`,
`github.py:288`, `google.py:130`, `google.py:303`, `odoo.py:80`, `okta.py:87`,
`saml/sp.py:190` (spec §6, from `wiki_blast_radius`). Tests touching it:
`tests/test_azure_token_verifier.py:241`,
`tests/test_github_token_verifier.py:131,145`,
`tests/test_google_token_verifier.py:231,246`,
`tests/unit/identity/test_{github,google,odoo,okta}_backend.py`.

### Does NOT Exist (do not reference)
- **No** `id_token`, `has_refresh_token` or `external_provider_user_id` key in
  the session on any login path today.
- **No** `from datetime import datetime` in `external.py` — add it.
- **No** `userdata["expires_at"]`. The absolute-expiry key published by
  TASK-107 (Module 5) is Navigator's **own** token expiry and is a different
  value from the provider's `external_expires_at`. Do not conflate them.
- **No** session-key constant module — these are plain string literals, as
  `auth_method` / `auth_token` already are.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: add the `datetime` import — needed for the `expires_at` type hint
   and the `.isoformat()` call.
2. Block B: replace the `build_user_info` signature and tail. Keep the whole
   mapping/userid block between them untouched — it raises `ValueError` on a
   missing username attribute and `check_credentials` in three backends relies
   on that exact exception.
3. Write each new key **inside an `if ... is not None`** guard — because spec
   §5 requires the old 3-arg call to produce output identical to `dev`, and an
   unconditional `userdata["id_token"] = None` would break that byte-for-byte.
   `has_refresh_token` is the one exception: it is a bool, so it is written
   whenever `refresh_token` was passed at all.
4. Run `pytest tests/test_azure_token_verifier.py tests/test_github_token_verifier.py tests/test_google_token_verifier.py tests/unit/identity/ -v`
   — the whole point of this task is that they all still pass unchanged.

### Block A — `navigator_auth/backends/external.py` (import)
```python
# AFTER — insert below `from typing import Any, Optional`
# occurrences: 1 (verified: grep -c 'from typing import Any, Optional' navigator_auth/backends/external.py)
from datetime import datetime
```
**Why**: `external.py` has no `datetime` import today; the new `expires_at`
parameter is typed `Optional[datetime]` and serialized with `.isoformat()`.

### Block B — `navigator_auth/backends/external.py` (`build_user_info`)
```python
# REPLACE — the `def build_user_info(...)` signature line and its docstring
# occurrences: 1 (verified: grep -c 'def build_user_info' navigator_auth/backends/external.py)
    def build_user_info(
        self,
        userdata: dict,
        token: str,
        mapping: dict,
        *,
        id_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        provider_user_id: Optional[str] = None,
    ) -> tuple:
        """build_user_info.
            Get user or validate user from User Model.
        Args:
            userdata (Dict): User data gets from Auth Backend.
            token (str): User token gets from Auth Backend.
            mapping (dict): User mapping gets from Auth Backend.
            id_token (str, optional): Provider OIDC ID token, published in the
                session as ``id_token``. Keyword-only.
            refresh_token (str, optional): Provider refresh token. Used ONLY to
                set ``has_refresh_token``; the secret itself is NEVER written
                into ``userdata`` — it goes to the ciphered vault instead
                (FEAT-103 Module 2). Keyword-only.
            expires_at (datetime, optional): Real expiry of ``token``, published
                as the ISO-8601 string ``external_expires_at``. Keyword-only.
            provider_user_id (str, optional): Verified external account id,
                published as ``external_provider_user_id`` and used by
                ``get_live_provider_token`` to bind a session to exactly one
                linked account. Keyword-only.
        Returns:
            Tuple: user_id and user_data.
        Raises:
            UserNotFound: when user doesn't exists on Backend.
            ValueError: User doesn't have username attributes.

        Note:
            All four capture arguments default to ``None`` and each new key is
            written only when its argument was supplied, so the eleven existing
            3-argument call sites produce byte-identical output.
        """
```
**Why**: keyword-only (`*`) per spec §7 "Patterns to Follow" — the eleven call
sites pass `userdata=`/`token=`/`mapping=` by keyword already, and `*` makes it
impossible for a future positional call to drift into the capture slots.

```python
# REPLACE — the tail of build_user_info, from `userdata["auth_method"]` to `return (userdata, userid)`
# occurrences: 1 (verified: grep -c 'userdata\["auth_method"\] = self._service_name' navigator_auth/backends/external.py)
        userdata["auth_method"] = self._service_name
        # set original token in userdata
        userdata["auth_token"] = token
        userdata["token_type"] = self.scheme
        # FEAT-103 Module 1 — additive provider-credential capture.
        # NOTE: the provider refresh token is deliberately NOT stored here.
        # `refresh_token` in this dict is NAVIGATOR's own refresh token
        # (validate_user_info, :766) and auth.py:505-513 indexes it in Redis
        # for 90 days; writing the provider's secret there would corrupt
        # Navigator's refresh flow.
        if id_token is not None:
            userdata["id_token"] = id_token
        if expires_at is not None:
            userdata["external_expires_at"] = expires_at.isoformat()
        if refresh_token is not None:
            userdata["has_refresh_token"] = bool(refresh_token)
        if provider_user_id is not None:
            userdata["external_provider_user_id"] = str(provider_user_id)
        return (userdata, userid)
```
**Why**: `expires_at.isoformat()` rather than an epoch, because
`external_expires_at` is already an ISO-8601 string everywhere it appears
(`exchange.py:206-209`, `basic.py:152`'s `_JWT_EXTRA_KEYS`) and reusing the
name with a different type would be worse than inventing a new one.
`bool(refresh_token)` rather than `True`, so an empty-string refresh token is
reported honestly as "no refresh token available".

### FILL IN checklist
*(none — this task's blueprint is complete; the signature and the four key
names are fixed by spec §2 "Data Models" and the delegation table marks
Module 1 as delegation-eligible for exactly that reason)*

---

## Implementation Notes

### Key Constraints
- The four keys are written on the `userdata` dict that `validate_user_info`
  later splats into its return value (`:766`), so they also become part of the
  JSON body of `check_credentials`. That is why TASK-108 (redaction) exists —
  do not "solve" it here by withholding `id_token` from the session.
- `expires_at` must be timezone-aware. `TokenResponse.__post_init__`
  (`identity/types.py:26-30`) builds it with `datetime.now(timezone.utc)`, so a
  caller passing `token.expires_at` already satisfies this. Do not strip the
  tzinfo.
- Do not touch the `get_user_mapping` / userid-resolution block (`:682-693`):
  its `ValueError` is caught by `check_credentials` in three backends
  (`azure.py:556`, `github.py:303`, `google.py:322`).

### References in Codebase
- `navigator_auth/backends/exchange.py:206-209` — existing producer of
  `external_expires_at`.
- `navigator_auth/backends/basic.py:152` — `_JWT_EXTRA_KEYS`, which already
  carries `external_expires_at` into the JWT payload.
- `navigator_auth/identity/types.py:8-30` — `TokenResponse`, the source of the
  values these arguments carry.

---

## Acceptance Criteria

- [ ] `build_user_info` called with its old 3-argument signature produces
      output identical to `dev` (spec §5; proven by TASK-111's
      `test_build_user_info_without_new_kwargs_is_unchanged`)
- [ ] The four new keys appear only when their argument is supplied
- [ ] `"secret"` passed as `refresh_token=` appears in **no** value of
      `userdata`; only `has_refresh_token is True`
- [ ] `pytest tests/test_azure_token_verifier.py tests/test_github_token_verifier.py tests/test_google_token_verifier.py tests/unit/identity/ -v` passes unchanged
- [ ] `ruff check navigator_auth/backends/external.py` clean
- [ ] `mypy navigator_auth/backends/external.py` no new errors

---

## Test Specification

The tests for this module are TASK-111's
`test_build_user_info_without_new_kwargs_is_unchanged`,
`test_build_user_info_sets_id_token_and_expiry`,
`test_build_user_info_never_writes_refresh_token` and
`test_navigator_refresh_token_key_not_clobbered` (spec §4). This task must not
leave the existing suite red; it does not add test files of its own.

---

## Agent Instructions

1. **Read the spec** §3 Module 1 and §2 "Data Models" / "New Public Interfaces".
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-103-build-user-info-capture-kwargs.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
