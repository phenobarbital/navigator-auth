# TASK-104: Generalized vaulting — explicit `TokenResponse` + exact-account lookup

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-102, TASK-103
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 2, §2 items 4-5, §2 "New Public Interfaces".

`_vault_upstream_token` (`external.py:454`) has exactly **one** caller today —
the OAuth2-AS resume at `external.py:440` — and it rebuilds a *partial*
`TokenResponse` from the session carrying `access_token` only (`:480-484`).
Two consequences:

1. The normal `/auth/<provider>/callback/` login never vaults anything, so G2
   (ciphered refresh token in `auth.user_identities`) cannot happen.
2. When the AS resume *does* fire after a captured login, that partial re-save
   overwrites the full grant's expiry and scopes, or creates a second row under
   a different account id (spec §9, CONFIRMED finding).

This task generalizes the vault write to accept an explicit `TokenResponse`,
calls it from the login path, adds the exact-account lookup
`IdentityStore.get_for_provider_account` that TASK-106 needs, and makes the AS
resume skip its partial re-save when the login already captured a grant.

---

## Scope

- `navigator_auth/backends/external.py`:
  - `_vault_upstream_token(request, *, token: Optional[TokenResponse] = None)`
    — when `token` is given, vault it as-is; when `None`, keep today's
    session-reconstruction fallback verbatim for legacy/uncaptured paths.
  - Keep the best-effort contract: any failure logs a warning and returns
    (`:489-492`), never raises.
  - Call it from the login path after `validate_user_info` has created the
    session, using the session's local `user_id`.
  - Mark the request when a login grant was vaulted, and make
    `_resume_oauth2_authorize` (`:419`) skip its `_vault_upstream_token(request)`
    call in that case.
  - Populate `token.provider_user_id` from `get_identity_userid(userinfo)`
    (`:515`) before vaulting; on a missing account id, log a warning and
    **skip** capture rather than persist an unbound row.
- `navigator_auth/identity/store.py`: add
  `get_for_provider_account(user_id, provider, provider_user_id)` returning the
  single **enabled, credential-bearing** row for that exact triple, or `None`.
  Leave `get_by_provider` (`:222`) untouched for its existing consumers.

**NOT in scope**: `AzureAuth` call-site wiring and the MSAL normalizer
(TASK-105); `get_live_provider_token` / `refresh_provider_tokens` (TASK-106);
changing `get_by_provider`'s newest-wins semantics; the Session Vault
(`cache_credential`, `store.py:360`) — spec §2 item 4 verified it is a silent
no-op on the callback path because `load_vault_for_session` runs only at
`auth.py:518`; tests (TASK-111).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/external.py` | MODIFY | `_vault_upstream_token` signature + login-path call + AS-resume guard |
| `navigator_auth/identity/store.py` | MODIFY | new `get_for_provider_account` |

---

## Codebase Contract

### Verified Imports
```python
from typing import Any, Optional                      # verified: external.py:8
from navigator_session import AUTH_SESSION_OBJECT      # verified: external.py:21
from ..identity.types import TokenResponse             # verified: external.py:27
# inside _vault_upstream_token, imported lazily (keep this style):
from navigator_session import get_session              # verified: external.py:464
from ..identity.store import IdentityStore             # verified: external.py:465
from ..identity.types import TokenResponse             # verified: external.py:466
# store.py
from datetime import datetime, timezone                # verified: identity/store.py (used at :243)
from asyncdb.exceptions import NoDataFound             # verified: used at :228, :262
from ..models import UserIdentity                      # verified: used throughout store.py
```

### Verified Signatures
```python
# navigator_auth/backends/external.py
async def _resume_oauth2_authorize(self, request, flow_id: str, response):   # verified: :419
    status = getattr(response, "status", 500)                                # verified: :427
    if status not in (301, 302, 303, 307, 308): ... return response          # verified: :428-433
    await self._vault_upstream_token(request)                                # verified: :440  (ONLY caller today)

async def _vault_upstream_token(self, request: web.Request) -> None:         # verified: :454
    session = await get_session(request, new=False)                          # verified: :468
    if not session: return                                                   # verified: :469-470
    access_token = session.get("auth_token")                                 # verified: :471
    if not access_token: return                                              # verified: :472-473
    user_id = session.get("user_id")                                         # verified: :474
    if user_id is None:                                                      # verified: :475
        session_obj = session.get(AUTH_SESSION_OBJECT) or {}                 # verified: :476
        user_id = session_obj.get("user_id")                                 # verified: :477
    if user_id is None: return                                               # verified: :478-479
    token = TokenResponse(access_token=access_token,
                          token_type=session.get("token_type") or self.scheme,
                          provider_user_id=str(session.get(self.userid_attribute) or ""))  # verified: :480-484
    store = IdentityStore(request.app["authdb"])                             # verified: :485
    await store.save_linked_identity(user_id, self._service_name, token, {}) # verified: :486-488
except Exception as err: self.logger.warning(...)                            # verified: :489-492

def get_identity_userid(self, userinfo: dict) -> Optional[str]:              # verified: :515
    for key in (self.userid_attribute, "sub", "id"):                         # verified: :517
        ...  return str(value)   # else None                                 # verified: :518-521

def build_user_info(self, userdata, token, mapping, *, id_token=None,
                    refresh_token=None, expires_at=None,
                    provider_user_id=None) -> tuple:                         # TASK-103
async def validate_user_info(self, request, user_id, userdata, token) -> dict:  # verified: :700
    session = await self.remember(request, user_id, userinfo, user)          # verified: :755
    uid = userinfo[AUTH_SESSION_OBJECT].get("user_id", user_id)              # verified: :748

# navigator_auth/identity/store.py
class IdentityStore:                                                         # verified: :49
    def __init__(self, pool): self._cipher = ...  # raises ConfigError w/o keys  # verified: :52-58
    async def save_linked_identity(self, user_id, provider, token: TokenResponse,
                                   userinfo: Optional[dict] = None) -> UserIdentity:  # verified: :112
        #  seals access_token / refresh_token / id_token independently       # verified: :132-138
        #  looks up UserIdentity.get(user_id=, auth_provider=, provider_user_id=)  # verified: :147-152
        #  D10: a re-save without a new refresh/id token KEEPS the stored one # verified: :155-157
    async def get_by_provider(self, user_id, provider) -> Optional[UserIdentity]:  # verified: :222
        """The newest enabled credential-bearing identity for a provider."""      # verified: :224
        rows = await UserIdentity.filter(user_id=user_id, auth_provider=provider) # verified: :227
        rows = [r for r in rows or [] if getattr(r, "access_token", None)
                and getattr(r, "enabled", True)]                                  # verified: :231-235
        rows.sort(key=... refreshed_at or created_at ..., reverse=True)            # verified: :238-244
        return rows[0]                                                            # verified: :245
    async def update_tokens(self, identity, token) -> UserIdentity:               # verified: :261
    def decrypt_credential(self, identity) -> TokenResponse:                      # verified: :280
```

### Does NOT Exist (do not reference)
- **No** `IdentityStore.get_for_provider_account` — this task creates it.
- **No** vault available on `/auth/<provider>/callback/`:
  `load_vault_for_session` is called only at `auth.py:518` (`api_login`), so
  `cache_credential` (`store.py:360`) is a silent no-op there. Do not add it.
- **No** `request["..."]` capture marker today — you introduce one; pick a
  namespaced key (see Block D) rather than a bare name.
- **No** unique constraint on `(user_id, auth_provider)`; the only unique index
  is the partial `uq_user_identities_provider_account` on
  `(user_id, auth_provider, provider_user_id) WHERE provider_user_id IS NOT NULL`
  (`identity/sql/001_identity_credentials.sql:17-19`). Never write an upsert
  targeting the two-column pair — that is SQLSTATE 42P10.
- **No** `IdentityStore` method that filters on `enabled` for you: both
  `get_by_provider` (`:231-235`) and your new method must filter in Python.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: `get_for_provider_account` in `store.py`. Filter in Python on
   `enabled` + `access_token` exactly as `get_by_provider` does — because
   asyncdb's `filter()` has no boolean/NOT NULL predicate in use anywhere in
   this file, and copying the existing shape keeps the two methods comparable.
2. Block B: new `_vault_upstream_token` signature and body.
3. Block C: the login-path call. It must run **after** `validate_user_info`
   returns, because that is what creates the session (`:755`) and resolves the
   local `uid` (`:748`) that `save_linked_identity` keys on.
4. Block D: the capture marker + the AS-resume guard, so the partial re-save
   cannot clobber a full grant.
5. Run `pytest tests/unit/identity/ tests/test_azure_token_verifier.py -v`.

### Block A — `navigator_auth/identity/store.py`
```python
# AFTER — insert below the body of `async def get_by_provider`, before `async def delete`
# occurrences: 1 (verified: grep -c 'async def get_by_provider' navigator_auth/identity/store.py)
    async def get_for_provider_account(
        self,
        user_id: Any,
        provider: str,
        provider_user_id: Optional[str],
    ) -> Optional[UserIdentity]:
        """The enabled credential-bearing identity for one EXACT account.

        Unlike :meth:`get_by_provider`, this never falls back to "the newest
        linked account": a session bound to external account A must never be
        refreshed with account B's credential, however recently B was linked
        (FEAT-103 Module 4).

        Args:
            user_id: Local Navigator user id.
            provider: Backend service name (``self._service_name``).
            provider_user_id: Verified external account id. ``None`` or an
                empty string returns ``None`` — a legacy row without a
                binding requires a re-login, it is not a match.

        Returns:
            The matching ``UserIdentity``, or ``None``.
        """
        if not provider_user_id:
            return None
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            try:
                rows = await UserIdentity.filter(
                    user_id=user_id,
                    auth_provider=provider,
                    provider_user_id=str(provider_user_id),
                )
            except NoDataFound:
                return None
        rows = [
            row
            for row in rows or []
            if getattr(row, "access_token", None) and getattr(row, "enabled", True)
        ]
        # FILL IN: with the partial unique index on
        # (user_id, auth_provider, provider_user_id) there can be at most one
        # row here — decide whether >1 is logged as a data-integrity warning or
        # silently takes rows[0] — bounded by "returns only the exact enabled
        # credential-bearing row, or None" (spec Module 2) and by the fact that
        # a legacy table may predate that index.
        return rows[0] if rows else None
```
**Why**: `provider_user_id` is passed through `str()` because the session
carries it as a string (TASK-103 writes `str(provider_user_id)`) while
providers may hand back an int (`get_identity_userid` normalizes with `str()`
too, `external.py:521`). A type mismatch here would silently return `None` and
look like "credential missing".

### Block B — `navigator_auth/backends/external.py` (`_vault_upstream_token`)
```python
# REPLACE — the whole `async def _vault_upstream_token` method (external.py:454-492)
# occurrences: 1 (verified: grep -c 'async def _vault_upstream_token' navigator_auth/backends/external.py)
    async def _vault_upstream_token(
        self,
        request: web.Request,
        *,
        token: Optional["TokenResponse"] = None,
    ) -> None:
        """Cipher the upstream provider credential into ``auth.user_identities``.

        The AS-initiated login is the same kind of event as an explicit
        identity link — the user has just authorised this deployment against
        Google/Microsoft — so the credential is ciphered into the vault
        through the same ``IdentityStore`` path.

        Args:
            request: The in-flight request; carries the session and ``authdb``.
            token: The full grant captured during the login negotiation. When
                ``None`` the legacy behaviour is kept: a PARTIAL TokenResponse
                carrying only the access token is rebuilt from the session.

        Note:
            Best-effort — a vault failure logs a warning and must never break
            the login or the authorize resume (unchanged contract).
        """
        try:
            from navigator_session import get_session
            from ..identity.store import IdentityStore
            from ..identity.types import TokenResponse

            session = await get_session(request, new=False)
            if not session:
                return
            user_id = session.get("user_id")
            if user_id is None:
                session_obj = session.get(AUTH_SESSION_OBJECT) or {}
                user_id = session_obj.get("user_id")
            if user_id is None:
                return
            if token is None:
                access_token = session.get("auth_token")
                if not access_token:
                    return
                token = TokenResponse(
                    access_token=access_token,
                    token_type=session.get("token_type") or self.scheme,
                    provider_user_id=str(
                        session.get(self.userid_attribute) or ""
                    ),
                )
            if not token.provider_user_id:
                # FEAT-103 Module 2: never persist an unbound login grant — a
                # row without provider_user_id cannot be matched by
                # get_for_provider_account and would disable refresh.
                self.logger.warning(
                    f"{self._service_name}: no verified external account id; "
                    "skipping credential capture."
                )
                return
            store = IdentityStore(request.app["authdb"])
            await store.save_linked_identity(
                user_id, self._service_name, token, {}
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"{self._service_name}: could not vault the upstream token: {err}"
            )
```
**Why**: the `user_id` resolution moved *above* the token branch because both
branches need it, and the legacy branch's `access_token` check only applies to
the reconstruction path. The `provider_user_id` guard is new and applies to
**both** paths — spec Module 2: "Missing account IDs disable capture/refresh
with a warning; never persist an unbound login grant." Note the legacy branch
previously allowed an empty-string `provider_user_id` through; that now
short-circuits, which is the intended behaviour change.

### Block C — `navigator_auth/backends/external.py` (login-path capture helper)
```python
# AFTER — insert below the end of `_vault_upstream_token` (i.e. after :492,
#         before the `# ---` comment banner that opens at :494-495)
# occurrences: 1 (verified: grep -c 'Identity-link flow: a logged-in user' navigator_auth/backends/external.py -> line 495)
    async def capture_login_credential(
        self,
        request: web.Request,
        token: "TokenResponse",
    ) -> None:
        """Vault a credential captured during the login negotiation.

        Called by a backend's ``auth_callback``/``authenticate`` AFTER
        ``validate_user_info`` has created the session — ``save_linked_identity``
        keys on the local ``user_id``, which only exists once the session does.

        Marks the request so ``_resume_oauth2_authorize`` skips its partial
        re-save (which would otherwise overwrite this grant's expiry and
        scopes, or create a second row under a different account id).
        """
        request[CAPTURED_LOGIN_GRANT] = True
        await self._vault_upstream_token(request, token=token)
```
**Why**: a named helper rather than inlining `_vault_upstream_token(request,
token=...)` at each backend call site, because the marker must be set on
**every** capture path (callback and ROPC) and a forgotten marker silently
reintroduces the overwrite bug. TASK-105 calls this one method twice.

### Block D — `navigator_auth/backends/external.py` (marker constant + AS guard)
```python
# AFTER — insert below the line `OAUTH2_RESUME_COOKIE: str = "nav_oauth2_flow"`
# occurrences: 1 (verified: grep -c 'OAUTH2_RESUME_COOKIE: str =' navigator_auth/backends/external.py -> line 63)
#: FEAT-103 Module 2 — set on the request once a login grant has been vaulted,
#: so the OAuth2-AS resume does not re-save a partial TokenResponse over it.
CAPTURED_LOGIN_GRANT = "_nav_captured_login_grant"
```
```python
# REPLACE — the AS-resume vault call and its comment
# occurrences: 1 (verified: grep -c 'await self._vault_upstream_token(request)' navigator_auth/backends/external.py)
        # Best-effort: persist the upstream credential in the Identity Vault,
        # exactly as the identity-link flow does — UNLESS the login already
        # captured the full grant (FEAT-103 Module 2). Re-saving the partial,
        # session-rebuilt TokenResponse here would drop the captured expiry and
        # scopes, or create a second row under a different account id.
        if not request.get(CAPTURED_LOGIN_GRANT, False):
            await self._vault_upstream_token(request)
```
**Why**: `request.get(...)` (aiohttp requests are `MutableMapping`) rather than
a session key, because the marker must be per-request: the session survives the
redirect and a stale flag there would permanently disable the legacy fallback
for that user.

### FILL IN checklist
- [ ] Block A: behaviour when `rows` holds more than one match (log vs. silent
      `rows[0]`).

---

## Implementation Notes

### Key Constraints
- **Best-effort is a contract, not a style choice.** `external.py:491-494` and
  `vault/integration.py:11-13` both state it; TASK-111's
  `test_vault_upstream_token_failure_does_not_raise` pins it.
- `IdentityStore.__init__` builds an `IdentityCipher` eagerly (`store.py:52-58`)
  and raises `ConfigError` when vault keys are unconfigured. The broad
  `except Exception` in `_vault_upstream_token` already covers it; do not
  narrow that catch.
- `save_linked_identity`'s **D10** rule (`store.py:155-157`): a re-save without
  a new refresh/id token keeps the previously vaulted one. This is why the AS
  resume's partial save is *merely* damaging (expiry/scopes) rather than
  token-destroying — but it is still damaging. Keep the guard.
- Non-integer `user_id`: `load_vault_for_session` skips non-int user ids
  (`vault/integration.py:74-84`) and `IdentityStore` keys on `user_id` too.
  Fail soft and log; never raise (spec §7).

### References in Codebase
- `navigator_auth/backends/external.py:611` — `finish_identity_link`, the
  identity-link flow that already does a full-grant vault write; mirror its
  ordering.
- `navigator_auth/identity/store.py:222-245` — `get_by_provider`, the shape
  Block A copies (and deliberately diverges from on account selection).

---

## Acceptance Criteria

- [ ] `_vault_upstream_token(request, token=<full grant>)` passes that exact
      object to `save_linked_identity` — no session reconstruction
- [ ] `_vault_upstream_token(request)` with no `token` behaves as on `dev` for
      a legacy session that has a non-empty `provider_user_id`
- [ ] A raising `IdentityStore` is swallowed and logged
- [ ] A grant with no `provider_user_id` is **not** persisted, and a warning is
      logged
- [ ] `get_for_provider_account` returns `None` for a missing, disabled,
      credential-less, or wrong-account row, and never falls back to another
      account
- [ ] After a callback followed by an AS resume, the row's scopes, expiry and
      tokens are the captured ones and there is exactly one row
- [ ] `pytest tests/unit/identity/ -v` passes
- [ ] `ruff check navigator_auth/backends/external.py navigator_auth/identity/store.py` clean

---

## Test Specification

Tests live in TASK-111: `test_vault_upstream_token_uses_passed_tokenresponse`,
`test_vault_upstream_token_failure_does_not_raise`,
`test_capture_binds_verified_provider_account`,
`test_refresh_uses_login_account_not_newest_link`,
`test_oauth2_resume_preserves_captured_grant` (spec §4).

---

## Agent Instructions

1. **Read the spec** §3 Module 2 and §2 items 4-5.
2. **Check dependencies** — TASK-102 and TASK-103 must be in
   `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve the `FILL IN`.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-104-generalized-vaulting.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
