# TASK-100: Normalize legacy session users at navigator-auth's rehydration points

**Feature**: FEAT-102 — Normalize `AuthUser.organizations` received as JSON
**Spec**: `sdd/specs/fix-organizations-orgid.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-99
**Assigned-to**: unassigned

---

## Context

Spec §2 item 2 (legacy session policy): navigator-session restores the user
with jsonpickle by assigning `__dict__` — no constructor runs — so sessions
written before FEAT-102 still carry dicts. This task implements spec §3
Module 2: call `normalize_memberships()` (TASK-99) in the two
`get_session_user` methods and `normalize_organizations()` inside
`allowed_organizations`, treating `ValueError` as "stale/corrupt session
user" (fail closed). Also covers the spec §4 round-trip tests (AC6, AC7, the
`create_user` → `InvalidAuth` behaviour change) and the version bump to
0.28.7 (spec §5 last criterion).

---

## Scope

- `navigator_auth/backends/abstract.py`: import `AuthUser`; in
  `BaseAuthBackend.get_session_user` call `user.normalize_memberships()` when
  `isinstance(user, AuthUser)`; add `ValueError` to the `except` tuple.
- `navigator_auth/auth.py`: add `from .identities import AuthUser`; same two
  changes in `AuthHandler.get_session_user`.
- `navigator_auth/decorators.py`: in both wrappers of `allowed_organizations`
  call `user.normalize_organizations()` right after `session.decode("user")`;
  add `ValueError` to their `except` tuple.
- `navigator_auth/version.py`: `0.28.6` → `0.28.7`.
- Write `tests/unit/test_session_user_rehydration.py` (spec §4 round-trip table).

**NOT in scope**: the other 11 `session.decode("user")` call sites (spec §1
Non-Goals); `identities.py` (TASK-99/101); migrating stored sessions;
navigator-session itself.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/abstract.py` | MODIFY | import + `get_session_user` |
| `navigator_auth/auth.py` | MODIFY | import + `get_session_user` |
| `navigator_auth/decorators.py` | MODIFY | `allowed_organizations` (both wrappers) |
| `navigator_auth/version.py` | MODIFY | bump to 0.28.7 |
| `tests/unit/test_session_user_rehydration.py` | CREATE | AC6, AC7, `create_user` behaviour change |

---

## Codebase Contract

### Verified Imports
```python
from ..identities import Identity, AuthBackend            # verified: navigator_auth/backends/abstract.py:39 (extend with AuthUser)
from .backends.idp import IdentityProvider                 # verified: navigator_auth/auth.py:39 (anchor; no .identities import exists in auth.py)
from navigator_session import get_session                  # verified: navigator_auth/decorators.py:8
from navigator_auth.identities import AuthUser, Organization      # TASK-99 adds normalize_memberships / normalize_organizations
from navigator_auth.backends.basic import BasicUser               # verified: backends/basic.py:35
from navigator_auth.backends.abstract import BaseAuthBackend      # verified: backends/abstract.py (class), get_session_user at :378
from navigator_auth.auth import AuthHandler                       # verified: auth.py, get_session_user at :757
from navigator_auth.decorators import allowed_organizations       # verified: decorators.py:663
from navigator_auth.exceptions import InvalidAuth                 # verified: exceptions.py:42
import navigator_session.data                                     # verified: registers jsonpickle ModelHandler for datamodel.BaseModel (data.py:36)
import jsonpickle                                                 # verified: 3.0.2 (transitive via navigator-session)
from aiohttp import web                                           # HTTPUnauthorized
from unittest.mock import AsyncMock, patch
```

### Verified Signatures
```python
# navigator_auth/backends/abstract.py
class BaseAuthBackend(ABC):
    _ident: Identity = Identity                                       # :75 — bare Identity has NO organizations -> guard with isinstance
    async def create_user(self, userdata) -> Identity:                # :176-181 — any Exception -> InvalidAuth("Unable to created Session User: ...") from err
    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:   # :378-387
        # :382  user = session.decode(name)
        # :384  user.is_authenticated = True
        # :386  except (AttributeError, RuntimeError) as ex:
        # :387  self.logger.warning(f"NAV: Unable to decode User session: {ex}")

# navigator_auth/auth.py
class AuthHandler:
    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:   # :757-765
        # :760  user = session.decode(name)   :762 is_authenticated   :764 except (AttributeError, RuntimeError) as ex:   :765 logging.warning(...)

# navigator_auth/decorators.py
def allowed_organizations(org: list, content_type: str = "application/json") -> Callable:   # :663-749
    # _wrap_function: :686 user = session.decode("user"); :687 for o in user.organizations:; :691 except (AttributeError, TypeError, RuntimeError):
    # _wrap_method:   :720 user = session.decode("user"); :721 for o in user.organizations:; :725 except (AttributeError, TypeError, RuntimeError):

# navigator_auth/version.py
__version__ = "0.28.6"  # pragma: no cover                          # :9

# navigator_session/data.py (site-packages 1.1.0)
SessionData.decode(key) -> jsonpickle.decode(self._data[key])        # :326-345; RuntimeError on decode failure, None on missing key
ModelHandler.restore -> mdl.__new__(mdl); cls.__dict__ = ...         # :30-34 — no __init__/__post_init__

# tests/unit/test_user_session_decorator.py
class FakeRequest: get/__getitem__/__setitem__, .method               # :10-25
class FakeSession: decode(key) -> user or raise RuntimeError          # :27-36
patch("navigator_auth.decorators.get_session", new_callable=AsyncMock, return_value=session)   # :40-45
patch("navigator_auth.decorators._attach_vault_to_request")           # :46
```

### Does NOT Exist (do not reference)
- Any `from .identities import ...` in `auth.py` today — you add the first one.
- A `__post_restore__` hook in navigator-session's `ModelHandler`.
- `AuthUser.normalize()` / `ensure_organizations()` — the names are
  `normalize_memberships()` and `normalize_organizations()` (TASK-99).
- `SessionData.encode_user` / `decode_user` — only generic `decode(key)`.
- A shared `get_session_user` — `abstract.py` and `auth.py` hold two copies; edit both.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: extend the `abstract.py` identities import — because the
   `isinstance` guard needs `AuthUser` (default `_ident` is bare `Identity`).
2. Block B: patch `BaseAuthBackend.get_session_user` — normalize before setting
   `is_authenticated`, and catch `ValueError` so a corrupt legacy payload is
   logged and yields `None` (fail closed → re-login).
3. Block C: `auth.py` — add the import next to the other package imports and
   apply the identical patch to `AuthHandler.get_session_user`.
4. Block D: `decorators.py` — both `allowed_organizations` wrappers; normalize
   right after decode, extend the except tuple. Keep the `TypeError` already
   there.
5. Block E: version bump.
6. Block F: create the test module; fill `FILL IN` bodies from spec §4.
7. Run `pytest tests/unit/test_session_user_rehydration.py tests/unit/test_user_session_decorator.py tests/test_allowed.py tests/test_basic_open_session.py -v`.

### Block A — `navigator_auth/backends/abstract.py` (import)
```python
# REPLACE — line `from ..identities import Identity, AuthBackend`
# occurrences: 1 (verified: grep -c 'from ..identities import Identity, AuthBackend' navigator_auth/backends/abstract.py)
from ..identities import Identity, AuthBackend, AuthUser
```
**Why**: no import cycle — `identities.py` imports only `slugify`/`datamodel`.

### Block B — `navigator_auth/backends/abstract.py` (`get_session_user`)
```python
# REPLACE — the method body starting at `async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:`
# occurrences: 1 (verified: grep -c 'async def get_session_user' navigator_auth/backends/abstract.py)
    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:
        """Rehydrate the user stored under *name* in *session*.

        Session payloads written before FEAT-102 may hold membership dicts;
        they are normalized here via ``normalize_memberships()``. A payload
        that cannot be normalized is treated like an undecodable session:
        a warning is logged and ``None`` is returned (fail closed).
        """
        try:
            user = None
            if session:
                user = session.decode(name)
                if user:
                    if isinstance(user, AuthUser):
                        user.normalize_memberships()
                    user.is_authenticated = True
            return user
        except (AttributeError, RuntimeError, ValueError) as ex:
            self.logger.warning(f"NAV: Unable to decode User session: {ex}")
```
**Why**: normalize before `is_authenticated` so a rejected payload never
marks the object authenticated; `ValueError` is what TASK-99 raises for bad
entries (TypeError cannot occur for list items coming from jsonpickle lists
of dicts/models, but a non-list `organizations` would raise `TypeError` from
iteration — leave that to the existing behaviour).

### Block C — `navigator_auth/auth.py`
```python
# AFTER — insert below `from .backends.idp import IdentityProvider`
# occurrences: 1 (verified: grep -c 'from .backends.idp import IdentityProvider' navigator_auth/auth.py)
from .identities import AuthUser
```
```python
# REPLACE — body of `async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:` in class AuthHandler
# occurrences: 1 (verified: grep -c 'async def get_session_user' navigator_auth/auth.py)
    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:
        """Rehydrate the session user; see ``BaseAuthBackend.get_session_user``."""
        try:
            if session:
                user = session.decode(name)
                if user:
                    if isinstance(user, AuthUser):
                        user.normalize_memberships()
                    user.is_authenticated = True
                return user
        except (AttributeError, RuntimeError, ValueError) as ex:
            logging.warning(f"NAV: Unable to decode User session: {ex}")
```
**Why**: the two copies must stay behaviourally identical (spec §7 notes the
duplication and forbids unifying them here); `auth.py` logs with the module
`logging`, keep that.

### Block D — `navigator_auth/decorators.py` (`allowed_organizations`, lines 663-749)
```python
# REPLACE — in BOTH wrappers of allowed_organizations (the only function containing
# `for o in user.organizations:`; occurrences of that line: 2 (verified: grep -c 'for o in user.organizations:' navigator_auth/decorators.py)).
# Replace this 7-line region in each of the two places:
#                user = session.decode("user")
#                for o in user.organizations:
#                    if o.organization in org:
#                        member = True
#                        break
#            except (AttributeError, TypeError, RuntimeError):
#                member = False
# with:
                user = session.decode("user")
                user.normalize_organizations()
                for o in user.organizations:
                    if o.organization in org:
                        member = True
                        break
            except (AttributeError, TypeError, RuntimeError, ValueError):
                member = False
```
**Why**: this decorator is the only in-repo reader of `.organizations`; a
legacy dict session must pass membership (AC7) and a malformed one must stay
a 401 (`member = False`). Do NOT touch the other `session.decode("user")`
sites (10 in the file).

### Block E — `navigator_auth/version.py`
```python
# REPLACE — line `__version__ = "0.28.6"  # pragma: no cover`
# occurrences: 1 (verified: grep -c '__version__ = ' navigator_auth/version.py)
__version__ = "0.28.7"  # pragma: no cover
```

### Block F — `tests/unit/test_session_user_rehydration.py` (CREATE)
```python
"""FEAT-102 / TASK-100 — legacy session rehydration (spec §4 round-trip table)."""
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jsonpickle
import pytest
from aiohttp import web

import navigator_session.data  # noqa: F401 — registers the jsonpickle ModelHandler
from navigator_auth.auth import AuthHandler
from navigator_auth.backends.abstract import BaseAuthBackend
from navigator_auth.backends.basic import BasicUser
from navigator_auth.decorators import allowed_organizations
from navigator_auth.exceptions import InvalidAuth
from navigator_auth.identities import Organization

ORG_DICT = {"org_id": "7", "organization": "Example", "slug": "example"}
BAD_ORG = {"organization": "x"}


def _legacy_payload(orgs: list) -> str:
    """jsonpickle string of a BasicUser whose organizations are raw dicts (pre-FEAT-102 session)."""
    user = BasicUser(id=1, data={"username": "legacy"})
    object.__setattr__(user, "organizations", [dict(o) for o in orgs])
    return jsonpickle.encode(user)


class FakeSession:
    """Mirror of tests/unit/test_user_session_decorator.py:27-36, backed by a jsonpickle payload."""

    def __init__(self, payload: str):
        self._payload = payload

    def decode(self, key):
        return jsonpickle.decode(self._payload)

    def get(self, key, default=None):
        return default


def _backend_stub():
    """Minimal `self` for unbound calls: only .logger and ._ident are used."""
    return SimpleNamespace(logger=logging.getLogger("test"), _ident=BasicUser)


def test_jsonpickle_roundtrip_keeps_attribute_access():
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT)])
    restored = jsonpickle.decode(jsonpickle.encode(user))
    assert isinstance(restored.organizations[0], Organization)
    assert restored.organizations[0].org_id == "7"                     # AC6


@pytest.mark.asyncio
@pytest.mark.parametrize("getter", [BaseAuthBackend.get_session_user, AuthHandler.get_session_user])
async def test_legacy_dict_session_payload_is_normalized(getter):
    # FILL IN: AC7 — session = FakeSession(_legacy_payload([ORG_DICT])); user = await getter(_backend_stub(), session)
    #          assert Organization elements and user.is_authenticated is True
    ...


@pytest.mark.asyncio
@pytest.mark.parametrize("getter", [BaseAuthBackend.get_session_user, AuthHandler.get_session_user])
async def test_legacy_malformed_session_payload_is_rejected(getter, caplog):
    # FILL IN: AC7/AC8 — payload with BAD_ORG -> result is None and caplog has "Unable to decode User session"
    ...


@pytest.mark.asyncio
async def test_allowed_organizations_accepts_legacy_dict_session():
    # FILL IN: AC7 — decorate `async def handler(request): return web.Response(text="ok")` with allowed_organizations(["Example"]);
    #          FakeRequest-like object with {"authenticated": True}, method "GET";
    #          patch navigator_auth.decorators.get_session (AsyncMock) -> FakeSession(legacy payload) => handler runs;
    #          FakeSession(_legacy_payload([BAD_ORG])) => pytest.raises(web.HTTPUnauthorized)
    ...


@pytest.mark.asyncio
async def test_create_user_rejects_malformed_organizations():
    # FILL IN: spec §2 item 3 — await BaseAuthBackend.create_user(_backend_stub(), {"organizations": [BAD_ORG]})
    #          raises InvalidAuth whose __cause__ is a ValueError
    ...
```
**Why**: no Redis — the real session codec is reproduced with `jsonpickle`
plus the `navigator_session.data` import that registers the datamodel
handler; unbound method calls with a stub `self` test both copies of
`get_session_user` without constructing a backend.

### FILL IN checklist
- [ ] Block F: bodies of the four `FILL IN` tests, bounded by the AC noted on each.
- [ ] Block D: apply to BOTH wrappers; verify with `grep -c 'user.normalize_organizations()' navigator_auth/decorators.py` → 2.

---

## Implementation Notes

### Key Constraints
- Do not alter which exceptions `create_user` wraps; the behaviour change is
  a consequence of TASK-99 and must be *tested*, not re-implemented.
- `pytest.mark.asyncio` is available (`pytest-asyncio` in `pyproject.toml:91`);
  `filterwarnings = error` — avoid un-awaited coroutine warnings.
- Keep `self.logger.warning` (abstract) vs `logging.warning` (auth) as they are.

### References in Codebase
- `navigator_auth/backends/abstract.py:290-312` — `remember()` writes the user with `save_encoded_data` (the write side of the round trip).
- `tests/unit/test_user_session_decorator.py` — fake request/session + patch pattern.

---

## Acceptance Criteria

- [ ] Implementation complete per scope.
- [ ] `pytest tests/unit/test_session_user_rehydration.py -v` passes.
- [ ] `pytest tests/unit/test_user_session_decorator.py tests/test_allowed.py tests/test_basic_auth.py tests/test_basic_open_session.py tests/test_auth_middleware_mechanism.py -v` still passes.
- [ ] `ruff check navigator_auth/backends/abstract.py navigator_auth/auth.py navigator_auth/decorators.py tests/unit/test_session_user_rehydration.py` clean.
- [ ] `grep -c "normalize_memberships()" navigator_auth/backends/abstract.py navigator_auth/auth.py` → 1 each; `grep -c "normalize_organizations()" navigator_auth/decorators.py` → 2.
- [ ] `navigator_auth/version.py` reads `0.28.7`.
- [ ] Spec AC6, AC7 and the `InvalidAuth` behaviour change each have a passing test.

---

## Test Specification

See Block F. Minimum passing set: the five test functions listed there (two parametrized ×2).

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/fix-organizations-orgid.spec.md` (§2 item 2–3, §3 M2, §4, §6, §7).
2. **Check dependencies** — TASK-99 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/fix-organizations-orgid.json` → `"in-progress"`.
4. **Implement** blocks A–F in order.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-100-session-rehydration-hooks.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback; parrot-sdd-coder unavailable: execution_not_found)
**Date**: 2026-10-12
**Notes**: Hooks in abstract.py/auth.py get_session_user and allowed_organizations; version 0.28.7; 69 related tests pass; ruff clean.

**Deviations from spec**: none
