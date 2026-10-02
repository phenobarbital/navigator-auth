# TASK-89: `RelyingPartyResolver` — exact-origin RP allow-list

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 3, §2.1, §7 R6/R7, AC4)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-87
**Assigned-to**: unassigned

---

## Context

Part of serial stage S0. Every ceremony resolves its relying party from the request's `Origin`
header against `PASSKEY_RELYING_PARTIES` (G2, E3). The service runs behind an ALB, so the
resolver must **never** read `Host`, `request.url` or `X-Forwarded-*` (R7).

---

## Scope

- Implement `navigator_auth/passkey/rp.py` with `RelyingPartyResolver(parties)`, `.resolve(request)` and `.by_rp_id(rp_id)`.
- Build it from a list of dicts, validating each entry into `RelyingParty`.
  - An empty map raises `ConfigError`.
  - Invalid entries raise `ConfigError` naming the bad index.
  - Duplicate origins raise `ConfigError`.
- Normalise configured origins: lowercase the scheme and host, and strip a trailing `/`.
  Compare against the request `Origin` exactly after the same normalisation.
- R6 fallback: when `Origin` is absent, use the `Referer`'s origin, but only if it is an exact
  allow-list match. The literal `null` origin is always rejected.
- On a miss, raise `InvalidAuth("Passkey: origin not allowed", status=401)`.
- Export it from `navigator_auth/passkey/__init__.py`.
- Write `tests/test_passkey_rp.py`.

**NOT in scope**: using the resolver in handlers (TASK-93 and later).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/passkey/rp.py` | CREATE | Resolver |
| `navigator_auth/passkey/__init__.py` | MODIFY | Export `RelyingPartyResolver` |
| `tests/test_passkey_rp.py` | CREATE | Unit tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
from aiohttp import web
from pydantic import ValidationError                           # pydantic v2
from navigator_auth.exceptions import ConfigError, InvalidAuth  # exceptions.py:26, :42
from navigator_auth.passkey.types import RelyingParty           # TASK-87
from urllib.parse import urlsplit
```

### Existing Signatures to Use
```python
class ConfigError(AuthException):
    def __init__(self, message: str = None, status=500)        # exceptions.py:26-29
class InvalidAuth(AuthException):
    def __init__(self, message: str = None, status=401)        # exceptions.py:42-45
```
- Unit tests can build requests with `aiohttp.test_utils.make_mocked_request("POST", "/", headers={...})`.

### Does NOT Exist
- `_resolve_tenant` (`abac/context.py:28`) cannot be reused here. It runs after authentication,
  and the RP must be known before it.
- No helper in the repo derives the origin from a request. Do not build one from `request.host`.

---

## Implementation Blueprint

### Steps (in order)
1. Write `_normalise_origin(value) -> Optional[str]`. It returns `scheme://host[:port]`
   lowercased, and `None` for empty input, `"null"`, or a value with a path, query or userinfo.
   Rejecting those prevents prefix tricks such as `https://a.test.evil.com` or
   `https://a.test/../`.
2. In the constructor, validate and index the entries by normalised origin and by `rp_id`. Fail
   fast with `ConfigError`, because a bad map is a deployment error, not a request error.
3. `resolve()` reads `Origin`, then the `Referer` fallback, and raises a uniform 401 on any miss.
4. Write the tests.

### `navigator_auth/passkey/rp.py` — CREATE
```python
"""Origin → relying-party resolution for passkey ceremonies (FEAT-101)."""
from typing import Optional
from urllib.parse import urlsplit

from aiohttp import web
from pydantic import ValidationError

from ..exceptions import ConfigError, InvalidAuth
from .types import RelyingParty


def _normalise_origin(value: Optional[str]) -> Optional[str]:
    """Return ``scheme://host[:port]`` lowercased, or ``None`` if not a bare origin."""
    # FILL IN: reject None/""/"null"; urlsplit; require scheme in {"https","http"} and netloc;
    #          reject userinfo; for an ORIGIN header reject any path/query/fragment;
    #          bounded by: test_rp_resolver_exact_origin (no prefix/suffix matches).
    raise NotImplementedError


class RelyingPartyResolver:
    """Exact-match ``Origin`` → ``RelyingParty`` allow-list. Never reads Host / X-Forwarded-*."""

    def __init__(self, parties: list[dict]) -> None:
        """Validate entries into ``RelyingParty``.

        Raises:
            ConfigError: When the map is empty, an entry is invalid, or an origin repeats.
        """
        if not parties:
            raise ConfigError("PasskeyAuth: PASSKEY_RELYING_PARTIES is empty.")
        self._by_origin: dict[str, RelyingParty] = {}
        self._by_rp_id: dict[str, RelyingParty] = {}
        # FILL IN: for idx, entry: RelyingParty.model_validate(entry) (ValidationError →
        #          ConfigError naming idx); normalise origin (None → ConfigError); duplicates →
        #          ConfigError; store the normalised origin back on the model.

    def resolve(self, request: web.Request) -> RelyingParty:
        """Return the RP for the request's ``Origin`` (``Referer`` origin as exact fallback).

        Raises:
            InvalidAuth: 401 when the origin is absent, ``null`` or not allow-listed.
        """
        # FILL IN: Origin header first; if absent, the origin part of Referer (scheme+netloc
        #          only); look up _by_origin; miss → InvalidAuth("Passkey: origin not allowed", status=401).
        raise NotImplementedError

    def by_rp_id(self, rp_id: str) -> Optional[RelyingParty]:
        """Return the RP configured for ``rp_id``, or ``None``."""
        return self._by_rp_id.get(rp_id)
```
**Why**: An exact match on a config-sourced origin is the whole E3 defence. Everything else in the
request is attacker-influenced, or rewritten by the ALB.

### `navigator_auth/passkey/__init__.py` — MODIFY
```python
# AFTER — insert below the `from .types import ...` line (occurrences: 1)
from .rp import RelyingPartyResolver
# and add "RelyingPartyResolver" to __all__
```
If TASK-88 merges first, its `from .store import PasskeyStore` line is also there. Keep both.

### `tests/test_passkey_rp.py` — CREATE
```python
"""FEAT-101 TASK-89 — RelyingPartyResolver."""
import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import ConfigError, InvalidAuth
from navigator_auth.passkey.rp import RelyingPartyResolver

PARTIES = [
    {"origin": "https://a.test", "rp_id": "a.test", "rp_name": "A", "org_id": 5, "client_id": 1},
    {"origin": "https://b.test", "rp_id": "b.test", "rp_name": "B", "org_id": 7, "client_id": 2},
]


def test_rp_resolver_exact_origin():
    """Known Origin → its RP; unknown/missing/null → 401; Host and X-Forwarded-Host ignored."""
    # FILL IN: include https://a.test.evil.com, https://A.TEST (matches), "null", Host-only,
    #          and Referer fallback cases.


def test_rp_resolver_empty_config():
    with pytest.raises(ConfigError):
        RelyingPartyResolver([])
```

### FILL IN checklist
- [ ] `_normalise_origin` rules.
- [ ] Constructor validation and duplicate detection.
- [ ] `resolve` with the `Referer` fallback.
- [ ] Full test cases.

---

## Acceptance Criteria

- [ ] `test_rp_resolver_exact_origin` and `test_rp_resolver_empty_config` pass (AC4, resolver part).
- [ ] No code path reads `request.host`, `request.url` or `X-Forwarded-*` (grep the file).
- [ ] `ruff check navigator_auth/passkey/rp.py tests/test_passkey_rp.py` is clean.

---

## Test Specification

See the blueprint above (spec §4: `test_rp_resolver_exact_origin`, `test_rp_resolver_empty_config`).

---

## Agent Instructions

1. Read the spec (Module 3, §2.1, R6, R7).
2. Confirm TASK-87 is in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
