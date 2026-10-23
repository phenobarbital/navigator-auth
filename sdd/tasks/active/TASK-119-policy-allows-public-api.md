# TASK-119: Public fail-closed ABAC evaluation API — `policy_allows()`

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 2**. The guard built in TASK-122 must take an
ABAC decision *in the middle of a request*, because the decision depends on
data that is only known after a row has been fetched (who owns it). The
existing `check_access` decorator cannot do that — it decides before the
handler body runs — and its engine, `_check_policies`, is private.

This task exposes `policy_allows()`: a thin, documented, public wrapper over
the same fail-closed `_check_policies` that `check_access` uses, so the guard
never imports a private symbol and the two paths can never drift in their
deny semantics.

**Why a wrapper rather than making the guard call `_check_policies`
directly.** `_check_policies` takes six positional arguments with no
defaults and its signature is internal. A handler calling it would pin the
feature to an implementation detail; worse, a future refactor of
`_check_policies` would silently change the security behaviour of three
endpoints with no public contract to test against. The wrapper is the
contract — spec §2 New Public Interfaces fixes its signature.

**Why it must fail closed, loudly.** `_check_policies` already returns
`False` when there is no PDP, when the named policy is not declared, and
when evaluation raises (verified below). `policy_allows()` must add nothing
that could turn any of those into an allow, and must preserve the `reason`
string so the guard can audit *why* a cross-user attempt was refused.

> **Environment drift (read this).** The spec's §6 upstream `navigator` table
> was recorded against `navigator-api` 3.2.2; `.venv` actually has **4.0.1**.
> That affects the handler tasks, not this one — this task touches only
> `navigator_auth/decorators.py`, whose anchors below were re-verified today.

---

## Scope

- Add one public coroutine, `policy_allows()`, to
  `navigator_auth/decorators.py`, placed immediately after `_check_policies`
  and before `check_access`.
- Add `tests/test_policy_allows.py` covering the four Module-2 cases from
  spec §4.

**NOT in scope**:
- Any change to `_check_policies`, `_get_pdp`, `_find_policy`,
  `_policy_allows`, `_abac_eval_context`, `_evaluate_policy` or
  `check_access`. This task is purely additive — existing behaviour must be
  byte-for-byte unchanged.
- Calling `policy_allows()` from anywhere. TASK-122 wires it into the guard;
  this task must not touch `navigator_auth/handlers/`.
- Any ABAC policy file. TASK-120 ships the policy pack.
- Renaming the pre-existing private helper `_policy_allows(effect)`
  (`decorators.py:1031`). It is a **different function** with a different job
  — see the name-collision note below.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/decorators.py` | MODIFY | Add the public `policy_allows()` coroutine |
| `tests/test_policy_allows.py` | CREATE | Unit tests for the four fail-closed cases |

---

## Codebase Contract

> Every fact below was re-verified on `dev` @ `62fd419` (2026-10-23).

### CRITICAL — name collision with an existing private helper

`navigator_auth/decorators.py:1031` **already defines**:

```python
def _policy_allows(effect: Any) -> bool:
    """Normalize a PolicyResponse effect (enum, str or bool) into a boolean."""
```

The new public function is `policy_allows` (no leading underscore) and is an
`async def` returning a 3-tuple. They are unrelated. Do not rename, replace,
merge or shadow `_policy_allows` — `_check_policies` calls it at
`decorators.py:1159` and the whole ABAC decision depends on it.

### `_check_policies` — the function being wrapped (verified: `decorators.py:1103-1168`)

```python
async def _check_policies(
    request: web.Request,
    names: list,
    action: str,
    resource: str,
    resource_type: Any,
    require_all: bool,
) -> tuple:
    """Evaluate the named policies for the current request.

    Returns:
        Tuple ``(allowed, reason, response)`` where ``response`` is the last
        ``PolicyResponse`` produced (or None when nothing could be evaluated).
    """
```

All six parameters are **positional with no defaults**. Its three verified
fail-closed exits:

| Condition | Verified line | Returns |
|---|---|---|
| `_get_pdp(request)` is `None` | `:1119-1122` | `(False, "ABAC is not enabled on this Application.", None)` |
| `_find_policy(pdp, name)` is `None` | `:1140-1147` | denies; appends `"Policy '<name>' is not declared on ABAC."` |
| `_evaluate_policy(...)` raises | `:1149-1155` | catches bare `Exception`, appends `"Policy '<name>' failed to evaluate."`, continues/denies |
| nothing allowed | `:1167-1168` | `(False, "; ".join(reasons) or "Access Denied", last_response)` |

### How `check_access` normalizes its `policy` argument (verified: `decorators.py:1226-1228`)

```python
    names = [policy] if isinstance(policy, str) else list(policy)
    if not names:
        raise ValueError("check_access requires at least one ABAC Policy name.")
```

`policy_allows()` must normalize **identically**, so a `str` and a
one-element `list` behave the same in both entry points.

### Other verified anchors in `decorators.py`

| Symbol | Line | Fact |
|---|---|---|
| module imports | `:1-12` | `from typing import Any, Optional, TypeVar, Union`; `from aiohttp import web, hdrs`; `from navconfig.logging import logger` — every symbol `policy_allows` needs is **already imported**; add no import |
| `_get_pdp` | `:994` | `request.app.get("abac")`, else `getattr(request.app.get("security"), "pdp", None)` |
| `_find_policy` | `:1003` | indexed lookup via `pdp._evaluator._index.get_by_name(name)`, then linear scan of `pdp.policies` |
| `_policy_allows` | `:1031` | the private effect-normalizer described above — **not** this task's function |
| `_abac_eval_context` | `:1044` | builds the `EvalContext`; swallows a missing session (`RuntimeError` → `session = None`) |
| `check_access` | `:1170` | `(policy, action=None, resource=None, resource_type=None, require_all=False, content_type="application/json")`; docstring states "the check always fails closed" |
| `_check_policies` call site | `:1250-1257` | `check_access` passes `(request, names, action, resource, resource_type, require_all)` positionally |
| module length | 1272 lines | `policy_allows` is inserted at line 1169, between `_check_policies` and `check_access` |
| `__all__` | — | **there is none** (`grep -c '__all__' navigator_auth/decorators.py` → `0`). A module-level `def` is therefore importable with no export bookkeeping; do **not** introduce an `__all__` |

### The signature fixed by spec §2 (not renegotiable)

```python
async def policy_allows(
    policy: Union[str, list],
    request: web.Request,
    action: str = None,
    resource: str = None,
    resource_type: Any = None,
    require_all: bool = False,
) -> tuple[bool, str, Any]:
```

Note the argument order: `policy` **first**, `request` second — deliberately
mirroring `check_access(policy, ...)` rather than `_check_policies(request,
names, ...)`.

### Existing test pattern to follow (verified: `tests/test_check_access.py:1-93`)

```python
pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)


class FakePDP:
    """Minimal PDP stub exposing the ``policies`` collection."""

    def __init__(self, policies):
        self._evaluator = None
        self._policies = policies

    @property
    def policies(self):
        return self._policies


def _make_request(method="GET", authenticated=True, pdp=None, path="/articles"):
    app = web.Application()
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request(method, path, app=app)
    request["authenticated"] = authenticated
    return request


def _session(groups: list, username: str = "editor@example.com"):
    userinfo = {"username": username, "groups": groups, "email": username}
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value=userinfo)
    session.decode = MagicMock(return_value=None)
    return session


def _patch_session(session):
    return patch(
        "navigator_auth.decorators.get_session",
        new=AsyncMock(return_value=session),
    )
```

`Policy` and `PolicyEffect` come `from navigator_auth.abac.policies`
(verified: `tests/test_check_access.py:11`), and a `Policy` is built as
`Policy(name, description=..., effect=PolicyEffect.ALLOW, actions=[...],
groups=[...], priority=N)` (verified: `tests/test_check_access.py:22-46`).

### Does NOT Exist (do not reference)

- `navigator_auth.decorators.policy_allows` — **this task creates it**. Today
  only the private `_check_policies` and the unrelated private
  `_policy_allows(effect)` exist.
- `navigator_auth.decorators.check_policies` (no underscore) — no such
  public alias. Do not create one as well; `policy_allows` is the single
  public entry point this feature adds.
- `tests/test_policy_allows.py` — this task creates it. Do not append these
  cases to `tests/test_check_access.py`; that file covers the decorator and
  must stay green unmodified.
- A PDP method that evaluates one named policy for a request. `PDP.authorize`
  (`navigator_auth/abac/pdp.py`) evaluates *all* policies and writes an audit
  record of its own; `_check_policies` is the by-name path and the one to
  wrap.
- `request.app["pdp"]` — the PDP lives at `request.app["abac"]`, or at
  `request.app["security"].pdp`. `_get_pdp` already handles both; do not
  re-implement the lookup.
- An `EvalContext` key carrying row ownership. `EvalContext.__init__`
  (`navigator_auth/abac/context.py:89`) stores `user`, `userinfo`, `session`,
  `auth_method`, `mfa`, `org_id`, `client_id` and nothing else, and
  `ResourcePolicy.evaluate_conditions` **passes** on a missing attribute
  (`resource_policy.py:119-150`: `if actual is None: continue`). Ownership is
  decided in code by the guard, never by the policy — do not try to pass an
  owner through this function.

---

## Implementation Blueprint

### `navigator_auth/handlers/` — untouched

This task adds no handler code. Stated explicitly because the function being
added exists only to serve the handlers.

### `navigator_auth/decorators.py` — MODIFY

```python
# AFTER — insert between the end of `_check_policies` and `def check_access(`
# anchor (verified: navigator_auth/decorators.py:1170)
# occurrences: 1 (verified: grep -cF 'def check_access(' navigator_auth/decorators.py)
# The preceding line 1168 is `    return False, "; ".join(reasons) or "Access Denied", last_response`
# and line 1170 is `def check_access(`. Insert the new function between them,
# separated by two blank lines on each side.


async def policy_allows(
    policy: Union[str, list],
    request: web.Request,
    action: str = None,
    resource: str = None,
    resource_type: Any = None,
    require_all: bool = False,
) -> tuple[bool, str, Any]:
    """Evaluate ABAC policies for a request outside a decorator.

    Public, documented wrapper over the fail-closed :func:`_check_policies`
    used by :func:`check_access`, for handlers whose decision depends on data
    known only at request time (e.g. the owner of a row, which is unknown
    until the row has been fetched).

    Like :func:`check_access`, the evaluation **always fails closed**: it
    denies when ABAC is not enabled on the Application, when a named policy
    is not declared on the PDP, and when a policy raises while evaluating.
    A missing policy can therefore only ever remove access, never grant it.

    Args:
        policy: Name of the ABAC Policy, or a list of names. With a list,
            access is granted when **any** of them allows it, unless
            ``require_all`` is True.
        request: The live request whose session and path are evaluated.
        action: Optional action (e.g. ``"identity:read"``) the policy must
            cover for access to be granted.
        resource: Optional resource name the policy must cover (the resource
            type defaults to ``ResourceType.URI`` when none is given).
        resource_type: Optional ``ResourceType`` (or its string value) used
            together with ``resource``.
        require_all: Require every named policy to allow access.

    Returns:
        ``(allowed, reason, response)`` — ``response`` is the last
        ``PolicyResponse`` produced, or ``None`` when nothing was evaluated.
        ``reason`` is always a non-empty string, suitable for an audit
        record. ``allowed`` is ``False`` when ABAC is absent, the policy is
        not declared, or evaluation raised.

    Raises:
        ValueError: ``policy`` resolved to an empty list of names.
    """
    # FILL IN: normalize `policy` to `names` exactly as check_access does at
    # decorators.py:1226-1228 (str -> [policy], else list(policy); raise
    # ValueError on empty), then return await _check_policies(request, names,
    # action, resource, resource_type, require_all) — all six positional.
    # Bounded by AC-1, AC-2, AC-6.
```

**Why `policy` comes before `request`.** Callers of this function are
handlers that already hold `self.request`; they read as
`await policy_allows(self.policy_name, self.request, action=...)`. Matching
`check_access(policy, ...)` keeps one mental model for "which policy" being
the first thing you say, and makes the two call sites greppable together.

**Why it must `await _check_policies` rather than re-implement the loop.**
The three fail-closed exits are the security property. Duplicating the loop
duplicates the places that have to stay closed, and the day someone fixes a
bug in one copy the other keeps the bug. Delegate, add nothing.

**Why no `try/except` around the delegation.** `_check_policies` already
catches a bare `Exception` per policy (`:1149`) and converts it into a deny
with a reason. Wrapping the call in another handler would either swallow the
`ValueError` this function is documented to raise on an empty policy list, or
convert a programming error into a silent deny that is impossible to debug.
Let the two documented outcomes through unchanged.

**Why the `reason` must be returned and not discarded.** Spec **G6** requires
every cross-user decision to produce an `AuditLog` record naming the policy
rule. `reason` is the only human-readable explanation `_check_policies`
produces for the deny paths where `response` is `None` (no PDP, policy not
declared), so dropping it would make exactly the interesting denials
unauditable.

**Where to insert it, and why there.** Immediately after `_check_policies`
and before `check_access`: the wrapper belongs next to the thing it wraps,
and both public entry points then sit together at the end of the module.
Appending it at EOF (after `check_access`) also works mechanically — but do
not, because the diff then reads as "unrelated function bolted on" instead
of "public face of the function above".

### `tests/test_policy_allows.py` — CREATE

```python
"""Tests for the public ``policy_allows()`` ABAC evaluation API (FEAT-105).

Covers the four fail-closed cases from spec §4: no PDP, a PDP without the
named policy, a policy that raises while evaluating, and the one allow path
(a ``superuser``-group subject).
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.decorators import policy_allows
from navigator_auth.abac.policies import Policy, PolicyEffect

# Same rationale as tests/test_check_access.py:14-19 — navigator-auth stores
# state under plain string keys, which aiohttp only warns about, and this
# project turns warnings into errors.
pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)


class FakePDP:
    """Minimal PDP stub exposing the ``policies`` collection."""

    def __init__(self, policies):
        self._evaluator = None
        self._policies = policies

    @property
    def policies(self):
        return self._policies


class ExplodingPolicy:
    """A policy whose evaluation raises, to prove nothing escapes."""

    name = "user_identities_admin_access"

    def evaluate(self, ctx, env):
        raise RuntimeError("policy backend is down")

    def is_allowed(self, ctx, env, **kwargs):
        raise RuntimeError("policy backend is down")


def _make_request(pdp=None, path="/api/v1/user_identity/1"):
    # FILL IN: mirror tests/test_check_access.py:60-73 — build a
    # web.Application, set app["abac"] = pdp when pdp is not None, make the
    # mocked request, set request["authenticated"] = True.


def _session(groups: list, username: str = "admin@example.com"):
    # FILL IN: mirror tests/test_check_access.py:76-82 — a MagicMock whose
    # __getitem__ returns the userinfo dict and whose decode() returns None.


def _patch_session(session):
    return patch(
        "navigator_auth.decorators.get_session",
        new=AsyncMock(return_value=session),
    )


@pytest.mark.asyncio
async def test_policy_allows_denies_without_pdp():
    """No `abac` and no `security` on the app => (False, reason, None)."""
    # FILL IN: request built with pdp=None; assert allowed is False, reason
    # is a non-empty str and response is None — bounded by AC-3.


@pytest.mark.asyncio
async def test_policy_allows_denies_undeclared_policy():
    """PDP present but the named policy absent => denied, fail-closed."""
    # FILL IN: FakePDP([]) (or a PDP holding an unrelated policy); assert
    # allowed is False and the reason names the policy — bounded by AC-4.


@pytest.mark.asyncio
async def test_policy_allows_denies_on_evaluation_error():
    """A policy whose evaluation raises => denied, nothing propagates."""
    # FILL IN: FakePDP([ExplodingPolicy()]); assert allowed is False and that
    # no RuntimeError escapes the call — bounded by AC-5.


@pytest.mark.asyncio
async def test_policy_allows_grants_for_superuser_group():
    """A matching policy plus groups=["superuser"] => (True, reason, resp)."""
    # FILL IN: build a Policy named "user_identities_admin_access" with
    # effect=PolicyEffect.ALLOW, actions=["identity:read"],
    # groups=["superuser"]; pass action="identity:read"; assert allowed is
    # True — bounded by AC-6.


@pytest.mark.asyncio
async def test_policy_allows_accepts_str_and_list_identically():
    """"name" and ["name"] take the same decision."""
    # FILL IN: call twice against the same PDP, once with the str and once
    # with the one-element list; assert the `allowed` values agree — AC-2.


@pytest.mark.asyncio
async def test_policy_allows_rejects_empty_policy_list():
    """An empty list is a programming error, not a silent deny."""
    # FILL IN: pytest.raises(ValueError) around policy_allows([], request)
    # — bounded by AC-2.
```

**Why `test_policy_allows_rejects_empty_policy_list` matters.** Every other
deny path returns `False`. An empty policy list is different in kind: it
means the *caller* is misconfigured (a handler with `policy_name = None`
would produce it). Returning `False` there would look like a correct
fail-closed deny while hiding a handler that can never grant superuser
access at all — so it must raise, loudly, exactly as `check_access` does.

**Why `ExplodingPolicy` defines both `evaluate` and `is_allowed`.**
`_evaluate_policy` (`decorators.py:1071-1101`) routes to one or the other
depending on whether the policy has `covers_resource`, and on whether an
action/resource was passed. Implementing only one would let the test pass for
the wrong reason — through a route that never reaches the raise.

### Steps (in order)

1. Open `navigator_auth/decorators.py` and locate line 1170, `def check_access(`.
2. Insert `policy_allows` immediately above it, blueprint verbatim, then fill
   the single body stub. Add **no imports** — `Union`, `Any` and `web` are
   already imported at `:1-6`.
3. Confirm you have not touched `_policy_allows` (`:1031`) or anything else:
   `git diff navigator_auth/decorators.py` must show one added block and zero
   removed lines.
4. Create `tests/test_policy_allows.py` and fill the two helper bodies plus
   the six test bodies.
5. Run `pytest tests/test_policy_allows.py -v`, then the regression gate
   `pytest tests/test_check_access.py tests/test_check_superuser.py -q` —
   both must be green and unmodified.
6. `ruff check navigator_auth/decorators.py tests/test_policy_allows.py`.

### FILL IN checklist

- [ ] `policy_allows` body: normalize names, raise on empty, delegate — AC-1, AC-2, AC-6
- [ ] `_make_request` helper — mirrors `test_check_access.py:60-73`
- [ ] `_session` helper — mirrors `test_check_access.py:76-82`
- [ ] `test_policy_allows_denies_without_pdp` — AC-3
- [ ] `test_policy_allows_denies_undeclared_policy` — AC-4
- [ ] `test_policy_allows_denies_on_evaluation_error` — AC-5
- [ ] `test_policy_allows_grants_for_superuser_group` — AC-6
- [ ] `test_policy_allows_accepts_str_and_list_identically` — AC-2
- [ ] `test_policy_allows_rejects_empty_policy_list` — AC-2

---

## Acceptance Criteria

- [ ] **AC-1** `from navigator_auth.decorators import policy_allows` resolves, and the signature matches spec §2 exactly: `(policy, request, action=None, resource=None, resource_type=None, require_all=False)`.
- [ ] **AC-2** A `str` policy and a one-element `list` produce the same decision; an empty list raises `ValueError`.
- [ ] **AC-3** With neither `app["abac"]` nor `app["security"].pdp`, the call returns `allowed is False`, a non-empty `reason`, and `response is None`.
- [ ] **AC-4** With a PDP that does not declare the named policy, the call denies and the reason names the policy.
- [ ] **AC-5** A policy that raises during evaluation yields a deny; no exception propagates to the caller.
- [ ] **AC-6** A declared ALLOW policy covering the requested action, with the session in group `superuser`, yields `allowed is True` and a non-`None` `PolicyResponse`.
- [ ] **AC-7** `_check_policies`, `_policy_allows`, `_get_pdp`, `_find_policy`, `_abac_eval_context`, `_evaluate_policy` and `check_access` are unmodified — the diff on `decorators.py` adds lines only.
- [ ] **AC-8** `pytest tests/test_policy_allows.py tests/test_check_access.py tests/test_check_superuser.py -q` passes.
- [ ] **AC-9** `ruff check navigator_auth/decorators.py tests/test_policy_allows.py` is clean.
- [ ] **AC-10** Nothing under `navigator_auth/handlers/` is modified.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_policy_allows.py -v
pytest tests/test_check_access.py tests/test_check_superuser.py -q   # regression
ruff check navigator_auth/decorators.py tests/test_policy_allows.py
```

```python
from navigator_auth.decorators import policy_allows
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §2 Overview layer 2, §2 New Public Interfaces, §3 Module 2, §4 the four
   `test_policy_allows_*` rows.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. Additive only.
5. **Verify** every acceptance criterion, AC-7 and AC-10 included.
6. **Move this file** to `sdd/tasks/completed/TASK-119-policy-allows-public-api.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
