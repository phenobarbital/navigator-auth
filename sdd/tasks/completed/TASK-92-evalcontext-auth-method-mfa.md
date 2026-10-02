# TASK-92: ABAC `EvalContext` — `auth_method` and `mfa` keys

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 6, §2.7, AC11, Q5)
**Status**: done
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Q5 asks for passkey logins to be visible to ABAC as first-class keys. Then a policy can require a
phishing-resistant login (`auth_method == "passkey"`, or `mfa == true`) without digging through
`userinfo`.

The session already carries both values: TASK-95 sets them, and `open_session` merges them into
`AUTH_SESSION_OBJECT`. This task only lifts them into the evaluation context.

---

## Scope

- In `EvalContext.__init__`, add `self.store['auth_method']` and `self.store['mfa']`, read from `userinfo`.
  - Use `.get` for a dict and `getattr` otherwise.
  - The defaults are `None` and `False`; `mfa` is coerced with `bool()`.
- Write `tests/test_eval_context_auth_method.py` (`test_eval_context_auth_method_mfa`).

**NOT in scope**: policy-language changes, and setting the values (TASK-95).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/context.py` | MODIFY | Two new store keys |
| `tests/test_eval_context_auth_method.py` | CREATE | Unit test |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Existing Signatures to Use
```python
# navigator_auth/abac/context.py
class EvalContext(dict, MutableMapping):                                        # :81
    def __init__(self, request, user, userinfo, session, *args,
                 org_id=None, client_id=None, **kwargs):                        # :87
        ...
        self.store['userinfo'] = userinfo                                       # :124
        if isinstance(userinfo, dict):
            self.store['userinfo_keys'] = list(userinfo.keys())
        else: ...                                                               # :125-131
        self.store['session'] = session                                         # :132  ← insert BELOW
        resolved_org, resolved_client = _resolve_tenant(request, userinfo, org_id, client_id)  # :135
        ...
        self._columns = list(self.store.keys())                                 # end of __init__
```
- `tests/conftest.py` provides `make_request()`, a MagicMock `web.Request` factory. Reuse it.
- `_columns` is computed from `store.keys()` at the end of `__init__`, so the new keys appear in it automatically.

### Does NOT Exist
- `store['auth_method']` and `store['mfa']` today.
- An `auth_method` attribute on `request`. Read it only from `userinfo`.

---

## Implementation Blueprint

### Steps (in order)
1. Insert the two keys right after `self.store['session'] = session`. This must happen before
   `_columns` is computed, so policies can address them.
2. Write the test with dict `userinfo`, object `userinfo` and `None` `userinfo`.

### `navigator_auth/abac/context.py` — MODIFY
```python
# AFTER — insert below `self.store['session'] = session`
#   (verified: abac/context.py:132; occurrences: 1 (verified: grep -cF))
        # FEAT-101 (Q5): first-class login-method keys for policies.
        if isinstance(userinfo, dict):
            self.store['auth_method'] = userinfo.get('auth_method')
            self.store['mfa'] = bool(userinfo.get('mfa', False))
        else:
            self.store['auth_method'] = getattr(userinfo, 'auth_method', None)
            self.store['mfa'] = bool(getattr(userinfo, 'mfa', False))
```
**Why**: Using the same dict/object branching as the `userinfo_keys` block above keeps the context
tolerant of every `userinfo` shape it gets today, including `None`.

### `tests/test_eval_context_auth_method.py` — CREATE
```python
"""FEAT-101 TASK-92 — EvalContext exposes auth_method and mfa."""
from types import SimpleNamespace

from navigator_auth.abac.context import EvalContext


def test_eval_context_auth_method_mfa(make_request):
    """Keys present; defaults None/False; values from dict and object userinfo."""
    # FILL IN: three EvalContext(...) constructions (dict with passkey/mfa True, object, None);
    #          assert ctx['auth_method'] / ctx['mfa'] for each.
```

### FILL IN checklist
- [ ] Test body with the three `userinfo` shapes.

---

## Acceptance Criteria

- [ ] AC11: `EvalContext` exposes `auth_method` and `mfa`.
- [ ] `pytest tests/test_eval_context_auth_method.py tests/test_tenant_scoping.py tests/test_policy_evaluation.py -v` passes. The existing ABAC tests must not regress.
- [ ] `ruff check navigator_auth/abac/context.py tests/test_eval_context_auth_method.py` shows no new findings.

---

## Test Specification

See the blueprint above (spec §4: `test_eval_context_auth_method_mfa`).

---

## Agent Instructions

1. Read the spec (Module 6, §2.7).
2. This task has no task dependencies. It runs in parallel with TASK-91 after stage S0.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Sonnet 5.5, sequential fallback)
**Date**: 2026-10-02
**Notes**: Keys added to EvalContext.store; test reads via ctx.store (dict __getitem__ is not store-backed). 31 ABAC tests pass.
**Deviations from spec**: none
