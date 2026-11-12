# TASK-190: PDP registration of programmatic policies (`add_policy` enforced)

**Feature**: FEAT-109 — PBAC example policy issues
**Spec**: `sdd/specs/policy-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-189
**Assigned-to**: unassigned

---

## Context

This is the actual 428 fix (spec §1 problem 1, §3 **Module 2**). Today `PDP.add_policy()` and
`PDP(policies=[...])` only append to `self._policies`, which `PDP.authorize` never reads — it asks
only `self._evaluator`. After this task a registered policy is adapted with
`PolicyAdapter.from_policy` (TASK-189), loaded into the evaluator, kept across
`reload_policies()` and per-tenant evaluators, and the startup guard in `_load_policies` ignores
registered policies when deciding whether the evaluator was pre-loaded externally.

`add_policy` fails loudly: an unadaptable policy or a repeated registered name raises `ValueError`
and changes nothing (registries, evaluator index/JSON, decision cache, tenant LRU).

---

## Scope

- Add `self._registered: list[ResourcePolicy]`; stop aliasing the caller's `policies` list; register
  each constructor policy through `add_policy` at the **end** of `__init__`.
- Replace `add_policy` (pdp.py:104-106) with the enforced version returning the loaded
  `ResourcePolicy` list; add `_has_external_policies()`.
- Change the `_load_policies` guard (pdp.py:116) to `if self._has_external_policies():`.
- Include `self._registered` in `_build_tenant_evaluator` (before `ev.load_policies`, pdp.py:226)
  and in `reload_policies` (before the new index is built, pdp.py:300-301).
- Write `tests/test_pdp_add_policy.py` (13 M2 tests from spec §4).

**NOT in scope**: `PDP.authorize` (unchanged — a genuine no-match still raises the 428);
`find_deny_policy` (pdp.py:61, no caller — do not wire it in); the adapter itself (TASK-189);
the example (TASK-193); detecting a registered name that collides with a storage/YAML policy
loaded later (existing behaviour, spec §7).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | `_registered`, enforced `add_policy`, guard, reload + tenant include registered |
| `tests/test_pdp_add_policy.py` | CREATE | M2 unit tests (spec §4) |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` HEAD `c5403d4` on 2026-11-11. All spec §6 pdp.py anchors re-checked: counts match.

### Verified Imports
```python
# pdp.py new imports — relative, matching pdp.py:13-20 style
from .policies.abstract import AbstractPolicy                 # verified: abac/policies/abstract.py:42
from .policies.resource_policy import ResourcePolicy          # verified: abac/policies/resource_policy.py:7
# already imported in pdp.py (do not re-add)
from .policies.adapter import PolicyAdapter                   # verified: pdp.py:18
from .policies.evaluator import PolicyEvaluator, PolicyIndex  # verified: pdp.py:19
# tests
from aiohttp import web
from aiohttp.test_utils import make_mocked_request             # verified: tests/test_check_access.py:10
from navigator_auth.abac.pdp import PDP                         # verified: abac/pdp.py:69
from navigator_auth.abac.policies import Policy, PolicyEffect, ObjectPolicy  # verified: abac/policies/__init__.py:6-8
from navigator_auth.abac.policies.resource_policy import ResourcePolicy      # verified: resource_policy.py:7
from navigator_auth.abac.policies.resources import ResourceType              # verified: resources.py (ResourceType.URI = "uri")
from navigator_auth.conf import AUTH_SESSION_OBJECT                          # verified: abac/pdp.py:8
```

### Existing Signatures to Use
```python
# navigator_auth/abac/pdp.py
class PDP:                                                       # line 69
    def __init__(self, storage, policies=None, yaml_storage=None, evaluator=None):  # lines 72-78
        self._policies: list = []                                # line 79; 80-81 alias `policies` (remove)
        self._evaluator: PolicyEvaluator                         # lines 87-89
        self._tenant_evaluators: OrderedDict[...] = OrderedDict()  # lines 93-95 (end of __init__)
    def add_policy(self, policy: Policy): ...                    # lines 104-106 (append + sort only)
    def sorted_policies(self): ...                               # line 108 (sort by .priority)
    async def _load_policies(self): ...                          # 111-141; guard `if self._evaluator._index.all():` at 116
    async def _build_tenant_evaluator(self, org_id, client_id) -> PolicyEvaluator: ...  # 197-231; `ev.load_policies(resource_policies)` at 226
    def _invalidate_tenant_evaluators(self) -> int: ...          # line 233
    async def reload_policies(self) -> int: ...                  # 274-320; `# Build new index` 300, `new_index = PolicyIndex()` 301
    async def authorize(self, request, session=None, user=None, effect=PolicyEffect.ALLOW): ...  # 397-448
        # userinfo = session[AUTH_SESSION_OBJECT]; evaluator.check_access(ctx, ResourceType.URI, request.path, action, ...)
        # not allowed + no matched policy -> raise PreconditionFailed(...)  (444)
    async def auditlog(self, answer, user): ...                  # line 486 (swallows errors; uses self._auditlog.log)

# navigator_auth/abac/policies/evaluator.py
class PolicyIndex:                                               # line 84
    def add(self, policy) -> None: ...                           # line 97 (NO de-duplication; _by_name overwritten)
    def get_by_name(self, name: str) -> Optional[ResourcePolicy]: ...  # line 125
    def all(self) -> List[ResourcePolicy]: ...                   # line 129
class PolicyEvaluator:                                           # line 194 (__init__ raises RuntimeError without rs_pep)
    _cache: dict                                                 # line 232
    _policies_json: str                                          # line 233
    def load_policies(self, policies) -> None: ...               # line 240 (does NOT clear the cache)
    def invalidate_cache(self, user_id: str = None) -> None: ... # line 396 (None -> clear all)
    def check_access(self, ctx, resource_type, resource_name, action, env=None,
                     owner_reports_to=None, org_id=1, client_id=1) -> EvaluationResult: ...  # line 410
        # ctx only needs .userinfo (dict: username, groups) and .user; resource_type may be a str
```

### Does NOT Exist
- ~~`PDP._registered`~~, ~~`PDP._has_external_policies`~~ — added by this task.
- ~~`PolicyEvaluator.add_policy` / `PolicyEvaluator.clear_cache`~~ — use `load_policies` / `invalidate_cache`.
- ~~`PDP.authorize` iterating `self._policies`~~ — authorization is evaluator-only (pdp.py:423).
- ~~`navigator_auth.abac.errors.PreconditionFailed` as an exception class~~ — it is a **factory
  function** (errors.py:77) returning `aiohttp.web.HTTPPreconditionRequired` (status 428). Tests
  must catch `web.HTTPPreconditionRequired`; `except PreconditionFailed` raises `TypeError`.
- ~~`ResourcePolicy.__eq__` semantics to rely on~~ — compare with `id()` (spec §7).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/pdp.py", "action": "MODIFY"},
    {"path": "tests/test_pdp_add_policy.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/pdp.py#PDP",
    "sym:navigator_auth/abac/pdp.py#PDP.__init__",
    "sym:navigator_auth/abac/pdp.py#PDP.add_policy",
    "sym:navigator_auth/abac/pdp.py#PDP.sorted_policies",
    "sym:navigator_auth/abac/pdp.py#PDP._load_policies",
    "sym:navigator_auth/abac/pdp.py#PDP._build_tenant_evaluator",
    "sym:navigator_auth/abac/pdp.py#PDP._invalidate_tenant_evaluators",
    "sym:navigator_auth/abac/pdp.py#PDP.reload_policies",
    "sym:navigator_auth/abac/pdp.py#PDP.authorize",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyIndex.all",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyEvaluator.load_policies",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyEvaluator.invalidate_cache",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyEvaluator.check_access"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- **Atomicity**: validate the whole adapted batch (the policy **and** its `<name>_negated` DENY)
  before any mutation. A `ValueError` must leave `_registered`, `_policies`, the evaluator index and
  `_policies_json`, the decision cache and the tenant LRU exactly as they were.
- Load into the evaluator **before** extending the registries, so a raising `load_policies` cannot
  leave a registered-but-unloaded policy.
- `load_policies` does not clear the decision cache (evaluator.py:240-246): call
  `invalidate_cache()` or a cached deny survives up to 300 s.
- **Identity, not equality**, in `_has_external_policies`, and use only
  `self._evaluator._index.all()` so the `_make_fake_evaluator` fakes in
  `tests/test_yaml_storage_double_load.py:206` keep working (`TestPDPDoubleLoadPrevention` must stay green).
- Tests that need the real evaluator require the `rs_pep` extension (worktrees get it via native
  artifact sync — never run `maturin develop` in a worktree).
- Stub the audit log in `authorize` tests: `pdp._auditlog = MagicMock(log=AsyncMock())`
  (pattern: `tests/test_auth_crud_write_envelope.py:129`).

### References in Codebase
- `tests/test_yaml_storage_double_load.py:190-216` — `_FakeIndex` / `_make_fake_evaluator` (copy them into the new test file; do not import across test modules).
- `tests/test_check_access.py:71` — `make_mocked_request` pattern.

---

## Implementation Blueprint

### Steps (in order)
1. Add the two imports after pdp.py:18 — *why*: `add_policy` is typed with `AbstractPolicy` and stores `ResourcePolicy`.
2. Replace pdp.py:79-81 (alias removal + `_registered`) — *why*: the PDP must own its list; `_registered` drives reload/tenant/guard.
3. Append constructor registration after pdp.py:95 — *why*: `add_policy` needs `_evaluator` and `_tenant_evaluators` to exist.
4. Replace `add_policy` (pdp.py:104-106) and add `_has_external_policies` — *why*: core fix.
5. Change the guard at pdp.py:116 — *why*: registered-only evaluators must still load DB + YAML (`examples/test_abac.py` shape).
6. Insert the two `extend(self._registered)` lines — *why*: G1 "survives reload_policies() and reaches per-tenant evaluators".
7. Write the tests and run the Validation Commands.

### `navigator_auth/abac/pdp.py` (MODIFY — imports)
```python
# occurrences: 1 (verified: grep -c 'from .policies.adapter import PolicyAdapter' navigator_auth/abac/pdp.py)
# AFTER — insert below `from .policies.adapter import PolicyAdapter` (verified: pdp.py:18)
from .policies.abstract import AbstractPolicy
from .policies.resource_policy import ResourcePolicy
```

### `navigator_auth/abac/pdp.py` (MODIFY — `__init__` start)
```python
# occurrences: 1 (verified: grep -cF '        self._policies: list = []' navigator_auth/abac/pdp.py)
# REPLACE lines 79-81 (verified: pdp.py:79-81):
#         self._policies: list = []
#         if isinstance(policies, list):
#             self._policies = policies
# WITH:
        self._policies: list = []
        # Policies registered through add_policy / policies=: enforced by the
        # evaluator and kept across reload_policies() and tenant evaluators.
        self._registered: list[ResourcePolicy] = []
```

### `navigator_auth/abac/pdp.py` (MODIFY — `__init__` end)
```python
# occurrences: 1 (verified: grep -cF '        ] = OrderedDict()' navigator_auth/abac/pdp.py)
# AFTER — insert below `        ] = OrderedDict()` (verified: pdp.py:95, last line of __init__)
        # Register constructor policies last: add_policy needs the evaluator and
        # the tenant LRU created above. The caller's list is not aliased.
        if isinstance(policies, list):
            for policy in policies:
                self.add_policy(policy)
```

### `navigator_auth/abac/pdp.py` (MODIFY — `add_policy` + `_has_external_policies`)
```python
# occurrences: 1 (verified: grep -c '    def add_policy(self, policy: Policy):' navigator_auth/abac/pdp.py)
# REPLACE lines 104-106 (verified: pdp.py:104-106) WITH:
    def add_policy(self, policy: AbstractPolicy) -> list[ResourcePolicy]:
        """Register a policy so ``PDP.authorize`` enforces it.

        Args:
            policy: A classic ``Policy``/``ObjectPolicy``/``FilePolicy`` or a
                ``ResourcePolicy``.

        Returns:
            The ``ResourcePolicy`` objects loaded into the evaluator: the adapted
            policy plus its ``<name>_negated`` DENY when it has ``!`` resources.

        Raises:
            ValueError: ``PolicyAdapter.from_policy`` rejected the policy (the
                message carries its reason), or a policy with the same name is
                already registered. Nothing is changed when it raises.
        """
        name = getattr(policy, "name", repr(policy))
        result = PolicyAdapter.from_policy(policy)
        if result.skipped:
            raise ValueError(f"Policy '{name}' cannot be registered: {result.reason}")
        adapted = [p for p in [result.policy, *result.additional_policies] if p is not None]
        # FILL IN: duplicate check — raise ValueError(f"Policy name '<n>' is already registered")
        #   when any name in `adapted` is already a name in self._registered, or `adapted` repeats a
        #   name itself — bounded by spec M2 + AC "duplicate registered name -> ValueError"; must run
        #   BEFORE any mutation below (atomic rejection, test_add_policy_rejection_is_atomic).
        for warning in result.warnings:
            self.logger.warning("Policy adaptation warning: %s", warning)
        self._evaluator.load_policies(adapted)
        self._registered.extend(adapted)
        self._policies.extend(adapted)
        self._evaluator.invalidate_cache()
        if self._tenant_evaluators:
            self._invalidate_tenant_evaluators()
        self.sorted_policies()
        return adapted

    def _has_external_policies(self) -> bool:
        """Tell whether the evaluator holds policies not registered via ``add_policy``.

        Returns:
            True when any policy in the evaluator index is not (by identity) in
            ``self._registered`` — i.e. the evaluator was pre-loaded externally.
        """
        registered = {id(p) for p in self._registered}
        return any(id(p) not in registered for p in self._evaluator._index.all())
```
**Why**: spec §3 M2 skeleton. Keep the `def sorted_policies(self):` that follows untouched.

### `navigator_auth/abac/pdp.py` (MODIFY — startup guard)
```python
# occurrences: 1 (verified: grep -c '        if self._evaluator._index.all():' navigator_auth/abac/pdp.py)
# REPLACE line 116 (verified: pdp.py:116) WITH:
        if self._has_external_policies():
# keep the logger.info(...) and `return` below it; update the comment above (112-115) to say the
# guard ignores policies registered through add_policy.
```

### `navigator_auth/abac/pdp.py` (MODIFY — tenant evaluator)
```python
# occurrences: 1 (verified: grep -c '        ev.load_policies(resource_policies)' navigator_auth/abac/pdp.py)
# BEFORE — insert above `        ev.load_policies(resource_policies)` (verified: pdp.py:226)
        # Registered policies reach every tenant evaluator; tenant scoping stays
        # with the engine (org_id/client_id on each ResourcePolicy).
        resource_policies.extend(self._registered)
```

### `navigator_auth/abac/pdp.py` (MODIFY — reload)
```python
# occurrences: 1 (verified: grep -c '        # Build new index' navigator_auth/abac/pdp.py)
# BEFORE — insert above `        # Build new index` (verified: pdp.py:300, directly above
#          `        new_index = PolicyIndex()` at 301). Do NOT anchor on the adapt_batch line: it occurs twice (221, 296).
        # Registered policies survive a reload (storage alone does not hold them).
        resource_policies.extend(self._registered)
```
**Why**: `self._policies = resource_policies` (pdp.py:317) then also carries them.

### FILL IN checklist
- [ ] `pdp.py::PDP.add_policy` duplicate-name check — before any mutation; bounded by AC (duplicate → `ValueError`, atomic)
- [ ] `tests/test_pdp_add_policy.py` — all 13 test bodies; bounded by spec §4 M2 rows

---

## Acceptance Criteria

- [ ] `PDP.authorize` on a mocked `GET /dashboard/` returns a `PolicyResponse` once a no-subject ALLOW policy for `urn:uri:/dashboard/` is registered via `add_policy` **or** `PDP(policies=[...])`.
- [ ] An uncovered path still raises `web.HTTPPreconditionRequired` (428).
- [ ] `add_policy` raises `ValueError` for an unadaptable policy (message includes the adapter reason) and for a duplicate registered name; rejection is atomic (registries, index, `_policies_json`, cache, tenant LRU unchanged; `/admin[` never grants `/unrelated`).
- [ ] `add_policy` clears the decision cache and the tenant LRU; returns the adapted list.
- [ ] `_load_policies` still skips for an externally pre-loaded evaluator (`TestPDPDoubleLoadPrevention` green) and still loads storage when the evaluator holds only registered policies.
- [ ] `reload_policies()` and `_build_tenant_evaluator()` include registered policies.
- [ ] `PDP.authorize` is unchanged (`git diff` shows no edit in pdp.py:397-448).
- [ ] All Validation Commands pass.

---

## Validation Commands
- `pytest tests/test_pdp_add_policy.py -q`
- `pytest tests/test_yaml_storage_double_load.py -q`
- `pytest tests/test_tenant_sql_filtering.py -q`

---

## Test Specification

```python
# tests/test_pdp_add_policy.py
"""PDP.add_policy / PDP(policies=) are enforced by the evaluator (FEAT-109 M2)."""
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.conf import AUTH_SESSION_OBJECT


def _dashboard_policy(name: str = "public_dashboard") -> Policy:
    return Policy(name=name, effect=PolicyEffect.ALLOW, resource=["urn:uri:/dashboard/"], priority=5)


def _ctx(username: str = "someone@acme.com", groups=None):
    ctx = MagicMock()
    ctx.user = None
    ctx.userinfo = {"username": username, "groups": list(groups or [])}
    return ctx


@pytest.fixture
def pdp_with_storage():
    """Real evaluator (needs rs_pep) over an empty mocked storage."""
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    pdp = PDP(storage=storage)
    pdp._auditlog = MagicMock(log=AsyncMock())
    return pdp


def test_add_policy_loads_into_evaluator(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    assert "public_dashboard" in [p.name for p in pdp_with_storage.evaluator._index.all()]


def test_add_policy_empty_subject_allows_dashboard(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    result = pdp_with_storage.evaluator.check_access(_ctx(), ResourceType.URI, "/dashboard/", "uri:read")
    assert result.allowed


@pytest.mark.asyncio
async def test_authorize_unmatched_still_428(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    request = make_mocked_request("GET", "/nothing-here", app=web.Application())
    session = {AUTH_SESSION_OBJECT: {"username": "someone@acme.com", "groups": []}}
    with pytest.raises(web.HTTPPreconditionRequired):
        await pdp_with_storage.authorize(request=request, session=session)


# FILL IN: test_authorize_dashboard_no_428, test_constructor_policies_registered,
#   test_add_policy_duplicate_name_raises, test_add_policy_unadaptable_raises (reason in message),
#   test_add_policy_rejection_is_atomic (snapshot _registered/_policies/_index.all()/_policies_json/
#   _cache/_tenant_evaluators; try Policy(resource=["urn:uri:/admin["]) and
#   Policy(resource=["urn:uri:/x"], context={"username": "u"}); assert unchanged and /unrelated denied),
#   test_add_policy_invalidates_cache (cached deny dropped), test_load_policies_runs_with_only_registered
#   (copied _make_fake_evaluator + add_policy, then storage.load_policies awaited),
#   test_reload_keeps_registered, test_tenant_evaluator_includes_registered (await
#   pdp._build_tenant_evaluator(5, 7); name present in its _index)
```

---

## Agent Instructions

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug policy-issues --feature-id FEAT-109`).
2. **Read the spec** (§2 Overview, §3 Module 2, §4, §7 Known Risks).
3. **Check dependencies** — TASK-189 must be `"done"` in `sdd/tasks/index/policy-issues.json`.
4. **Verify the Codebase Contract**; confirm `PolicyAdapter.from_policy` and `AbstractPolicy.raw_resources` exist.
5. **Update status** → `"in-progress"` (set `started_at`).
6. **Implement** from the blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-190 policy-issues verified`.
10. **Fill in the Completion Note**, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

## Completion Note

Merged by hand (engine merge refused: attempt lacked execution_id after 3 attempts). Task-tier failures were order-dependent legacy tests (get_event_loop) broken by pytest-asyncio teardown; fixed with a module-scoped loop-restoring fixture in tests/test_pdp_add_policy.py. Merge-tier validation: completed (green).
