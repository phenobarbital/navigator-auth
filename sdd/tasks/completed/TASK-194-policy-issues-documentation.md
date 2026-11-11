# TASK-194: Documentation — CHANGELOG entry + API docstrings (no wiki pages)

**Feature**: FEAT-109 — PBAC example policy issues
**Spec**: `sdd/specs/policy-issues.spec.md`
**Status**: done
**Priority**: low
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-190, TASK-191, TASK-192
**Assigned-to**: unassigned

---

## Context

The spec sets `docs.policy: required` (FEAT-801 documentation task) but declares **no** `wiki/`
pages: this repository has no `wiki/` tree and `techwiki` is not configured (spec §10). The
repository docs are updated inside the module tasks instead (`docs/settings.rst` in TASK-192,
`examples/README.md` in TASK-193). What remains for this task:

1. **The intentional behavior change** must be documented (spec §5 AC: "Document the intentional
   behavior change: duplicate names, invalid patterns, and unsupported classic restrictions now
   raise `ValueError` instead of being silently accepted but unenforced"). It goes in
   `CHANGELOG.md` under `# Unreleased` (rendered by `docs/changelog.rst`), together with the
   `abac_middleware` 404 fix (`navigator_auth/abac/middleware.py`, TASK-191) and the HMAC
   key-length warning (TASK-192).
2. **Docstring completeness** for the spec's `api_modules`: `navigator_auth.abac.pdp`,
   `navigator_auth.abac.policies.adapter`, `navigator_auth.libs.hmac_keys`.

---

## Scope

- Add three FEAT-109 bullets at the top of `# Unreleased` in `CHANGELOG.md`.
- Docstring pass (docstrings/comments only, **no code change**) on the public surface of the three
  API modules: `PDP.add_policy`, `PDP.policies`, `PDP.sorted_policies`, `PDP.evaluator`,
  `PDP.reload_policies`, `PDP.authorize`; `AdapterResult`, `PolicyAdapter.from_policy`,
  `PolicyAdapter.adapt`, `PolicyAdapter.adapt_batch`; every public name in
  `navigator_auth/libs/hmac_keys.py`. Add or complete Google-style docstrings (Args / Returns /
  Raises where they apply). Leave a file untouched when its docstrings are already complete.
- Run `parrot sdd techwiki check --spec sdd/specs/policy-issues.spec.md --root .` and record its output
  in the Completion Note (expected: `warning` with only `docs_no_pages` — the spec declares no pages).

**NOT in scope**: creating a `wiki/` tree or techwiki pages; `docs/settings.rst` and
`examples/README.md` (owned by TASK-192 / TASK-193); any logic change; bumping
`navigator_auth/version.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `CHANGELOG.md` | MODIFY | FEAT-109 bullets under `# Unreleased` |
| `navigator_auth/abac/pdp.py` | MODIFY | docstrings only, if gaps remain |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | docstrings only, if gaps remain |
| `navigator_auth/libs/hmac_keys.py` | MODIFY | docstrings only, if gaps remain |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` HEAD `c5403d4` on 2026-11-11 (symbols marked "after TASK-…" land with that task).

### Verified Imports
```python
# none — this task adds no imports. The docstring check in the Acceptance Criteria imports:
import inspect
import navigator_auth.abac.pdp            # verified: navigator_auth/abac/pdp.py
import navigator_auth.abac.policies.adapter   # verified: navigator_auth/abac/policies/adapter.py
import navigator_auth.libs.hmac_keys      # after TASK-192
```

### Existing Signatures to Use
```python
# CHANGELOG.md
# line 1: `# Unreleased` (1 occurrence); line 3 starts the first existing bullet
#   (`- **BREAKING — write envelope on the auth CRUD handlers (FEAT-107, ...`). Bullets are
#   `- **<bold lead>.** <prose>` wrapped at ~80 columns.
# navigator_auth/abac/pdp.py (after TASK-190)
class PDP:
    def add_policy(self, policy: AbstractPolicy) -> list[ResourcePolicy]: ...   # raises ValueError
    def _has_external_policies(self) -> bool: ...
# navigator_auth/abac/policies/adapter.py (after TASK-189)
class PolicyAdapter:
    @staticmethod
    def from_policy(policy: AbstractPolicy) -> AdapterResult: ...
# navigator_auth/libs/hmac_keys.py (after TASK-192)
MIN_HMAC_KEY_BYTES: int = 32
def configured_hmac_keys() -> dict[str, str | bytes | None]: ...
def short_hmac_keys(keys) -> list[tuple[str, int]]: ...
def warn_short_hmac_keys(logger=None) -> list[str]: ...
# navigator_auth/abac/middleware.py (after TASK-191): _is_system_route(); 404 handler awaited outside try; DEBUG log
```

### Does NOT Exist
- ~~`wiki/` pages for this feature~~ — none declared; do not create `wiki/`.
- ~~`docs/abac.rst` / a PBAC docs page~~ — not in `docs/`; do not invent one.
- ~~A separate `CHANGES.rst` FEAT entry convention~~ — recent features document in `CHANGELOG.md` `# Unreleased`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "CHANGELOG.md", "action": "MODIFY"},
    {"path": "navigator_auth/abac/pdp.py", "action": "MODIFY"},
    {"path": "navigator_auth/abac/policies/adapter.py", "action": "MODIFY"},
    {"path": "navigator_auth/libs/hmac_keys.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/pdp.py#PDP",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter",
    "sym:navigator_auth/abac/policies/adapter.py#AdapterResult"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- **Docstrings and comments only** in the three Python modules — a code diff there is a scope violation.
- Describe what the merged code does: read `add_policy`, `from_policy` and `abac_middleware` before
  writing the CHANGELOG, and correct the draft below if any detail differs.
- Never put a key value or secret in docs.

---

## Implementation Blueprint

### Steps (in order)
1. Read the merged `add_policy` / `from_policy` / `abac_middleware` / `hmac_keys` code — *why*: the
   CHANGELOG must match the shipped behavior, not the spec draft.
2. Insert the CHANGELOG bullets — *why*: AC "Document the intentional behavior change".
3. Docstring pass on the listed symbols — *why*: spec §10 api_modules.
4. Run the AC docstring check, `parrot sdd techwiki check`, and the Validation Commands.

### `CHANGELOG.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '# Unreleased' CHANGELOG.md) -->
<!-- AFTER — insert below `# Unreleased` and its blank line (verified: CHANGELOG.md:1-2), above the
     first existing bullet at line 3; end with a blank line. -->
- **Behavior change — `PDP.add_policy()` and `PDP(policies=[...])` are enforced
  (FEAT-109).** They used to append to a list `PDP.authorize` never read, so
  programmatic policies were silently ignored (the PBAC example answered 428 for
  `/dashboard/`). Registered policies are now adapted with the new
  `PolicyAdapter.from_policy`, loaded into the `PolicyEvaluator`, and kept across
  `reload_policies()` and per-tenant evaluators; `add_policy` returns the loaded
  `ResourcePolicy` list. It now **raises `ValueError`** instead of accepting a
  policy it cannot enforce: duplicate registered names, invalid resource
  patterns (including `!`-negated ones), and classic `context` / `conditions` /
  `scopes` restrictions (use `subject=[...]` for a username restriction). Classic
  `environment` accepts `day_of_week` as an alias of `dow`; unsupported keys are
  rejected. `Policy(resource="...")` with a single string no longer raises
  `TypeError`.
- **`abac_middleware` no longer mishandles unrouted requests (FEAT-109).** The
  404 skip swallowed `HTTPNotFound`, ran the 404 handler twice and logged
  `Access to <path> is not Authenticated.` at WARNING for browser probes
  (`/favicon.ico`, `/.well-known/...`). Unrouted requests now pass through once
  and silently; the unauthenticated pass-through logs at DEBUG.
  `EXCLUDE_DEFAULTS` is unchanged.
- **Startup warning for short HMAC keys (FEAT-109).** `AuthHandler.setup` logs
  one WARNING on `navigator_auth.security` per configured HMAC key shorter than
  32 bytes (`AUTH_SECRET_KEY`, `AUTH_TOKEN_SECRET` / `PARTNER_KEY`, an explicit
  `AUTH_RECOVERY_SECRET`), naming the setting and its length, never the value.
  See "Signing keys" in `docs/settings.rst`.

```
**Why**: spec §5 AC (behavior change), §2 Overview (log noise, short keys). Adjust wording to the merged code (Step 1).

### `navigator_auth/abac/pdp.py`, `navigator_auth/abac/policies/adapter.py`, `navigator_auth/libs/hmac_keys.py` (MODIFY — docstrings only)
```python
# FILL IN: for each symbol in Scope whose inspect.getdoc() is None or lacks the Args/Returns/Raises
#   sections that apply, add a Google-style docstring — bounded by project rule (Google-style
#   docstrings) and "docstrings only, no code change". Example shape:
    def policies(self) -> list:
        """Return the PDP's local policy list (adapted ``ResourcePolicy`` objects).

        Returns:
            The list kept for compatibility (e.g. ``Guardian``); authorization
            itself is decided by the evaluator.
        """
```
**Why**: spec §10 lists the three `api_modules` for docstring completeness. Do not add a return
annotation or change any signature while doing this — docstrings only.

### FILL IN checklist
- [ ] `CHANGELOG.md` — reconcile the draft with the merged behavior; bounded by Step 1
- [ ] Docstrings for the Scope symbols that lack them; bounded by "docstrings only"

---

## Acceptance Criteria

- [ ] `CHANGELOG.md` `# Unreleased` documents: `add_policy` / `PDP(policies=)` enforcement, the `ValueError` cases (duplicate names, invalid patterns, unsupported classic restrictions) and the return value; the `abac_middleware` 404/DEBUG fix; the HMAC key-length warning.
- [ ] `git diff` of `pdp.py`, `adapter.py`, `hmac_keys.py` in this task touches docstrings/comments only.
- [ ] Docstring check passes:
      `python -c "import inspect, navigator_auth.abac.pdp as p, navigator_auth.abac.policies.adapter as a, navigator_auth.libs.hmac_keys as h; objs=[p.PDP.add_policy, p.PDP.policies, p.PDP.sorted_policies, p.PDP.reload_policies, p.PDP.authorize, a.AdapterResult, a.PolicyAdapter.from_policy, a.PolicyAdapter.adapt, a.PolicyAdapter.adapt_batch, h.configured_hmac_keys, h.short_hmac_keys, h.warn_short_hmac_keys]; missing=[o.__qualname__ for o in objs if not inspect.getdoc(o)]; print(missing); assert not missing"`
- [ ] `parrot sdd techwiki check --spec sdd/specs/policy-issues.spec.md --root .` reports only `docs_no_pages` (recorded in the Completion Note).
- [ ] All Validation Commands pass.

---

## Validation Commands
- `pytest tests/test_yaml_storage_double_load.py -q`
- `pytest tests/test_protected_paths.py -q`

---

## Test Specification

No new tests: this task changes documentation only. The Validation Commands import
`navigator_auth.abac.pdp` / `.policies.adapter` (via `PDP`) and `navigator_auth.auth`
(→ `navigator_auth.libs.hmac_keys`), so a docstring edit that breaks a module fails them.

---

## Agent Instructions

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug policy-issues --feature-id FEAT-109`).
2. **Read the spec** (§5 AC "Document the intentional behavior change", §10 Documentation).
3. **Check dependencies** — TASK-190, TASK-191 and TASK-192 must be `"done"`.
4. **Verify the Codebase Contract** against the merged code.
5. **Update status** in `sdd/tasks/index/policy-issues.json` → `"in-progress"` (set `started_at`).
6. **Implement** from the blueprint; complete every `# FILL IN:`.
7. **Verify** — run the AC checks and the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-194 policy-issues verified`.
10. **Fill in the Completion Note** (include the techwiki check output), then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

## Completion Note

Merged (TASK-194 by hand after task-tier validation_failed from order-dependent legacy get_event_loop tests; fixed with loop-restoring fixtures). Merge-tier validation: completed.
