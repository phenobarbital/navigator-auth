# TASK-193: PBAC example cleanup (`add_policy` only) and README section

**Feature**: FEAT-109 — PBAC example policy issues
**Spec**: `sdd/specs/policy-issues.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-190
**Assigned-to**: unassigned

---

## Context

`examples/policy_server.py` pre-loads the evaluator by hand (`evaluator.load_from_directory` +
`evaluator.load_policies([...])`) and then registers its five classic policies with
`pdp.add_policy`, which never reached the evaluator — hence the 428 on `/dashboard/`. Once
TASK-190 makes `add_policy` effective, the example must use **only** that documented path
(spec §3 **Module 5**, goal G5). Two example policies also need fixing so they register under
TASK-189's strict adapter without losing their restriction:

- `prod_config_manager` used `context={"username": ...}`, which the evaluator never enforced
  (anyone could edit production config) and which `from_policy` now rejects → use
  `subject=["platform-lead@acme.com"]`.
- `analytics_business_hours` keeps `day_of_week` on purpose: it exercises the `day_of_week` → `dow`
  normalization, so weekends are actually denied (today the engine ignores the key).

`examples/README.md` gains a `policy_server.py` section with run instructions and troubleshooting.

---

## Scope

- Replace `prod_config_manager`'s `context=` with `subject=["platform-lead@acme.com"]`.
- Add a module-level `EXAMPLE_POLICIES` tuple listing the ten example policies.
- In `create_app`: remove `evaluator.load_from_directory(...)` and `evaluator.load_policies([...])`
  (lines 558-569) and register all ten with `pdp.add_policy` (replaces lines 578-586). Keep the
  `PolicyEvaluator(cache_size=1024, cache_ttl_seconds=300)`, `pgStorage`, `YAMLStorage` and
  `PDP(storage=..., yaml_storage=..., evaluator=...)` construction unchanged.
- Add the README section before the identity-vault section.
- Write `tests/test_policy_server_example.py` (4 M5 tests from spec §4) — no live DB/Redis.

**NOT in scope**: running the example against Postgres/Redis (operator check, spec §5); rotating
env secrets; vault migration; changing the default policy packs; any library code.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `examples/policy_server.py` | MODIFY | subject restriction, `EXAMPLE_POLICIES`, `add_policy`-only registration |
| `examples/README.md` | MODIFY | `policy_server.py` section + troubleshooting |
| `tests/test_policy_server_example.py` | CREATE | example policies adapt, names disjoint, user + weekday restrictions enforced |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` HEAD `c5403d4` on 2026-11-11. Importing `examples/policy_server.py`
> under `warnings.simplefilter("error")` succeeds (checked at task time; it sets
> `AUDIT_BACKEND=log` via `os.environ.setdefault` on import).

### Verified Imports
```python
# tests
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from navigator_auth.abac.pdp import PDP                                   # verified: abac/pdp.py:69
from navigator_auth.abac.policies.adapter import PolicyAdapter            # verified: adapter.py:19 (from_policy added by TASK-189)
from navigator_auth.abac.policies.environment import Environment          # verified: examples/policy_server.py:52
from navigator_auth.abac.policies.evaluator import PolicyLoader           # verified: evaluator.py:134
from navigator_auth.abac.policies.resources import ResourceType           # verified: resources.py (URI = "uri")
```

### Existing Signatures to Use
```python
# examples/policy_server.py
data_science_vectors, qa_testing_tools, deny_vector_delete, agent_chat_all,
agent_configure_platform                                   # ResourcePolicy objects, lines 61-118
# NOTE: deny_vector_delete's name is "deny_vector_delete_non_admin", agent_chat_all's is "agent_chat_all_users"
public_dashboard (126), admin_panel (135, name "admin_panel_access"), analytics_business_hours (146),
deployment_approval (160, ObjectPolicy), prod_config_manager (171, ObjectPolicy)   # classic policies
#   177: `    context={"username": "platform-lead@acme.com"},`  -> replace with subject=[...]
#   183: `# 3. Login Form & Auth Helpers` (dashed lines 182/184 around it)
def create_app() -> web.Application: ...                   # line 528
#   553-556 PolicyEvaluator(...); 558-560 load_from_directory; 562-569 load_policies([...]);
#   572-576 PDP(...); 578-586 classic registration loop; 589 pdp.setup(app)

# navigator_auth/abac/pdp.py (after TASK-190)
class PDP:
    def add_policy(self, policy) -> list[ResourcePolicy]: ...          # raises ValueError on rejection
    async def reload_policies(self) -> int: ...                       # line 274
    async def _build_tenant_evaluator(self, org_id: int, client_id: int) -> PolicyEvaluator: ...  # line 197
    evaluator: PolicyEvaluator                                         # property, line 98
# navigator_auth/abac/policies/evaluator.py
class PolicyLoader:
    @staticmethod
    def load_from_directory(directory: Path) -> List[ResourcePolicy]: ...  # line 184
class PolicyEvaluator:
    def check_access(self, ctx, resource_type, resource_name, action, env=None,
                     owner_reports_to=None, org_id=1, client_id=1): ...    # line 410
    # ctx needs .userinfo {"username", "groups"} and .user; resource_type may be a plain str ("config")
# navigator_auth/abac/policies/environment.py
class Environment(BaseModel): dow: Optional[int]; hour: Optional[int]   # explicit values win (lines 98-123)
# Engine tenant match (rs_pep/src/lib.rs:303-306): org_id/client_id 1 = global, matches every tenant.
```

### Does NOT Exist
- ~~`examples.policy_server.EXAMPLE_POLICIES`~~ — added by this task.
- ~~`ResourceType.CONFIG` / `ResourceType("config")`~~ — not an enum member (raises `ValueError`); pass the string `"config"`.
- ~~`pdp.add_policies([...])`~~ — register one at a time with `add_policy`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "examples/policy_server.py", "action": "MODIFY"},
    {"path": "examples/README.md", "action": "MODIFY"},
    {"path": "tests/test_policy_server_example.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:examples/policy_server.py#create_app",
    "sym:navigator_auth/abac/pdp.py#PDP.add_policy",
    "sym:navigator_auth/abac/pdp.py#PDP.reload_policies",
    "sym:navigator_auth/abac/pdp.py#PDP._build_tenant_evaluator",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyLoader.load_from_directory",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyEvaluator.check_access"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Tests load the example by **file path** (`importlib.util.spec_from_file_location`) — do not rely
  on `examples` being importable from `sys.path`.
- Tests use the real evaluator (`rs_pep`) with mocked storage — no DB/Redis.
- Verify each restriction on **three** paths: right after registration (`pdp.evaluator`), after
  `await pdp.reload_policies()`, and on `await pdp._build_tenant_evaluator(5, 7)` checked with
  `org_id=5, client_id=7`.
- Weekday check: analytics-group user allowed at `Environment(dow=0, hour=12)`; denied at
  `dow=5`/`dow=6` noon and at `dow=2, hour=20` (outside `range(8, 19)`).

---

## Implementation Blueprint

### Steps (in order)
1. Fix `prod_config_manager` (line 177) — *why*: classic `context` is rejected by `from_policy`, and it never restricted anything.
2. Add `EXAMPLE_POLICIES` above section 3 — *why*: one list for `create_app` and the tests.
3. Remove the manual evaluator preload and register via `add_policy` in `create_app` — *why*: spec §3 M5; packs now load from `yaml_storage` at startup (the `_load_policies` guard ignores registered policies).
4. Add the README section — *why*: G5 / AC troubleshooting entries.
5. Write the tests; run the Validation Commands.

### `examples/policy_server.py` (MODIFY — subject restriction)
```python
# occurrences: 1 (verified: grep -c '    context={"username": "platform-lead@acme.com"},' examples/policy_server.py)
# REPLACE line 177 (verified: policy_server.py:177) WITH:
    subject=["platform-lead@acme.com"],
```

### `examples/policy_server.py` (MODIFY — `EXAMPLE_POLICIES`)
```python
# occurrences: 1 (verified: grep -c '# 3. Login Form & Auth Helpers' examples/policy_server.py)
# BEFORE — insert above the dashed comment line (policy_server.py:182) that precedes
#          `# 3. Login Form & Auth Helpers` (verified: policy_server.py:183), after prod_config_manager:
# Every example policy, registered with pdp.add_policy in create_app().
EXAMPLE_POLICIES = (
    data_science_vectors,
    qa_testing_tools,
    deny_vector_delete,
    agent_chat_all,
    agent_configure_platform,
    public_dashboard,
    admin_panel,
    analytics_business_hours,
    deployment_approval,
    prod_config_manager,
)

```

### `examples/policy_server.py` (MODIFY — `create_app`)
```python
# occurrences: 1 (verified: grep -c '    # Load default policy packs into the evaluator' examples/policy_server.py)
# DELETE lines 558-570 (verified: policy_server.py:558-569 + the blank line after), i.e. from
#   `    # Load default policy packs into the evaluator` through the closing `    ])` of
#   `evaluator.load_policies([...])`.
# occurrences: 1 (verified: grep -c '    # Add classic ABAC policies' examples/policy_server.py)
# REPLACE lines 578-586 (verified: policy_server.py:578-586, the loop ending in `pdp.add_policy(policy)`) WITH:
    # Register every example policy: add_policy loads it into the evaluator.
    # The default packs load from yaml_storage when the app starts.
    for policy in EXAMPLE_POLICIES:
        pdp.add_policy(policy)
```
**Why**: spec §3 M5 skeleton. `pdp.add_policy(policy)` (anchor at line 586, 1 occurrence) stays the
only registration call.

### `examples/README.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '## `identity_vault_server.py` — Identity Vault: login + linked credentials' examples/README.md) -->
<!-- BEFORE — insert above that heading (verified: README.md:77); README.md:75 is the `---` separator
     closing the previous section, so end the new block with its own `---` + blank line. -->
## `policy_server.py` — PBAC example

<!-- FILL IN: 1 paragraph "what it demonstrates": AuthHandler login form + PDP/Guardian, default
     packs from navigator_auth/abac/default_policies via YAMLStorage, ten policies registered with
     pdp.add_policy (5 ResourcePolicy, 5 classic: Policy/ObjectPolicy), REST /api/v1/abac/check. -->

### Run

<!-- FILL IN: needs PostgreSQL (pgStorage, default_dsn) and Redis from env/.env;
     `python examples/policy_server.py`; open http://localhost:5000/, log in, visit /dashboard/;
     reuse the curl example from the module docstring (policy_server.py:20-22). -->

### Troubleshooting

* **`428 "No Matching Policies were found, Deny access."`** — no policy covers the path. Register
  one with `pdp.add_policy(...)`; policies pushed straight into the evaluator are dropped by
  `reload_policies()`.
* **`ValueError` from `pdp.add_policy(...)`** — the policy cannot be enforced as written: an invalid
  resource pattern, a duplicate name, or a classic `context` / `conditions` / `scopes` restriction
  (rejected, never silently ignored). Express a username restriction with `subject=[...]`.
  Supported environment keys: `hour`, `dow` (`day_of_week` is accepted as an alias),
  `is_business_hours`, `is_weekend`, `day_segment`.
* **`InsecureKeyLengthWarning: The HMAC key is N bytes long`** or the startup WARNING
  `AUTH_SECRET_KEY is N bytes; HMAC keys should be at least 32 bytes` — set `AUTH_SECRET_KEY` and
  `AUTH_TOKEN_SECRET` / `PARTNER_KEY` to ≥ 32 bytes (see "Signing keys" in `docs/settings.rst`).
* **`Vault secret failed integrity check ... UnsupportedFormatError`** — a pre-v2 (v1) vault
  secret. Apply `navigator_auth/vault/sql/002_vault_crypto_hardening.sql`, then run
  `navigator-vault migrate --dry-run`, then `navigator-vault migrate --run --backup-dir <dir>`.

---

```
**Why**: spec §3 M5 fixes the heading, placement and the four troubleshooting entries.

### FILL IN checklist
- [ ] README "what it demonstrates" paragraph and "Run" steps — bounded by spec §3 M5 + module docstring (policy_server.py:1-32)
- [ ] `tests/test_policy_server_example.py` — the four test bodies; bounded by spec §4 M5 rows

---

## Acceptance Criteria

- [ ] `examples/policy_server.py` registers all ten example policies with `pdp.add_policy` and no longer calls `evaluator.load_from_directory` / `evaluator.load_policies` (`grep -c "evaluator.load_" examples/policy_server.py` → 0).
- [ ] Every example policy adapts via `PolicyAdapter.from_policy` without a skip; example names (including any `_negated`) are disjoint from the `default_policies` pack names.
- [ ] Through registration, reload and tenant evaluator paths: platform lead may `config:edit`/`config:deploy` `production`; an unrelated username is denied.
- [ ] Through the same three paths: analytics user allowed weekday noon, denied Saturday/Sunday noon and at 20:00.
- [ ] `examples/README.md` has the `policy_server.py` section with all four troubleshooting entries, including registration failures.
- [ ] All Validation Commands pass.

---

## Validation Commands
- `pytest tests/test_policy_server_example.py -q`

---

## Test Specification

```python
# tests/test_policy_server_example.py
"""The PBAC example registers cleanly and enforces its restrictions (FEAT-109 M5)."""
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.policies.evaluator import PolicyLoader
from navigator_auth.abac.policies.resources import ResourceType

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def example():
    """Load examples/policy_server.py by path (no live services are touched)."""
    spec = importlib.util.spec_from_file_location(
        "policy_server_example", ROOT / "examples" / "policy_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pdp(example) -> PDP:
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    pdp = PDP(storage=storage)
    pdp._auditlog = MagicMock(log=AsyncMock())
    for policy in example.EXAMPLE_POLICIES:
        pdp.add_policy(policy)
    return pdp


def _ctx(username: str, groups=()):
    ctx = MagicMock()
    ctx.user = None
    ctx.userinfo = {"username": username, "groups": list(groups)}
    return ctx


async def _evaluator_paths(pdp):
    """Return [(label, evaluator, org_id, client_id)] for registration, reload and tenant paths."""
    paths = [("registered", pdp.evaluator, 1, 1)]
    await pdp.reload_policies()
    paths.append(("reloaded", pdp.evaluator, 1, 1))
    paths.append(("tenant", await pdp._build_tenant_evaluator(5, 7), 5, 7))
    return paths


def test_example_policies_adapt_cleanly(example):
    for policy in example.EXAMPLE_POLICIES:
        result = PolicyAdapter.from_policy(policy)
        assert not result.skipped, (policy.name, result.reason)


# FILL IN: test_example_policy_names_disjoint_from_packs (PolicyLoader.load_from_directory(
#   ROOT / "navigator_auth" / "abac" / "default_policies") names vs adapted example names)
# FILL IN: @pytest.mark.asyncio test_example_config_user_restriction — for each path:
#   ev.check_access(_ctx("platform-lead@acme.com"), "config", "production", "config:edit",
#   org_id=o, client_id=c).allowed is True (also config:deploy); "intruder@acme.com" -> False
# FILL IN: @pytest.mark.asyncio test_example_analytics_weekday_restriction — for each path:
#   ev.check_access(_ctx("analyst@acme.com", ["analytics"]), ResourceType.URI, "/api/v1/analytics/",
#   "uri:read", env=Environment(dow=0, hour=12), ...) allowed; dow=5/6 hour=12 and dow=2 hour=20 denied
```

---

## Agent Instructions

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug policy-issues --feature-id FEAT-109`).
2. **Read the spec** (§3 Module 5, §4 M5 rows, §5 example ACs).
3. **Check dependencies** — TASK-190 (and through it TASK-189) must be `"done"`.
4. **Verify the Codebase Contract**; confirm `PDP.add_policy` now loads into the evaluator.
5. **Update status** in `sdd/tasks/index/policy-issues.json` → `"in-progress"` (set `started_at`).
6. **Implement** from the blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-193 policy-issues verified`.
10. **Fill in the Completion Note**, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

## Completion Note

Merged (TASK-194 by hand after task-tier validation_failed from order-dependent legacy get_event_loop tests; fixed with loop-restoring fixtures). Merge-tier validation: completed.
