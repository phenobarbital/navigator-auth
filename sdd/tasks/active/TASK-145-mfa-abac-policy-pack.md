# TASK-145: ABAC policy pack `mfa_admin_access.yaml`

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 11** — configuration only, no Python under
`navigator_auth/`.

Administrative OTP disenrolment (TASK-142, `DELETE /auth/mfa/{user_id}`) is
gated by a **new ABAC action, `mfa:disenroll`, declared in its own named
policy and granted to a group that is not `superuser`** (spec §8 resolved
question "Which permission gates administrative OTP disenrolment?", §7 R1).
That separation is the mitigation for R1: switching a user's OTP off drops them
to the e-mail floor, and a principal who can also edit `email` through the
generic `UserManager` could then take the account over. Requiring two roles for
the two capabilities is what makes the bounded disenrolment "bounded".

The separation is **real, not nominal**, because of two verified facts:

1. `admin_full_access.yaml` wildcards **resources** (`uri:*`, priority 100) but
   **enumerates its actions with no wildcard** (verified, file contents below),
   so `mfa:disenroll` falls outside it.
2. `policy_allows()` **fails closed** when a named policy is absent
   (`navigator_auth/decorators.py:1170-1215`, FEAT-105 TASK-119), so a
   deployment that never ships this file has *nobody* able to disenrol — the
   escape hatch is an explicit operator decision.

The `security_admin` group is a **provisional default** (spec §6 Does NOT
Exist: no such group is defined anywhere). FEAT-107's open question about the
default group for `users:grant_role` names this same decision; this task ships
the spec's choice and the test pins it, so a later rename is a deliberate,
visible change.

---

## Scope

- Create `navigator_auth/abac/default_policies/mfa_admin_access.yaml` exactly
  per spec §3 Module 11.
- Create `tests/test_mfa_policy_pack.py`, a contract test mirroring
  `tests/unit/handlers/test_auth_model_policy_pack.py`: the pack parses through
  `YAMLStorage._parse_file`, declares exactly the action/group/effect/priority
  the handler expects, grants nothing to `superuser`/`admin`/`*`, and
  `admin_full_access.yaml` has no action wildcard that would cover
  `mfa:disenroll`.

**NOT in scope**:
- The handler that calls `policy_allows(..., action="mfa:disenroll")` and the
  tenant-ownership check — TASK-142 (it owns
  `test_admin_disenroll_requires_mfa_action` and
  `test_admin_disenroll_rejects_foreign_tenant`).
- Creating a `security_admin` group, any migration, or editing
  `admin_full_access.yaml`.
- Loading `default_policies/` automatically — nothing in the codebase reads that
  directory (FEAT-105 TASK-120 note); operators copy packs into their PDP
  storage. Documentation of that is TASK-148.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/default_policies/mfa_admin_access.yaml` | CREATE | The `mfa_admin_access` policy |
| `tests/test_mfa_policy_pack.py` | CREATE | Contract test (parse, shape, exclusivity) |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
from pathlib import Path
import pytest
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
#   class YAMLStorage(AbstractStorage)                     # yaml_storage.py:20
#   @staticmethod def _parse_file(path: Path) -> list[dict]   # yaml_storage.py:105
```

### `YAMLStorage._parse_file` output shape (verified `yaml_storage.py:105-150`)

For each entry under `policies:` with the default `policy_type: resource`:

```python
{
    "name": policy_data["name"],
    "policy_type": "resource",
    "effect": "ALLOW" | "DENY",           # upper-cased from the YAML `effect`
    "description": policy_data.get("description", ""),
    "resources": policy_data.get("resources", []),
    "actions": policy_data.get("actions", []),
    "subjects": policy_data.get("subjects", {}),
    "conditions": conditions.get("context", {}),
    # … plus priority / enforcing (asserted by the FEAT-105 test: p["priority"] == 90, p["enforcing"] is True)
}
```

### The pack shape being mirrored — `auth_model_admin_access.yaml` (FEAT-105 TASK-120)

```yaml
version: "1.0"
defaults:
  effect: deny
policies:
  - name: user_identities_admin_access
    effect: allow
    resources: ["uri:/api/v1/user_identity*"]
    actions: ["identity:read", "identity:revoke", "identity:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true
```

and its test, `tests/unit/handlers/test_auth_model_policy_pack.py:14-20,45-100`
(module-scoped `parsed` fixture over `YAMLStorage._parse_file(PACK)`; asserts
names, actions, `object:verb` shape, groups, `effect == "ALLOW"`,
`enforcing is True`, `priority == 90`, `policy_type == "resource"`).

### `admin_full_access.yaml` (verified verbatim, 695 B)

`resources: ["tool:*", "kb:*", "vector:*", "agent:*", "mcp:*", "uri:*"]`,
`actions:` = `tool:execute, tool:list, tool:configure, kb:query, kb:write,
kb:admin, vector:search, vector:insert, vector:delete, agent:chat, agent:query,
agent:configure` — **no `*` and no `<object>:*` entry**; groups
`superuser, admin`; priority 100; enforcing true.

### `default_policies/` today (verified `ls`)

`admin_full_access.yaml`, `auth_model_admin_access.yaml`,
`business_hours_only.yaml`, `deny_after_hours.yaml`, `engineering_tools.yaml`,
`mcp_services.yaml`, `readonly_agents.yaml` — seven files; this adds an eighth.
Do not assert a file count in the test (other features add packs).

### Does NOT Exist (Anti-Hallucination)

- ~~the `mfa:disenroll` action, or any policy declaring it~~ — this task creates it.
- ~~a `security_admin` group~~ — not defined anywhere; the YAML names it as the deployment default, it must not be assumed to exist at runtime.
- ~~a loader that auto-applies `default_policies/`~~ — none.
- ~~`YAMLStorage.parse` / `load_file`~~ — the static parser is `_parse_file`; the async API is `load_policies()` over a directory.

---

## Implementation Blueprint

### `navigator_auth/abac/default_policies/mfa_admin_access.yaml` — CREATE

```yaml
# FEAT-106 (spec §3 Module 11) — administrative OTP disenrolment.
#
# Separation of duties, verifiably real:
#   * admin_full_access.yaml wildcards RESOURCES (uri:*) at priority 100 but
#     ENUMERATES its actions with no wildcard, so `mfa:disenroll` falls outside it.
#   * policy_allows() fails closed, so a deployment that never ships this file
#     has NOBODY able to disenrol — the escape hatch is an explicit operator decision.
# WARNING: adding `mfa:*` or "*" to admin_full_access.yaml collapses this separation.
# `security_admin` is a provisional default group; it is not created by navigator-auth.
version: "1.0"
defaults:
  effect: deny
policies:
  - name: mfa_admin_access
    effect: allow
    description: >-
      Switch a user's OTP off. Grants nothing else: no password reset, no
      account edit. Deliberately NOT granted to `superuser`.
    resources: ["uri:/auth/mfa/*"]
    actions: ["mfa:disenroll"]
    subjects:
      groups: ["security_admin"]
    priority: 90
    enforcing: true
```

**Why exactly the spec text.** The policy name `mfa_admin_access` and the action
`mfa:disenroll` are the contract with TASK-142's `policy_allows()` call; a
rename on either side silently removes admin disenrolment (fail closed — safe,
but broken). `uri:/auth/mfa/*` covers `DELETE /auth/mfa/{user_id}`; unlike the
FEAT-105 packs there is no bare collection route to cover, so the `/*` suffix is
correct here. The header comment carries the R1 warning to whoever edits
`admin_full_access.yaml` next.

### `tests/test_mfa_policy_pack.py` — CREATE

```python
"""FEAT-106 Module 11 — the `mfa_admin_access` pack parses and stays exclusive.

Contract test between this YAML and TASK-142's admin_disenroll handler: if
either side renames the policy or the action, admin disenrolment silently dies,
because policy_allows() fails closed on a policy or action it cannot match.
"""
from pathlib import Path

import pytest

from navigator_auth.abac.storages.yaml_storage import YAMLStorage

POLICY_DIR = Path(__file__).resolve().parents[1] / "navigator_auth" / "abac" / "default_policies"
PACK = POLICY_DIR / "mfa_admin_access.yaml"
ADMIN_FULL = POLICY_DIR / "admin_full_access.yaml"

ACTION = "mfa:disenroll"
POLICY_NAME = "mfa_admin_access"


@pytest.fixture(scope="module")
def parsed():
    assert PACK.exists(), f"policy pack missing: {PACK}"
    return YAMLStorage._parse_file(PACK)


@pytest.fixture(scope="module")
def admin_full():
    return YAMLStorage._parse_file(ADMIN_FULL)


def test_policy_pack_parses(parsed):
    """The YAML parses and yields the action, group and effect (spec §4 M11)."""
    # FILL IN: exactly one policy; name == POLICY_NAME; actions == [ACTION];
    #  subjects["groups"] == ["security_admin"]; effect == "ALLOW";
    #  policy_type == "resource"; resources == ["uri:/auth/mfa/*"]


def test_priority_and_enforcing(parsed):
    # FILL IN: priority == 90; enforcing is True


def test_not_granted_to_superuser_or_admin(parsed):
    """Separation of duties (R1): neither superuser, admin nor a wildcard holds the action."""
    # FILL IN: no group in {"superuser", "admin", "*"}


def test_grants_nothing_but_disenroll(parsed):
    """The pack grants exactly one capability — no password reset, no account edit."""
    # FILL IN: set(actions) == {ACTION}; every action matches "object:verb" with object "mfa"


def test_admin_full_access_does_not_cover_mfa_disenroll(admin_full):
    """admin_full_access enumerates actions with no wildcard, so it cannot grant mfa:disenroll."""
    # FILL IN: for every policy in admin_full: ACTION not in actions, and no action
    #  equals "*" or "mfa:*" or ends with ":*" (any object-wildcard would be a
    #  latent collapse of the separation if a future object were named "mfa")
```

**Why the `admin_full_access` assertion lives here.** The exclusivity of
`mfa:disenroll` is a property of *two* files. The FEAT-105 test only checks its
own pack; without this assertion, someone "simplifying" `admin_full_access.yaml`
to `actions: ["*"]` would hand every superuser the R1 takeover chain and no test
would notice.

### Steps (in order)

1. Create the YAML verbatim (keep the header comment).
2. `python -c "from pathlib import Path; from navigator_auth.abac.storages.yaml_storage import YAMLStorage; print(YAMLStorage._parse_file(Path('navigator_auth/abac/default_policies/mfa_admin_access.yaml')))"`
   and check the dict matches the shape above (note `effect == "ALLOW"`).
3. Write the test; fill the five bodies.
4. Run the new test and the FEAT-105 pack test (regression; it must be unaffected).
5. `ruff check tests/test_mfa_policy_pack.py`.

### FILL IN checklist

- [ ] `test_policy_pack_parses` — name, action, group, effect, type, resource
- [ ] `test_priority_and_enforcing`
- [ ] `test_not_granted_to_superuser_or_admin`
- [ ] `test_grants_nothing_but_disenroll`
- [ ] `test_admin_full_access_does_not_cover_mfa_disenroll`

---

## Acceptance Criteria

- [ ] **AC-1** `navigator_auth/abac/default_policies/mfa_admin_access.yaml` declares one policy `mfa_admin_access`: `effect: allow`, `resources: ["uri:/auth/mfa/*"]`, `actions: ["mfa:disenroll"]`, `subjects.groups: ["security_admin"]`, `priority: 90`, `enforcing: true`, with `defaults.effect: deny`.
- [ ] **AC-2** `YAMLStorage._parse_file` parses it into one `policy_type="resource"` policy with `effect == "ALLOW"`.
- [ ] **AC-3** No group in the pack is `superuser`, `admin` or `*`; the pack grants no action other than `mfa:disenroll`.
- [ ] **AC-4** `admin_full_access.yaml` contains neither `mfa:disenroll` nor any `*` / `<object>:*` action (pinned by a test).
- [ ] **AC-5** No Python file under `navigator_auth/` is created or modified; `admin_full_access.yaml` is unchanged.
- [ ] **AC-6** `pytest tests/test_mfa_policy_pack.py tests/unit/handlers/test_auth_model_policy_pack.py -v` passes; `ruff check tests/test_mfa_policy_pack.py` clean.
- [ ] **AC-7** Covers spec §4 `test_policy_pack_parses` and the policy half of spec **AC16** (the handler half — denial of a plain superuser — is TASK-142).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_policy_pack.py tests/unit/handlers/test_auth_model_policy_pack.py -v
ruff check tests/test_mfa_policy_pack.py
```

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §3 Module 11,
   §6 Key constants and facts (`admin_full_access.yaml`, `policy_allows()`),
   §7 R1, §8 resolved question on `mfa:disenroll`.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint; configuration and test only.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-145-mfa-abac-policy-pack.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
