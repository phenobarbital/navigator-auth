# TASK-120: Default ABAC policy pack — `auth_model_admin_access.yaml`

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 7**. The guard's superuser path (spec §2 Overview
layer 2) consults a **named** ABAC policy per surface. This task ships the
three policies in the default pack so a stock deployment behaves correctly
once an operator copies the pack into `POLICY_STORAGE_DIR`.

**Why this is configuration and not code, and why that is safe.** The guard
denies when a policy is absent (`policy_allows()` fails closed — TASK-119).
So a missing or malformed pack can only ever *remove* superuser access; it
can never grant anything. That asymmetry is what lets this task land in
parallel with everything else: nothing depends on it, and nothing breaks
without it.

**Why it still has to be right.** Without these three policies the admin
path of all three surfaces is dead — a superuser cannot read, revoke or
delete a foreign row at all (spec §5 criterion 5 fails). So the policy
names, the action strings and the `subjects.groups` must match exactly what
the handlers declare in TASK-122..TASK-126.

---

## Scope

- Create
  `navigator_auth/abac/default_policies/auth_model_admin_access.yaml` with
  the three policies `user_identities_admin_access`,
  `user_accounts_admin_access` and `partner_keys_admin_access`, verbatim
  from spec §3 Module 7.
- Create `tests/unit/handlers/test_auth_model_policy_pack.py` asserting the
  file parses through `YAMLStorage._parse_file()` and yields those three
  policies with the right actions, subjects and effect.
- Create `tests/unit/handlers/__init__.py` **if absent** (see the
  parallel-task note).

**NOT in scope**:
- Any Python change. No handler, no decorator, no loader. In particular do
  **not** add code that reads `navigator_auth/abac/default_policies/` — see
  "Does NOT Exist" below.
- Copying the pack into `POLICY_STORAGE_DIR`, or changing
  `navigator_auth/conf.py`. That is an operator action.
- Editing any existing policy file in `default_policies/`, including
  `admin_full_access.yaml` (which already grants `uri:*` to `superuser` at
  `priority: 100` — see the interaction note).
- Changing the `pyproject.toml` package-data configuration to ship the new
  YAML in the wheel. The six existing files in that directory are already
  covered by whatever the build does today; this task adds a seventh file to
  the same directory and changes nothing about packaging.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/default_policies/auth_model_admin_access.yaml` | CREATE | The three named policies |
| `tests/unit/handlers/__init__.py` | CREATE | New test package (empty; may already exist) |
| `tests/unit/handlers/test_auth_model_policy_pack.py` | CREATE | Parse + content assertions |

---

## Codebase Contract

> Every fact below was re-verified on `dev` @ `62fd419` (2026-10-23).

### `YAMLStorage._parse_file` — the parser this file must satisfy

Verified: `navigator_auth/abac/storages/yaml_storage.py:104-105` — it is a
**`@staticmethod`**, so the test can call it directly with a `Path` and needs
no storage instance:

```python
    @staticmethod
    def _parse_file(path: Path) -> list[dict]:
```

Verified behaviour (`yaml_storage.py:122-175`):

- `default_effect = data.get('defaults', {}).get('effect', 'deny')`
- per policy: `effect = 'ALLOW' if effect_str.lower() == 'allow' else 'DENY'`
  — so the emitted dict's `effect` is the **upper-case string** `'ALLOW'`,
  not the YAML's `allow` and not a `PolicyEffect`.
- `policy_type = policy_data.get('policy_type', 'resource')` — the default
  is `resource`, which is the branch this pack must use.
- the `resource` branch emits exactly these keys:
  `name`, `policy_type`, `effect`, `description`, `resources` (plural),
  `actions`, `subjects` (the structured dict, passed through unchanged),
  `conditions` (from `conditions.context`), `environment` (from
  `conditions.environment`), `priority` (default `0`), `enforcing`
  (default `False`).
- **a policy that raises while parsing is logged and skipped**
  (`yaml_storage.py:170-175`: `except Exception: logger.error(...); continue`).
  A typo therefore yields *fewer* policies rather than an error — which is
  why the test must assert the **count is 3** and not merely that each name
  it looks for is present.

### Existing pack files — the format to copy

Verified `navigator_auth/abac/default_policies/` contains six files:
`admin_full_access.yaml`, `business_hours_only.yaml`,
`deny_after_hours.yaml`, `engineering_tools.yaml`, `mcp_services.yaml`,
`readonly_agents.yaml`.

`admin_full_access.yaml` in full (verified, 695 bytes):

```yaml
version: "1.0"
defaults:
  effect: deny
policies:
  - name: admin_full_access
    effect: allow
    description: "Superuser and admin groups have unrestricted access to all resources at all times."
    resources:
      - "tool:*"
      - "kb:*"
      ...
      - "uri:*"
    actions:
      - "tool:execute"
      ...
    subjects:
      groups:
        - superuser
        - admin
    priority: 100
    enforcing: true
```

`engineering_tools.yaml` (verified) proves **multiple policies in one file**
is the established pattern — it declares `engineering_tools` and
`engineering_kb_access` under a single `policies:` list.

### Interaction with `admin_full_access.yaml` (do not "fix" it)

`admin_full_access.yaml` already grants `uri:*` to groups `superuser` and
`admin` at `priority: 100`, but its `actions` list does **not** contain any
of this feature's `identity:*` / `account:*` / `partner:*` actions (verified:
the file's actions are `tool:*`, `kb:*`, `vector:*`, `agent:*` only). Since
the guard calls `policy_allows(self.policy_name, ...)` **by name** — not "any
policy that covers this URI" — `admin_full_access` is never consulted by this
feature at all. Leave it alone. Do not add this feature's actions to it, and
do not lower its priority.

### `ResourceType` — why `uri:` is the correct prefix

Verified `navigator_auth/abac/policies/resources.py:15-30`, the enum members
are: `TOOL, KB, VECTOR, AGENT, MCP, URI, DATASET, WIDGET, CARD, SLUG,
DATASOURCE, DRIVER, RAW_QUERY`. There is no `IDENTITY`, `MODEL` or `PARTNER`
member, and spec §1 Non-Goals rules out adding one. `uri:` is also what
`admin_full_access.yaml` already uses for HTTP surfaces.

### `SubjectSpec` — the `subjects` block's contract

Verified `navigator_auth/abac/policies/resources.py:128`: fields
`groups / users / roles / exclude_groups / exclude_users`, a `from_dict`
constructor and `matches_user(username, user_groups, user_roles)`.
**`'*'` in `groups` matches any authenticated user** — so `groups: ["*"]`
would hand every logged-in user cross-user access. Use the literal
`superuser` and nothing else.

### The routes these policies name (verified: `navigator_auth/handlers/__init__.py`)

| Surface | Routes | Lines |
|---|---|---|
| identities | `r"/api/v1/user_identity/{id:.*}"`, `r"/api/v1/user_identity{meta:\:?.*}"` | `:58-65` |
| accounts | `r"/api/v1/user_accounts/{id:.*}"`, `r"/api/v1/user_accounts{meta:\:?.*}"` | `:39-46` |
| partner keys | `r"/api/v1/partner/tokens/{id:.*}"`, `r"/api/v1/partner/tokens{meta:\:?.*}"` | `:48-56` |

### The action strings the handlers will declare (spec §3 Modules 4/5/6)

These must match this pack **exactly**, character for character:

| Policy | `superuser_actions` on the handler |
|---|---|
| `user_identities_admin_access` | `identity:read`, `identity:revoke`, `identity:delete` |
| `user_accounts_admin_access` | `account:read`, `account:revoke`, `account:delete` |
| `partner_keys_admin_access` | `partner:read`, `partner:create`, `partner:revoke`, `partner:delete` |

Note `partner_keys_admin_access` has **four** actions — it is the only one
with a `:create`, because partner keys have no owner, so even creation is a
superuser-only act (spec G8).

### `ActionKey` — why every action must contain exactly one colon

Verified `navigator_auth/abac/policies/abstract.py:26-28`:

```python
class ActionKey:
    def __init__(self, action: str):
        self.object, self.action = action.split(':', 1)
```

An action with no colon raises `ValueError` on unpacking. Every action
string in this pack is `<object>:<verb>`; keep it that way.

### Does NOT Exist (do not reference)

- `navigator_auth/abac/default_policies/auth_model_admin_access.yaml` —
  **this task creates it**.
- **Any Python file that reads `default_policies/`.** Verified: no module
  references that directory. It is a pack an operator copies into
  `POLICY_STORAGE_DIR` (`navigator_auth/conf.py:705`, default
  `BASE_DIR / "env" / "policies"`). Do **not** add a loader, an
  `__init__.py`, an import hook or a `conf.py` default that points at it —
  the guard must keep working when the policy is absent, and wiring an
  auto-loader would quietly change that contract for every existing pack
  file too.
- A `policy_type: resource` line in the existing pack files — none of them
  sets it, because `resource` is the default. Do not add it here either;
  match the house format.
- `tests/unit/handlers/` — a new package. `tests/unit/identity/__init__.py`
  and `tests/unit/middlewares/__init__.py` are the pattern.
- `YAMLStorage.load_policies` / `.get_policies` as a test entry point — the
  `@staticmethod _parse_file(path)` is the testable unit and the one spec §4
  names. Instantiating a storage would pull in `POLICY_STORAGE_DIR` and the
  PDP.
- A `ResourceType.IDENTITY` / `.MODEL` / `.PARTNER` enum member — see above.
- `subjects.groups: ["*"]` or `["superuser", "admin"]`. Spec G2 and the §8
  Q7 decision name the `superuser` group alone. `admin` is deliberately not
  granted cross-user access to credentials.

---

## Implementation Blueprint

### `navigator_auth/abac/default_policies/auth_model_admin_access.yaml` — CREATE

Spec §3 Module 7 fixes this file's content. Write it as given:

```yaml
version: "1.0"
defaults:
  effect: deny
policies:
  - name: user_identities_admin_access
    effect: allow
    description: >-
      Superusers may read (redacted), revoke and delete other users' linked
      identities. Never grants token material: redaction is enforced in code.
    resources: ["uri:/api/v1/user_identity*"]
    actions: ["identity:read", "identity:revoke", "identity:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true

  - name: user_accounts_admin_access
    effect: allow
    description: >-
      Superusers may read, revoke and delete other users' social accounts.
    resources: ["uri:/api/v1/user_accounts*"]
    actions: ["account:read", "account:revoke", "account:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true

  - name: partner_keys_admin_access
    effect: allow
    description: >-
      Partner keys have no owner: only superusers may manage them. The signed
      token is returned once at creation and never on a read.
    resources: ["uri:/api/v1/partner/tokens*"]
    actions:
      ["partner:read", "partner:create", "partner:revoke", "partner:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true
```

**Why `priority: 90` and not 100.** `admin_full_access.yaml` sits at 100.
Keeping this pack just below it means that if an operator ever *does* widen
`admin_full_access` to cover these actions, the broader grant wins
deterministically rather than racing on equal priority. 90 also leaves room
above for a site-specific override.

**Why `enforcing: true`.** `_parse_file` defaults `enforcing` to `False`
(`yaml_storage.py:166`). A non-enforcing policy is advisory, which for an
access grant means it may be evaluated and then ignored — the superuser path
would be dead with no error anywhere. Set it explicitly on all three.

**Why `effect: deny` under `defaults` when all three policies say
`effect: allow`.** `defaults.effect` is the fallback for a policy that omits
`effect` (`yaml_storage.py:126,129`). Declaring `deny` there means a future
policy appended to this file without an explicit effect denies instead of
granting. Every existing pack file does the same; match them.

**Why the resources use a trailing `*` and no `/`.** The routes are
`/api/v1/user_identity/{id:.*}` **and** `/api/v1/user_identity{meta:\:?.*}`
(`handlers/__init__.py:58-65`) — the second has no slash before the suffix,
so `uri:/api/v1/user_identity/*` would miss `/api/v1/user_identity:meta`.
`uri:/api/v1/user_identity*` covers both. Same for the other two surfaces.

**Why `>-` for the descriptions.** Folded block scalars with the chomping
indicator keep the lines under the project's width without embedding a
newline in the description string. `admin_full_access.yaml` uses a single
long quoted line instead; either parses, but `>-` is what spec §3 Module 7
specifies and it keeps the file readable.

### `tests/unit/handlers/__init__.py` — CREATE

```python
# empty — marks tests/unit/handlers as a package, like
# tests/unit/identity/__init__.py and tests/unit/middlewares/__init__.py
```

**Why this may already exist.** TASK-118 is `parallel: true` alongside this
task and also writes into `tests/unit/handlers/`. Both create this file with
identical (empty) content, so a concurrent create is harmless. Create it if
absent; if it is already there, leave it exactly as it is.

### `tests/unit/handlers/test_auth_model_policy_pack.py` — CREATE

```python
"""The FEAT-105 default policy pack parses and declares what the guards expect.

Spec §4 row `test_policy_pack_parses`. This is a contract test between a YAML
file and three handler classes: if either side renames a policy or an action,
the superuser path silently dies, because `policy_allows()` fails closed on a
policy it cannot find by name.
"""
from pathlib import Path

import pytest

from navigator_auth.abac.storages.yaml_storage import YAMLStorage

PACK = (
    Path(__file__).resolve().parents[3]
    / "navigator_auth"
    / "abac"
    / "default_policies"
    / "auth_model_admin_access.yaml"
)

EXPECTED_ACTIONS = {
    "user_identities_admin_access": {
        "identity:read", "identity:revoke", "identity:delete",
    },
    "user_accounts_admin_access": {
        "account:read", "account:revoke", "account:delete",
    },
    "partner_keys_admin_access": {
        "partner:read", "partner:create", "partner:revoke", "partner:delete",
    },
}


@pytest.fixture(scope="module")
def parsed():
    """The pack as `_parse_file` sees it (a list of policy dicts)."""
    # FILL IN: assert PACK.exists() with a message naming the path, then
    # return YAMLStorage._parse_file(PACK) — bounded by AC-1.


class TestPolicyPack:
    def test_all_three_policies_parse(self, parsed):
        """Exactly three policies, no silently-skipped one."""
        # FILL IN: assert len(parsed) == 3 and the name set equals
        # EXPECTED_ACTIONS.keys(). The length assertion is the point: a
        # malformed policy is logged and skipped, not raised
        # (yaml_storage.py:170-175) — bounded by AC-1, AC-2.

    def test_actions_match_the_handler_contract(self, parsed):
        """Action strings agree with the handlers' `superuser_actions`."""
        # FILL IN: for each policy, set(p["actions"]) == EXPECTED_ACTIONS[name]
        # — bounded by AC-3.

    def test_every_action_is_object_colon_verb(self, parsed):
        """Each action survives `ActionKey`'s split(':', 1)."""
        # FILL IN: for every action string, assert it contains exactly one ':'
        # and that neither half is empty — bounded by AC-4.

    def test_subjects_grant_superuser_only(self, parsed):
        """`subjects.groups == ["superuser"]` — no wildcard, no `admin`."""
        # FILL IN: for each policy, p["subjects"]["groups"] == ["superuser"];
        # assert "*" not in that list and "admin" not in it — bounded by AC-5.

    def test_effect_and_enforcing(self, parsed):
        """All three are enforcing ALLOW policies at priority 90."""
        # FILL IN: p["effect"] == "ALLOW" (upper-case: yaml_storage.py:126),
        # p["enforcing"] is True, p["priority"] == 90 — bounded by AC-6.

    def test_resources_cover_both_route_shapes(self, parsed):
        """The `uri:` pattern matches the `/{id}` and the `{meta}` route."""
        # FILL IN: assert each policy's single resource is the expected
        # "uri:/api/v1/<surface>*" string and that it does NOT end in "/*"
        # — bounded by AC-7.

    def test_policy_type_defaults_to_resource(self, parsed):
        """The pack uses the structured `resources`/`subjects` branch."""
        # FILL IN: p["policy_type"] == "resource" and "resources" in p
        # (plural) — bounded by AC-8.
```

**Why `test_all_three_policies_parse` asserts a count.**
`_parse_file` catches `Exception` per policy and `continue`s
(`yaml_storage.py:170-175`), so a typo in one policy produces a shorter list
and a log line nobody reads. A test that only looked up the names it cares
about would pass with two of three policies silently dropped. Assert the
length first.

**Why `test_every_action_is_object_colon_verb` exists.** `ActionKey`
(`abac/policies/abstract.py:26-28`) does `action.split(':', 1)` into exactly
two names. An action like `identityread` raises `ValueError` deep inside
policy evaluation, where `_check_policies` turns it into a generic deny —
indistinguishable from "the superuser is not allowed". Catch it here.

**Why `test_resources_cover_both_route_shapes` checks for the absence of
`/*`.** `uri:/api/v1/user_identity/*` looks more correct and is wrong: it
cannot match `/api/v1/user_identity:meta`, whose route
(`handlers/__init__.py:63`) has no slash. Pin the intent so nobody
"tidies" it later.

**Why the path is computed with `parents[3]`.** The test file is at
`tests/unit/handlers/test_auth_model_policy_pack.py`, so
`parents[0] = handlers`, `[1] = unit`, `[2] = tests`, `[3] = repo root`.
Verify this resolves before filling the rest — if the file is moved, this is
the one line that must change.

### Steps (in order)

1. Create the YAML file, content verbatim from the blueprint. Nothing to
   decide here — spec §3 Module 7 fixes it.
2. Create `tests/unit/handlers/__init__.py` **if it does not already exist**.
3. Create the test module and fill the fixture plus the seven bodies. Fill
   the `parsed` fixture first and run it alone — if the path is wrong every
   other test fails for the same uninformative reason.
4. Run `pytest tests/unit/handlers/test_auth_model_policy_pack.py -v`.
5. `ruff check tests/unit/handlers/`. (The YAML needs no lint; if the repo
   has a YAML linter configured, run it, otherwise skip.)
6. Confirm the blast radius: `git diff --name-only` plus
   `git status --porcelain` must show only the three files above. In
   particular **no** `.py` file under `navigator_auth/` and no other file in
   `default_policies/`.

### FILL IN checklist

- [ ] `parsed` fixture — existence assertion + `_parse_file(PACK)` — AC-1
- [ ] `test_all_three_policies_parse` — count is 3, names match — AC-1, AC-2
- [ ] `test_actions_match_the_handler_contract` — AC-3
- [ ] `test_every_action_is_object_colon_verb` — AC-4
- [ ] `test_subjects_grant_superuser_only` — AC-5
- [ ] `test_effect_and_enforcing` — AC-6
- [ ] `test_resources_cover_both_route_shapes` — AC-7
- [ ] `test_policy_type_defaults_to_resource` — AC-8

---

## Acceptance Criteria

- [ ] **AC-1** `YAMLStorage._parse_file(Path("navigator_auth/abac/default_policies/auth_model_admin_access.yaml"))` returns a list of length **3** with no exception.
- [ ] **AC-2** The three names are exactly `user_identities_admin_access`, `user_accounts_admin_access`, `partner_keys_admin_access`.
- [ ] **AC-3** The action sets match the handler contract table above, including `partner:create` on the partner policy only.
- [ ] **AC-4** Every action string contains exactly one `:` with a non-empty name on each side (survives `ActionKey`).
- [ ] **AC-5** Each policy's `subjects["groups"] == ["superuser"]` — no `"*"`, no `"admin"`.
- [ ] **AC-6** Each parsed policy has `effect == "ALLOW"`, `enforcing is True`, `priority == 90`.
- [ ] **AC-7** Each policy declares a single resource of the form `uri:/api/v1/<surface>*`, not ending in `/*`.
- [ ] **AC-8** Each parsed policy has `policy_type == "resource"` and the plural `resources` key.
- [ ] **AC-9** `pytest tests/unit/handlers/test_auth_model_policy_pack.py -v` passes and `ruff check tests/unit/handlers/` is clean.
- [ ] **AC-10** No `.py` file under `navigator_auth/` is created or modified, and no existing file in `default_policies/` is touched.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_auth_model_policy_pack.py -v
ruff check tests/unit/handlers/
```

```python
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
YAMLStorage._parse_file(PACK)   # staticmethod — no instance needed
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §3 Module 7 (the file content), §1 G2/G8, §4 row `test_policy_pack_parses`.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. Add no Python under `navigator_auth/`.
5. **Verify** every acceptance criterion, AC-10 included.
6. **Move this file** to `sdd/tasks/completed/TASK-120-auth-model-policy-pack.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
