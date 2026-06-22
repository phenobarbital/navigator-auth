# Feature Specification: Policy-Based Access Control

**Feature ID**: FEAT-001
**Date**: 2026-04-01
**Author**: Jesus Lara
**Status**: draft
**Target version**: 1.0.0

---

## 1. Motivation & Business Requirements

### Problem Statement

navigator-auth already has a working ABAC/PBAC skeleton (PDP, PEP/Guardian, policies, evaluator, decorators) but several gaps prevent production deployment:

1. **Environment model is limited** — uses `datamodel.Model`, lacks day-segment awareness (morning/afternoon/night), business-hours support, and configurable work schedule.
2. **No YAML policy storage** — policies can only be loaded from PostgreSQL or created programmatically; there is no file-based YAML storage that can be shipped with a deployment.
3. **Decorator gaps** — `requires_permission` in `abac/decorators.py` uses `_apply_decorator` from the main decorators module but the class-based view path needs verification and hardening.
4. **No high-performance native modules** — the evaluator and resource filter run in pure Python; for large policy/resource sets (hundreds of tools, MCP services, agents) a Rust/Cython PEP module would provide 10-100x speedup.
5. **No ready-to-use policy pack** — every deployment must author policies from scratch.

### Goals

- G1: Migrate `Environment` to Pydantic `BaseModel` with day-segment, business-hours, and configurable schedule.
- G2: Support YAML policy definitions alongside JSON and programmatic creation.
- G3: Implement a YAML-based `PolicyStorage` that reads from `POLICY_STORAGE_DIR` (default: `BASE_DIR/env/policies/`).
- G4: Verify and harden ABAC decorators for class-based views.
- G5: Create a Rust-based PEP module for batch resource filtering.
- G6: Create a Cython or Rust module for fast resource evaluation.
- G7: Ship a set of ready-to-use policy templates for common scenarios.
- G8: Expose a REST endpoint: `POST /api/v1/abac/check` — given user + resource, return PBAC decision.

### Non-Goals (explicitly out of scope)

- Replacing the PostgreSQL storage backend (it stays as-is).
- Implementing a policy admin UI.
- Multi-tenant policy isolation (org_id/client_id scoping is existing and unchanged).
- RBAC migration — ABAC/PBAC complements existing RBAC, does not replace it.

---

## 2. Architectural Design

### Overview

The solution extends the existing ABAC/PBAC architecture along four axes:

1. **Model layer** — richer `Environment` with Pydantic.
2. **Storage layer** — new `YAMLStorage` alongside existing `pgStorage`.
3. **Performance layer** — Rust extension for batch PEP evaluation, Cython for fast resource matching.
4. **Deployment layer** — ready-to-use policy YAML files and REST check endpoint.

### Component Diagram

```
                    ┌──────────────────────────┐
                    │   navigator_auth.conf    │
                    │  (business_hours config)  │
                    └────────────┬─────────────┘
                                 │
  YAML files ──→ YAMLStorage ───┤
  PostgreSQL ──→ pgStorage   ───┤
  Code       ──→ add_policy  ───┤
                                 ▼
                    ┌──────────────────────────┐
                    │    PDP (pdp.py)           │
                    │  ┌────────────────────┐   │
                    │  │ PolicyEvaluator    │   │
                    │  │  (Python + cache)  │   │
                    │  └────────┬───────────┘   │
                    │           │               │
                    │  ┌────────▼───────────┐   │
                    │  │ RustPEP (native)   │   │  ← Rust batch filter
                    │  │ CythonEval (fast)  │   │  ← Cython fast eval
                    │  └────────────────────┘   │
                    └──────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
         Guardian          Middleware       REST /check
         (PEP)           (abac_middleware)   endpoint
              │                │                 │
              ▼                ▼                 ▼
         Decorators       Request pipeline   API response
     (@requires_permission,                  {allowed, reason}
      @groups_protected)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `Environment` (datamodel.Model) | **replaces** | Migrate to Pydantic BaseModel |
| `AbstractStorage` | **extends** | New `YAMLStorage` subclass |
| `PolicyEvaluator` | **enhances** | Delegate batch filter to Rust module |
| `PolicyLoader` (evaluator.py) | **refactors** | Extract to standalone, add YAML schema validation |
| `PDP.pdp` | **enhances** | Load from YAML storage on startup |
| `PEP` (policyhandler.py) | **extends** | Add `/check` endpoint |
| `abac/decorators.py` | **hardens** | CBV support verification |
| `navigator_auth/decorators.py` (`_apply_decorator`) | **uses** | Existing CBV/function dispatcher |
| `setup.py` (Cython extensions) | **extends** | Add new `.pyx` for fast eval |
| Cargo.toml / PyO3 | **creates** | New Rust extension module |

### Data Models

```python
from pydantic import BaseModel, Field
from datetime import datetime, date, time
from enum import Enum
from typing import Optional

class DaySegment(str, Enum):
    MORNING = "morning"      # configurable, default 06:00-12:00
    AFTERNOON = "afternoon"  # configurable, default 12:00-18:00
    EVENING = "evening"      # configurable, default 18:00-22:00
    NIGHT = "night"          # configurable, default 22:00-06:00

class Environment(BaseModel):
    """Rich environment context for PBAC evaluation."""
    time: float = Field(default_factory=time.time)
    timestamp: datetime = Field(default_factory=datetime.now)
    dow: int = 0              # 0=Monday, 6=Sunday
    day_of_week: int = 0
    hour: int = 0
    minute: int = 0
    date: date = Field(default_factory=date.today)
    day_segment: DaySegment = DaySegment.MORNING
    is_business_hours: bool = False
    is_weekend: bool = False
    timezone: str = "UTC"

    def model_post_init(self, __context):
        self.hour = self.timestamp.hour
        self.minute = self.timestamp.minute
        self.dow = self.timestamp.weekday()
        self.day_of_week = self.dow
        self.date = self.timestamp.date()
        self.is_weekend = self.dow >= 5
        self.day_segment = self._compute_segment()
        self.is_business_hours = self._compute_business_hours()

    def _compute_segment(self) -> DaySegment:
        # Uses configurable boundaries from navigator_auth.conf
        ...

    def _compute_business_hours(self) -> bool:
        # Reads BUSINESS_HOURS_START / BUSINESS_HOURS_END from config
        ...
```

```yaml
# YAML Policy Schema Example
version: "1.0"
defaults:
  effect: deny
policies:
  - name: engineering_tools
    effect: allow
    description: "Engineering team can use all dev tools during business hours"
    resources:
      - "tool:jira_*"
      - "tool:github_*"
      - "tool:confluence_*"
    actions:
      - "tool:execute"
      - "tool:list"
    subjects:
      groups: ["engineering", "devops"]
    conditions:
      environment:
        is_business_hours: true
    priority: 10
```

### New Public Interfaces

```python
# YAML Storage
class YAMLStorage(AbstractStorage):
    """Load policies from YAML files in a directory."""
    async def load_policies(self) -> list[dict]: ...
    async def save_policy(self, policy: dict) -> None: ...
    async def reload(self) -> list[dict]: ...

# REST Check endpoint
# POST /api/v1/abac/check
# Body: {"user": "jlara@trocglobal.com", "resource": "tool:jira_create", "action": "tool:execute"}
# Response: {"allowed": true, "effect": "ALLOW", "policy": "engineering_tools", "reason": "..."}

# Rust PEP module (exposed via PyO3)
def filter_resources_batch(
    policies_json: str,         # serialized policies
    resources: list[str],       # resources to filter
    user_context: dict,         # user info
    environment: dict           # current environment
) -> dict:                      # {"allowed": [...], "denied": [...]}
    ...
```

---

## 3. Module Breakdown

### Module 1: Environment Migration
- **Path**: `navigator_auth/abac/policies/environment.py`
- **Responsibility**: Migrate `Environment` from `datamodel.Model` to Pydantic `BaseModel`. Add `DaySegment` enum, `is_business_hours`, `is_weekend`, `minute`, `timezone`. Read business-hours config from `navigator_auth.conf` via `navconfig`.
- **Depends on**: navconfig, pydantic

### Module 2: YAML Policy Storage
- **Path**: `navigator_auth/abac/storages/yaml_storage.py`
- **Responsibility**: Implement `YAMLStorage(AbstractStorage)` that scans `POLICY_STORAGE_DIR` for `.yaml`/`.yml` files, parses them into policy dicts compatible with PDP loading. Support hot-reload. Consolidate with `PolicyLoader` from `evaluator.py` to avoid duplication.
- **Depends on**: Module 1, AbstractStorage

### Module 3: PDP YAML Integration
- **Path**: `navigator_auth/abac/pdp.py`
- **Responsibility**: Extend PDP startup to optionally load from `YAMLStorage` in addition to DB storage. Add `POLICY_STORAGE_DIR` config. Support mixed sources (DB + YAML).
- **Depends on**: Module 2

### Module 4: Decorator Hardening
- **Path**: `navigator_auth/abac/decorators.py`
- **Responsibility**: Verify `groups_protected` and `requires_permission` work correctly with `aiohttp.web.View` class-based views. Add test coverage for CBV handlers. Align with `_apply_decorator` from `navigator_auth/decorators.py` patterns used by `@is_authenticated`, `@allowed_groups`, etc.
- **Depends on**: None (independent)

### Module 5: Rust PEP Batch Filter
- **Path**: `src/lib.rs` (new module in existing Rust crate, or new crate)
- **Responsibility**: PyO3 module exposing `filter_resources_batch()` — takes serialized policies + resource list + user context, returns allowed/denied split. Optimized with parallel iteration, compiled pattern matching, and zero-copy where possible.
- **Depends on**: Module 1 (Environment schema for condition evaluation)

### Module 6: Cython Fast Resource Evaluator
- **Path**: `navigator_auth/libs/policy_eval.pyx`
- **Responsibility**: Cython-accelerated resource pattern matching and condition evaluation. Used by `PolicyEvaluator` when available, with pure-Python fallback.
- **Depends on**: Module 1

### Module 7: Ready-to-Use Policy Pack
- **Path**: `navigator_auth/abac/default_policies/`
- **Responsibility**: Ship YAML policy templates:
  - `admin_full_access.yaml` — superuser/admin unrestricted access
  - `business_hours_only.yaml` — restrict all access to business hours
  - `engineering_tools.yaml` — engineering team tool access
  - `readonly_agents.yaml` — read-only access to agents/bots
  - `mcp_services.yaml` — MCP service access by role
  - `deny_after_hours.yaml` — deny sensitive operations outside business hours
- **Depends on**: Module 2 (YAML format), Module 1 (Environment fields)

### Module 8: REST Check Endpoint
- **Path**: `navigator_auth/abac/policyhandler.py`
- **Responsibility**: Add `POST /api/v1/abac/check` endpoint that accepts `{user, resource, action}` and returns the PBAC decision. This is the frontend-facing API for checking access without the full middleware flow.
- **Depends on**: Module 3 (PDP with loaded policies)

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_environment_pydantic` | Module 1 | Environment creates with correct defaults via Pydantic |
| `test_environment_day_segment` | Module 1 | Day segment computed correctly for each hour range |
| `test_environment_business_hours` | Module 1 | Business hours flag matches configured schedule |
| `test_environment_weekend` | Module 1 | Weekend detection for Saturday/Sunday |
| `test_yaml_storage_load` | Module 2 | Loads policies from YAML files |
| `test_yaml_storage_invalid` | Module 2 | Handles malformed YAML gracefully |
| `test_yaml_storage_reload` | Module 2 | Hot-reload picks up new/changed files |
| `test_pdp_mixed_sources` | Module 3 | PDP loads from both DB and YAML |
| `test_decorator_cbv` | Module 4 | `@groups_protected` works on View subclass |
| `test_decorator_requires_permission_cbv` | Module 4 | `@requires_permission` works on View methods |
| `test_rust_filter_batch` | Module 5 | Rust filter returns correct allowed/denied |
| `test_rust_filter_performance` | Module 5 | Batch filter faster than pure Python for 1000+ resources |
| `test_cython_pattern_match` | Module 6 | Cython glob matching equivalent to Python |
| `test_default_policies_valid` | Module 7 | All shipped YAML policies parse without error |
| `test_check_endpoint` | Module 8 | REST check returns correct decisions |

### Integration Tests

| Test | Description |
|---|---|
| `test_e2e_yaml_policy_enforcement` | Load YAML policies → request → middleware enforces → correct response |
| `test_e2e_check_api` | POST to /check with user+resource → receives correct PBAC decision |
| `test_e2e_business_hours_deny` | Request outside business hours denied by time-based policy |
| `test_e2e_rust_filter_in_pdp` | PDP uses Rust module for batch filtering when available |

### Test Data / Fixtures

```python
@pytest.fixture
def sample_environment():
    """Environment fixed at Tuesday 10:30 AM."""
    from datetime import datetime
    return Environment(timestamp=datetime(2026, 4, 1, 10, 30))

@pytest.fixture
def sample_yaml_policy_dir(tmp_path):
    """Temp directory with sample YAML policy files."""
    policy = {
        "version": "1.0",
        "defaults": {"effect": "deny"},
        "policies": [{
            "name": "test_allow",
            "effect": "allow",
            "resources": ["tool:test_*"],
            "actions": ["tool:execute"],
            "subjects": {"groups": ["testers"]},
            "priority": 10
        }]
    }
    (tmp_path / "test.yaml").write_text(yaml.dump(policy))
    return tmp_path

@pytest.fixture
def sample_eval_context():
    """EvalContext with test user in engineering group."""
    return EvalContext(
        userinfo={"username": "testuser", "groups": ["engineering"], "roles": ["developer"]}
    )
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `Environment` uses Pydantic `BaseModel` with `day_segment`, `is_business_hours`, `is_weekend`, `minute`, `timezone` fields
- [ ] Business hours are configurable via `navigator_auth.conf` (`BUSINESS_HOURS_START`, `BUSINESS_HOURS_END`, `BUSINESS_DAYS`)
- [ ] Policies can be defined in YAML files and loaded by PDP at startup
- [ ] `POLICY_STORAGE_DIR` config controls YAML policy directory (default: `BASE_DIR/env/policies/`)
- [ ] PDP supports mixed loading: DB + YAML sources
- [ ] `@groups_protected` and `@requires_permission` work with class-based views (verified by tests)
- [ ] Rust PEP module compiles and passes `filter_resources_batch` tests
- [ ] Cython fast evaluator provides measurable speedup over pure Python
- [ ] At least 6 ready-to-use policy YAML templates are shipped
- [ ] `POST /api/v1/abac/check` endpoint returns `{allowed, effect, policy, reason}`
- [ ] All unit tests pass (`pytest tests/ -v -k policy`)
- [ ] No breaking changes to existing `Policy`, `PDP`, `Guardian` public APIs
- [ ] Existing tests in `tests/test_policy*.py` continue to pass

---

## 6. Implementation Notes & Constraints

### Patterns to Follow

- Use existing `AbstractStorage` interface for `YAMLStorage`
- Follow async-first design — storage `load_policies()` is already `async`
- Pydantic `model_post_init` for computed fields in `Environment`
- PyO3 `#[pyfunction]` for Rust module, matching existing project patterns
- Cython `.pyx` files added to `setup.py` extensions list

### Configuration Keys (navigator_auth.conf / navconfig)

| Key | Default | Description |
|---|---|---|
| `BUSINESS_HOURS_START` | `"08:00"` | Start of business hours (HH:MM) |
| `BUSINESS_HOURS_END` | `"18:00"` | End of business hours (HH:MM) |
| `BUSINESS_DAYS` | `"1,2,3,4,5"` | ISO weekdays (1=Mon, 7=Sun) |
| `POLICY_STORAGE_DIR` | `BASE_DIR/env/policies` | Directory for YAML policy files |
| `DAY_SEGMENT_MORNING` | `"06:00-12:00"` | Morning segment range |
| `DAY_SEGMENT_AFTERNOON` | `"12:00-18:00"` | Afternoon segment range |
| `DAY_SEGMENT_EVENING` | `"18:00-22:00"` | Evening segment range |

### Known Risks / Gotchas

- **Environment migration** — any code that uses `Environment` as a `datamodel.Model` (e.g., dict-like access) may break. Audit all call sites.
- **YAML parsing** — initial implementation uses Python `yaml` library; the Rust `yaml-rs` integration comes in Module 5 as part of the Rust crate, not as a standalone change.
- **Cython build** — ensure `policy_eval.pyx` is added to `setup.py` ext_modules and that CI builds it.
- **Rust module optional** — the Rust PEP module must be optional (graceful fallback to Python if not compiled). Use `try: from navigator_auth._rust import ...` pattern.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| `pydantic` | `>=2.12.5` | Already in pyproject.toml, used for Environment |
| `PyYAML` | `>=6.0` | YAML parsing (already indirect dependency) |
| `PyO3` | `>=0.21` | Rust-Python binding for PEP module |
| `maturin` | `>=1.0` | Rust build backend |

---

## 7. Open Questions

- [ ] Should YAML policies override DB policies at the same priority, or should DB always win? — *Owner: Jesus Lara*
- [ ] Should the Rust PEP module use `serde` for policy deserialization or receive pre-parsed dicts from Python? — *Owner: Jesus Lara*
- [ ] Should `Environment.timezone` affect all time calculations or just be informational? — *Owner: Jesus Lara*
- [ ] Should the `/api/v1/abac/check` endpoint require authentication or support anonymous checks for frontend pre-flight? — *Owner: Jesus Lara*

---

## Worktree Strategy

- **Isolation unit**: `per-spec` (sequential tasks)
- All 8 modules share state (Environment changes cascade), so sequential execution in one worktree avoids merge conflicts.
- **Parallelizable exceptions**: Module 4 (decorator hardening) and Module 7 (policy pack) are independent and could run in parallel if needed.
- **Cross-feature dependencies**: None — this spec is self-contained within navigator-auth.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-04-01 | Jesus Lara | Initial draft |
