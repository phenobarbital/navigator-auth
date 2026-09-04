# TASK-054: pysaml2 dependency swap, SAML config keys, redirect-validator promotion, xmlsec1 in CI

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 1)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Foundation for FEAT-097. Swaps the SAML engine dependency, front-loads every configuration
key both roles will read (so later tasks never conflict on `conf.py`), and promotes the
host-checked redirect validator from `ADFSAuth` into `BaseAuthBackend` so the SAML SP and IdP
bases reuse it instead of copying it (spec §2 Integration Points, §6 Configuration Keys).

**Prerequisite:** FEAT-096 is merged into `dev` (decided 2026-09-04). Rebase the feature
worktree onto `dev` before starting; `conf.py` already contains `TOKEN_EXCHANGE_*` keys.

---

## Scope

- `pyproject.toml`: remove `python3-saml` and `xmlsec`; add `pysaml2>=7.5,<8`. Keep `lxml`.
  Run `uv lock` / `uv sync` inside the venv; confirm a clean install.
- `navigator_auth/conf.py`: add, next to the existing `SAML_*` block (lines ~456-484), every
  key from spec §6 "Configuration Keys" with the stated defaults:
  `SAML_METADATA`, `SAML_SP_KEY_FILE`, `SAML_SP_CERT_FILE`, `SAML_BINDING`,
  `SAML_ALLOW_UNSOLICITED`, `SAML_WANT_ASSERTIONS_SIGNED`, `SAML_WANT_RESPONSE_SIGNED`,
  `SAML_IDP_KEY_FILE`, `SAML_IDP_CERT_FILE`, `SAML_IDP_KEY_PASSPHRASE`, `SAML_IDP_ENTITY_ID`,
  `SAML_IDP_SERVICE_PROVIDERS` (JSON list, parsed with `orjson`, same fallback style as
  `SAML_MAPPING`), `SAML_IDP_SETTINGS`, `SAML_IDP_REQUIRE_AUTH_METHODS`, `SAML_XMLSEC_BINARY`,
  `SAML_CLOCK_SKEW`, `SAML_FLOW_TTL`, `SAML_METADATA_RELOAD`, `SAML_EXECUTOR_WORKERS`.
  Keep `SAML_PATH`, `SAML_SETTINGS`, `SAML_MAPPING` untouched.
- `navigator_auth/backends/abstract.py`: add `BaseAuthBackend.validate_redirect_host(uri) ->
  Optional[str]` with exactly the semantics of `ADFSAuth._validate_internal_redirect`
  (`adfs.py:120-135`): relative URIs pass; absolute URIs pass only if `netloc` matches an
  `ALLOWED_HOSTS` pattern via `fnmatch`; otherwise log a warning and return `None`. Accept an
  optional `extra_hosts: Iterable[str]` parameter (used later by the IdP role for per-SP
  `allowed_relay_hosts`).
- `navigator_auth/backends/adfs.py`: make `_validate_internal_redirect` a one-line delegation
  to the base method. No behavior change.
- CI/images: add the `xmlsec1` system package wherever the test suite runs
  (`.github/workflows/*.yml` that run pytest; any Dockerfile in the repo). Add a
  `pytest.mark.xmlsec` marker to `[tool.pytest.ini_options]` in `pyproject.toml`.

**NOT in scope**: any SAML code; deleting `backends/saml.py` (TASK-060 does that once the
replacement exists — until then `saml.py` will fail to import `onelogin`; guard the import in
`backends/__init__.py` with a try/except that logs a warning so the package still imports).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `pyproject.toml` | MODIFY | Dependency swap; `xmlsec` pytest marker |
| `uv.lock` | MODIFY | Regenerated |
| `navigator_auth/conf.py` | MODIFY | New `SAML_*` / `SAML_IDP_*` keys |
| `navigator_auth/backends/abstract.py` | MODIFY | `validate_redirect_host` |
| `navigator_auth/backends/adfs.py` | MODIFY | Delegate `_validate_internal_redirect` |
| `navigator_auth/backends/__init__.py` | MODIFY | Guard legacy `SAMLAuth` import until TASK-060 |
| `.github/workflows/*.yml`, `Dockerfile*` (if present) | MODIFY | Install `xmlsec1` |
| `tests/test_saml_foundation.py` | CREATE | Validator + conf tests |

---

## Implementation Notes

### Pattern to Follow
```python
# navigator_auth/backends/adfs.py:120-135 — move this body to BaseAuthBackend
def _validate_internal_redirect(self, uri: str) -> str:
    if not uri:
        return None
    netloc = urlparse(uri).netloc
    if not netloc:
        return uri
    for pattern in ALLOWED_HOSTS:
        if fnmatch.fnmatch(netloc, pattern):
            return uri
    self.logger.warning(...)
    return None
```

### Key Constraints
- Always `source .venv/bin/activate` before `uv`/`python`/`pytest`.
- Config parsing follows the existing `orjson.loads` + `logging.exception` fallback style
  in `conf.py`.
- Existing ADFS tests must pass unchanged.

### References in Codebase
- `navigator_auth/conf.py:456-484` — existing SAML keys and JSON-parsing style
- `navigator_auth/backends/adfs.py:120-135` — validator to promote
- `navigator_auth/conf.py:139-143` — `ALLOWED_HOSTS`

---

## Acceptance Criteria

- [ ] `uv pip list` shows `pysaml2` and no `python3-saml` / `xmlsec`
- [ ] `python -c "import navigator_auth.backends"` succeeds
- [ ] `pytest tests/test_saml_foundation.py tests/ -k "adfs or redirect" -v` passes
- [ ] `xmlsec1 --version` succeeds in CI after the workflow change
- [ ] All new conf keys importable from `navigator_auth.conf` with spec defaults

---

## Test Specification

```python
# tests/test_saml_foundation.py
import pytest
from navigator_auth import conf
from navigator_auth.backends.abstract import BaseAuthBackend


class _Stub(BaseAuthBackend):
    async def on_startup(self, app): ...
    async def check_credentials(self, request): ...


@pytest.fixture
def backend(monkeypatch):
    monkeypatch.setattr("navigator_auth.backends.abstract.ALLOWED_HOSTS", ["*.example.com"])
    return _Stub(user_model=None)


def test_validate_redirect_relative(backend):
    assert backend.validate_redirect_host("/home") == "/home"

def test_validate_redirect_allowed(backend):
    assert backend.validate_redirect_host("https://app.example.com/x") == "https://app.example.com/x"

def test_validate_redirect_rejected(backend):
    assert backend.validate_redirect_host("https://evil.test/x") is None

def test_validate_redirect_extra_hosts(backend):
    assert backend.validate_redirect_host("https://sp.partner.io/acs", extra_hosts=["sp.partner.io"])

def test_conf_defaults():
    assert conf.SAML_CLOCK_SKEW == 60
    assert conf.SAML_FLOW_TTL == 600
    assert conf.SAML_EXECUTOR_WORKERS == 4
    assert conf.SAML_IDP_SERVICE_PROVIDERS == []
```
---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-<NNN>-<slug>.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: sdd-worker (Claude Sonnet 5, session_01KS7E6KxYXnkgzMnYHaJC2U)
**Date**: 2026-09-05
**Notes**: Swapped `python3-saml`/`xmlsec` for `pysaml2>=7.5,<8` in `pyproject.toml`
(added `tool.pytest.ini_options.markers` registering `xmlsec`); added every
`SAML_*`/`SAML_IDP_*` key from spec §6 to `conf.py` next to the existing SAML
block, with the stated defaults and the existing `orjson`/`logging.exception`
fallback style for JSON-valued keys; promoted `validate_redirect_host(uri,
extra_hosts=())` onto `BaseAuthBackend` (`abstract.py`), imported `ALLOWED_HOSTS`
there; `ADFSAuth._validate_internal_redirect` now delegates to it (removed the
now-unused `fnmatch`/`urlparse` imports from `adfs.py`); guarded the legacy
`from .saml import SAMLAuth` in `backends/__init__.py` with try/except so the
package still imports (logs a warning) until TASK-060 replaces it. Created
`tests/test_saml_foundation.py` (validator + conf-defaults + package-import
tests) — all pass. Verified `pytest tests/test_saml_foundation.py tests/ -k
"adfs or redirect" -v` (34 passed) and a full-suite run; the only full-suite
failures are pre-existing environment/infra issues (no Postgres/Redis/vault
session storage in this sandbox) reproduced identically against unmodified
`dev` — confirmed zero regressions from this task's changes. `uv pip list`
confirms `pysaml2` present, no `python3-saml`/`xmlsec`.

**Deviations from spec**: No `.github/workflows/*.yml` or `Dockerfile` was
modified to install `xmlsec1` — this repository currently has no CI workflow
that runs `pytest` (only `codeql-analysis.yml`, a CodeQL scan with no test
step, and `release.yml`, a release-build/publish workflow) and no Dockerfile
exists in the repo. There is nothing in scope to add the binary to. `uv.lock`
is `.gitignore`d and not tracked in this repo, so it was not committed
(dependency resolution was verified with a local `uv pip install -e .`
instead).
