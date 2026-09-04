# TASK-061: SP↔IdP round-trip integration tests, OAuth2 resume regression, documentation and changelog

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 7)
**Status**: pending
**Priority**: medium
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-060
**Assigned-to**: unassigned

---

## Context

Closes FEAT-097: proves the two roles interoperate end to end in one aiohttp app, guards the
FEAT-095 OAuth2-AS resume detour over a POST callback, and documents both roles, the
`xmlsec1` requirement and the migration from `python3-saml` (spec §4 Integration Tests, §5
Acceptance Criteria, §3 Module 7).

---

## Scope

- `tests/test_saml_roundtrip.py` using `aiohttp_client` with `SAMLIdentityProvider` and
  `SAMLAuth` configured against each other (SP's `SAML_METADATA` = IdP metadata endpoint
  output; IdP registry has the SP's ACS):
  - `test_saml_roundtrip_sp_initiated`, `test_saml_roundtrip_idp_initiated` (+ replay
    rejection), `test_saml_roundtrip_slo`, `test_saml_oauth2_resume_detour` (set
    `nav_oauth2_flow` cookie, park a flow in the store, assert the final `Location` is
    `/oauth2/authorize?flow=`), `test_adfs_redirect_validator_unchanged`.
  - Performance check from spec §5: time 20 ACS validations and 20 issuances; assert p95
    < 150 ms (mark `@pytest.mark.slow` if the suite has such a marker; otherwise keep it in
    the xmlsec-marked group).
- Executor assertion test: patch `SAMLCore.run` to record the calling thread and assert no
  pysaml2 call executed on the loop thread during a round-trip.
- Documentation:
  - `documentation/saml.md`: rewrite for pysaml2 — prerequisites (`xmlsec1` package per
    distro), SP role configuration (`SAML_METADATA`, key pair, binding, unsolicited,
    signature flags, `SAML_MAPPING` incl. `multi`), IdP role configuration (`SAML_IDP_*`,
    `SAML_IDP_SERVICE_PROVIDERS` JSON example shaped for a generic SP), how to subclass each
    abstract base (hook table), routes table, error-code table, **Migration from
    python3-saml** section (translated keys, rejected keys, `SAML_PATH` behavior).
  - `docs/settings.rst` / `docs/config.rst`: add the key table from spec §6.
  - `README.md` auth-methods table: SAML SP and SAML IdP rows.
  - `CHANGELOG`/`docs/changelog.rst`: 0.26.0 entry marking the breaking dependency change.
- Coverage sweep: run `pytest tests/ -v`; fix any test-only gaps in M2–M6 (report production
  changes as deviations).

**NOT in scope**: Verizon Connect subclass or its docs (follow-up spec).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_saml_roundtrip.py` | CREATE | Integration + performance + executor tests |
| `documentation/saml.md` | MODIFY | Rewrite for both roles |
| `docs/settings.rst`, `docs/config.rst` | MODIFY | Key reference |
| `README.md` | MODIFY | Auth-methods table |
| `docs/changelog.rst` (or `CHANGELOG.md`) | MODIFY | 0.26.0 breaking-change entry |

---

## Implementation Notes

### Key Constraints
- Tests are offline; the SP's metadata "URL" form is exercised by pointing at the in-app IdP
  metadata route through the test client, not the network.
- Documentation examples must use only keys that exist in `conf.py` after TASK-054.

### References in Codebase
- `tests/test_oauth2_upstream_idp.py` — resume-detour test shape to mirror
- `tests/conftest.py` — shared fixtures added in TASK-056
- `documentation/oauth.md`, `documentation/mcp-connector.md` — doc style

---

## Acceptance Criteria

- [ ] `pytest tests/ -v` passes with no skipped `xmlsec` tests in CI
- [ ] Round-trip SP-initiated, IdP-initiated and SLO tests pass
- [ ] `test_saml_oauth2_resume_detour` passes
- [ ] p95 < 150 ms for ACS validation and issuance on CI fixtures
- [ ] `documentation/saml.md` covers both roles, subclassing, migration; README and changelog updated

---

## Test Specification

```python
# tests/test_saml_roundtrip.py
import pytest

@pytest.mark.xmlsec
async def test_saml_roundtrip_sp_initiated(saml_app):
    start = await saml_app.get("/api/v1/auth/saml/", allow_redirects=False)
    # follow to IdP sso (session pre-seeded), auto-POST to SP ACS, assert session + home redirect
    ...

@pytest.mark.xmlsec
async def test_saml_roundtrip_idp_initiated(saml_app): ...

@pytest.mark.xmlsec
async def test_saml_roundtrip_slo(saml_app): ...

@pytest.mark.xmlsec
async def test_saml_oauth2_resume_detour(saml_app, redis_stub):
    saml_app.session.cookie_jar.update_cookies({"nav_oauth2_flow": "flow-1"})
    await redis_stub.set("oauth2_pending_flow-1", {"state": "s"}, ttl=600)
    ...
    assert final.headers["Location"].startswith("https://127.0.0.1/oauth2/authorize?flow=flow-1")
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

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
