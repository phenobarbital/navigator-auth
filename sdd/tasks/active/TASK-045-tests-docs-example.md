# TASK-045: Claude-replay conformance tests, docs, example server

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 8)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-039, TASK-040, TASK-041, TASK-042, TASK-043, TASK-044
**Assigned-to**: unassigned

---

## Context

Final integration layer: the two **Claude-replay conformance tests** whose passing closes
ai-parrot's spike gate **S1**, plus operator documentation and a runnable example that
wires everything together.

---

## Scope

- Integration tests (spec §4):
  - `test_claude_replay_dcr` — discovery → DCR → authorize (PKCE S256) → gate-activated
    user consents → code → form-urlencoded token → refresh rotation → introspect active;
    assert each leg well under the 10 s (30 s refresh) budgets.
  - `test_claude_replay_static_client` — same with a pre-registered static client.
  - `test_upstream_google_end_to_end` — provider button → mocked Google callback →
    auto-provision → gate → consent → owner-bound token; upstream tokens vaulted.
  - `test_gate_lifecycle` and `test_asymmetric_e2e` (if not fully landed in
    TASK-042/043, complete here).
- `examples/oauth2_mcp_server.py`: GoogleAuth + AzureAuth as upstream IdPs, gate enabled,
  DCR open, discovery live — the copy-paste target for "what URL do I give Claude Web".
- Documentation:
  - `documentation/oauth.md` — new endpoints, config keys, DCR policies.
  - `documentation/mcp-connector.md` (new) — connector setup guide, gate administration
    (approval queue workflow), key-generation + rotation runbook (RS256), reverse-proxy /
    `.well-known` root-mounting notes, and the **cross-repo follow-up note** (D6):
    ai-parrot must add a spec for serving PRM per MCP mount using
    `build_protected_resource_metadata`.

**NOT in scope**: any production code change beyond what test failures force (report those
as deviations); ai-parrot-side changes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_oauth2_mcp_conformance.py` | CREATE | Claude-replay + upstream e2e suites |
| `examples/oauth2_mcp_server.py` | CREATE | Full wiring example |
| `documentation/oauth.md` | MODIFY | New surface documented |
| `documentation/mcp-connector.md` | CREATE | Connector guide + runbooks |

---

## Implementation Notes

### Key Constraints
- Replay Claude's observed behavior faithfully (ai-parrot brainstorm §4): DCR body with
  `client_name="Claude"`, `token_endpoint_auth_method=none`, callback
  `https://claude.ai/api/mcp/auth_callback`; form-urlencoded token; rotated refresh
  expected in the refresh response.
- Run with `OAUTH2_CLIENT_STORAGE=memory` so the suite needs no external services;
  mocked external backends (TASK-041 fixture).
- All FEAT-093/094/095 suites green at completion — this task is the regression gate.

### References in Codebase
- `tests/test_oauth2_integration.py` — FEAT-093 integration-test style.
- `examples/oauth2_3lo_server.py` — example-server pattern (env bootstrap header).

---

## Acceptance Criteria

- [ ] Both Claude-replay tests pass with every leg inside budget (**S1 closed**)
- [ ] Upstream Google e2e + gate lifecycle + asymmetric e2e pass
- [ ] Example server runs and completes a full flow against a local browser
- [ ] Docs updated incl. the D6 cross-repo follow-up note
- [ ] Full suite green: `pytest tests/ -v`

---

## Test Specification

```python
# tests/test_oauth2_mcp_conformance.py — spec §4 Integration Tests table:
# test_claude_replay_dcr, test_claude_replay_static_client,
# test_upstream_google_end_to_end, test_gate_lifecycle, test_asymmetric_e2e
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-039..044 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none
