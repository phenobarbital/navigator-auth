# TASK-040: Dynamic Client Registration (RFC 7591)

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 3, decision D1)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-039
**Assigned-to**: unassigned

---

## Context

Claude self-registers via RFC 7591 DCR. Registration is **open** (D1): anyone may
register; the access gate (TASK-042) is the real access control. ~80% of the storage layer
exists: `ClientStorage` trio + `client_uid` generation (`client_backend.py` `save_client`,
`secrets.token_urlsafe(18)`). Wire-contract reference: ai-parrot fixture
`ClientRegistry.register` / `_handle_registration` (request/response shapes as Claude
sends/expects them).

---

## Scope

- Create `navigator_auth/backends/oauth2/dcr.py` (pure): `validate_registration(req,
  policy, allowlist) -> ClientRegistrationRequest` and `to_oauth_client(reg) ->
  OAuthClient`.
- Add `ClientRegistrationRequest` / `ClientRegistrationResponse` Pydantic v2 models to
  `oauth2/models.py` (spec §2 Data Models).
- `POST /oauth2/register` on `Oauth2Provider` (JSON body; exclude list):
  - Policy `open` (default) / `allowlist` (redirect_uris must glob-match
    `OAUTH_DCR_REDIRECT_ALLOWLIST`; Claude callbacks shipped as defaults) / `disabled`
    (`400 registration_not_supported`).
  - Validation: `redirect_uris` required + https-only (localhost exempt);
    `token_endpoint_auth_method=none` ⇒ `client_type=public`, **no secret**; else
    confidential ⇒ `client_secret = secrets.token_urlsafe(32)`.
  - Map `grant_types`→`allowed_grant_types`, `scope`→`default_scopes`
    (default `OAUTH_DCR_DEFAULT_SCOPES`).
  - Persist via `ClientStorage.save_client` (all three tiers);
    `registration_source='dcr'`; `enforce_access_gate` from `OAUTH_DCR_GATE_NEW_CLIENTS`.
  - Response 201: `client_id`(=`client_uid`), `client_secret` (confidential only),
    `client_id_issued_at`, `client_secret_expires_at: 0`, echo of metadata.
    Errors: `{"error":"invalid_client_metadata","error_description":…}`.
- Anti-abuse: Redis per-source-IP rate limit (`OAUTH_DCR_RATE_LIMIT`, 429 on excess);
  TTL reaper for DCR clients with zero token exchanges (`OAUTH_DCR_UNUSED_TTL`).
- New `Client` columns: `token_endpoint_auth_method`, `registration_source`,
  `enforce_access_gate` (`models.py` + `oauth2/ddl.sql`).
- Unit tests per spec §4 (six `test_dcr_*` rows).

**NOT in scope**: the gate check itself (TASK-042), metadata document changes (TASK-039
already emits `registration_endpoint`), `client_secret_basic` at token (TASK-044).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/dcr.py` | CREATE | Pure validation/mapping |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | Registration request/response models |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `/oauth2/register` route + rate limit |
| `navigator_auth/backends/oauth2/client_backend.py` | MODIFY | Persist new fields across all three tiers |
| `navigator_auth/models.py` | MODIFY | `Client` +3 columns |
| `navigator_auth/backends/oauth2/ddl.sql` | MODIFY | ALTER `auth.clients` |
| `tests/test_oauth2_dcr.py` | CREATE | Full DCR matrix |

---

## Implementation Notes

### Key Constraints
- **Never issue a secret to a public client**; public ⇒ PKCE mandatory downstream via
  existing `OAUTH_REQUIRE_PKCE_PUBLIC` (no new enforcement needed here).
- Rate-limit counters in Redis (shared across workers) — mirror FEAT-094's device
  user-code lockout pattern (`OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS` implementation).
- Constant-time comparisons; never log secrets.
- Three meanings of `client_id` (FEAT-093): respond with `client_uid` on the wire; the int
  PK stays internal.

### References in Codebase
- `navigator_auth/backends/oauth2/client_backend.py` — `ClientStorage` ABC + trio;
  `save_client` generates `client_uid`.
- ai-parrot `.../parrot/mcp/oauth_server.py:339-371,432-463` — RFC 7591 wire shapes.

---

## Acceptance Criteria

- [ ] Claude-shaped metadata registers successfully (201, correct shape); public clients
      get no secret; confidential do
- [ ] `open`/`allowlist`/`disabled` policies behave per spec; Claude callbacks pass
      allowlist by default
- [ ] Invalid metadata ⇒ `invalid_client_metadata`; excess registrations ⇒ 429
- [ ] DCR clients born with `enforce_access_gate=True` when `OAUTH_DCR_GATE_NEW_CLIENTS`
- [ ] Registered client immediately completes authorize+PKCE+token (integration smoke)
- [ ] Tests pass: `pytest tests/test_oauth2_dcr.py -v`

---

## Test Specification

```python
# tests/test_oauth2_dcr.py — per spec §4:
# test_dcr_register_public_client, test_dcr_register_confidential,
# test_dcr_policy_allowlist, test_dcr_policy_disabled, test_dcr_invalid_metadata,
# test_dcr_rate_limit, test_dcr_client_born_gated
# fixture claude_like_client_metadata: client_name="Claude",
#   redirect_uris=["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method="none"
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-039 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none
