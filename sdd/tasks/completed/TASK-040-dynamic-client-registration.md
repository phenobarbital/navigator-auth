# TASK-040: Dynamic Client Registration (RFC 7591)

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 3, decision D1)
**Status**: done
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

**Completed by**: sdd-worker (Claude Opus 5)
**Date**: 2026-08-31
**Notes**: Pure `oauth2/dcr.py` (`validate_registration`, `to_oauth_client`, plus `build_registration_response`, `parse_rate_limit`, `generate_client_uid/secret` and a `DCRError` carrying the RFC 7591 §3.2.2 body). `ClientRegistrationRequest`/`ClientRegistrationResponse` added to `oauth2/models.py` with `extra="ignore"` (RFC 7591 §2 allows unknown metadata; Claude sends extras). `POST /oauth2/register` on `Oauth2Provider`, in the exclude list, returning 201 with `exclude_none=True` so `client_secret` is absent for public clients. Policy knob honoured: `open` (default) / `allowlist` (fnmatch globs, Claude callbacks default, fails closed when no patterns configured) / `disabled` ⇒ `registration_not_supported`. Validation rejects missing/empty `redirect_uris`, non-absolute URIs, fragments, wildcards and non-https (loopback exempt), unsupported grant/response types and auth methods — all as `invalid_client_metadata`. Public (`token_endpoint_auth_method=none`) ⇒ no secret ever minted; confidential ⇒ `secrets.token_urlsafe(32)`. Rate limiting is a fixed-window Redis counter per source IP off `self.code_storage.redis` (the one always-present handle, independent of the client-storage tier), 429 + `Retry-After`, and **fails open** so a broken cache cannot make the AS unregisterable. Unused-DCR reaper added as `ClientStorage.reap_unused_dcr_clients` across all three tiers: Postgres answers "never exchanged a token" authoritatively in SQL (`NOT EXISTS` against `oauth_access_tokens` / `oauth_grants`); memory/redis take an `is_used` predicate that fails **safe** (unknown ⇒ never delete). It is exposed as a method for a scheduler, deliberately not run on the request path. 52 new tests; 253 pass across the non-DB OAuth2 suites.

**Deviations from spec**: one required enabling change, `navigator_auth/models.py` `Client.user_id` `required=True` → `required=False` (plus `ALTER COLUMN user_id DROP NOT NULL` in `ddl.sql`). DCR registration is anonymous by design (D1), so a self-registered client has no owning user; without this the model raised `ValueError: Missing Required Field *user_id*` and DCR could not work at all on the default Postgres tier. The DDL column was already nullable — only the model-level constraint blocked it. Operator-provisioned and client_credentials clients still set `user_id` exactly as before. Two additions beyond the literal file table, both inside files already in scope: `enforce_access_gate`/`registration_source`/`token_endpoint_auth_method` were added to the `OAuthClient` Pydantic model (needed to carry the new columns through all three storage tiers), and the reaper lives on `ClientStorage` rather than in a new module.
