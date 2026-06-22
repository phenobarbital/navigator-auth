# TASK-023: Client identifier disambiguation (`client_uid`)

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **Module 1** of FEAT-093. Foundational data-model change. The wire OAuth
`client_id` is currently the integer DB primary key (enumerable, DB-coupled), bridged by a
lossy `int(client_id)` cast in `PostgresClientStorage`. This task separates the internal
surrogate PK from the opaque public identifier so all later modules build on a clean model.
See spec §2 (Client Identifier Model), Resolved Decision **D7**.

---

## Scope

- Add `auth.clients.client_uid VARCHAR(255) NOT NULL UNIQUE` to `ddl.sql` with a backfill
  that generates an opaque value (`secrets.token_urlsafe`/`uuid4`) for existing rows.
- Add `client_uid` (unique) to the `Client` asyncdb model in `navigator_auth/models.py`.
- In `OAuthClient` (`oauth2/models.py`): `client_id: str` = public id (= `client_uid`); add
  `client_pk: Optional[int] = None` (the surrogate PK, FK target). Keep the str validator.
- In `PostgresClientStorage`: look up by `client_uid` (**remove** the `int(client_id)` cast);
  map DB row `client_id`→`client_pk`, `client_uid`→`client_id`. Update `_save_client_db`
  accordingly.
- Update `examples/oauth2_server.py` (and any static callback usage) to register/use a fixed
  string `client_uid` instead of `client_id=1`.

**NOT in scope**: renaming nested-model `client_id`→`client` (that happens in TASK-024 with
the model rewrite); `user_id` binding; any token/grant logic.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/ddl.sql` | MODIFY | Add `client_uid` unique column + backfill |
| `navigator_auth/models.py` | MODIFY | `Client.client_uid` unique field |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `OAuthClient.client_id`(=uid) + `client_pk:int` |
| `navigator_auth/backends/oauth2/client_backend.py` | MODIFY | Lookup by `client_uid`; drop `int()`; map pk↔uid |
| `examples/oauth2_server.py` | MODIFY | Test client uses string `client_uid` |
| `tests/test_oauth2_client_uid.py` | CREATE | Unit tests for lookup + mapping |

---

## Implementation Notes

### Key Constraints
- `client_uid` is opaque and non-enumerable; generate with `secrets.token_urlsafe(24)` or
  `uuid4().hex` at registration.
- Integer PK (`auth.clients.client_id`) stays internal — never on the wire, FK target only.
- Memory/Redis client storages already key by string — they key by `client_uid`.
- Backfill must be idempotent (`ADD COLUMN IF NOT EXISTS`, guarded `UPDATE`).

### References in Codebase
- `navigator_auth/backends/oauth2/client_backend.py:80` — current `int(client_id)` cast to remove.
- `navigator_auth/backends/oauth2/models.py:54,69` — `OAuthClient.client_id` + validator.
- `navigator_auth/backends/oauth2/ddl.sql` — existing `auth.clients` ALTERs to extend.

---

## Acceptance Criteria

- [ ] `get_client` resolves a non-numeric opaque `client_uid` (no `ValueError`/`None`).
- [ ] `OAuthClient.client_id` is the public uid; `client_pk` carries the integer PK from DB.
- [ ] `int(client_id)` cast removed from storage; lookup is by `client_uid`.
- [ ] DDL adds `client_uid UNIQUE` + idempotent backfill; example uses a string `client_uid`.
- [ ] Tests pass: `pytest tests/test_oauth2_client_uid.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_client_uid.py
import pytest
from navigator_auth.backends.oauth2.models import OAuthClient

class TestClientUid:
    def test_public_id_is_string(self):
        c = OAuthClient(client_id="abc123uid", client_name="App", client_pk=7)
        assert c.client_id == "abc123uid"
        assert c.client_pk == 7

    async def test_memory_lookup_by_uid(self, memory_oauth_storages):
        # save then get by opaque uid (non-numeric) must succeed
        ...
```

---

## Agent Instructions

1. Read the spec for full context (§2 Client Identifier Model, D7).
2. Verify no `Depends-on`.
3. Update `tasks/.index.json` → `in-progress`.
4. Implement per scope.
5. Verify acceptance criteria.
6. Move file to `tasks/completed/`.
7. Update index → `done`. Fill Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (claude-sonnet-4-6)
**Date**: 2026-06-22
**Notes**: All 6 files modified/created as specified. OAuthClient.client_id is now the public
opaque uid (str); client_pk carries the integer surrogate PK. PostgresClientStorage looks up
by client_uid column (int() cast removed). MemoryClientStorage and RedisClientStorage key by
the public uid. DDL adds client_uid UNIQUE + backfill + all new tables (oauth_refresh_tokens,
oauth_grants, oauth_access_tokens, policies.scopes) for later tasks. All 11 unit tests pass.
**Deviations from spec**: DDL for oauth_refresh_tokens, oauth_grants, oauth_access_tokens and
policies.scopes column were added to ddl.sql in this task (ahead of TASK-026/027/030) to keep
the SQL file coherent and idempotent (CREATE TABLE IF NOT EXISTS). No behavioral deviations.
