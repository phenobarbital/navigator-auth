# TASK-128: Cross-surface integration tests and documentation

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-125, TASK-126, TASK-127
**Assigned-to**: unassigned

---

## Context

The feature's closure task, covering **spec §3 Module 8**'s integration tests
and **spec §3 Module 9**'s documentation. Both depend on all three surfaces
being hardened, and both are cross-surface — which is why they land together
rather than being split per handler.

**Half A — integration tests (spec §4 "Integration Tests").** Every test
written in TASK-118..127 is a unit test of one method on one class. They
prove the pieces; they do not prove the *sequences* that the acceptance
criteria are actually written about:

- an owner links an identity through the vault and then reads it through the
  generic CRUD surface — the two surfaces must agree and neither must leak;
- a superuser reads, revokes and deletes a foreign identity, and is refused a
  token refresh;
- a partner key is created (token returned once), listed (no token), revoked
  and deleted, and a regular user is refused at every step.

**Half B — documentation (spec §3 Module 9).** The owner-or-superuser rule is
the business rule spec §1 says *"is written nowhere"*. After this feature it
is written in code and in a policy pack; this task writes it down for the
people who have to operate it.

---

## Scope

**Half A:**
- Create `tests/integration/test_auth_model_ownership.py` with the three
  end-to-end scenarios from spec §4.

**Half B:**
- Update `documentation/identity-vault.md`: the owner-or-superuser rule, the
  redacted admin view, the generic `/api/v1/user_identity*` surface's
  behaviour, and the refused/parameterized `_filter`.
- Update `documentation/pdp.md`: the three policy names, what each grants,
  and that a missing policy removes admin access rather than granting it.
- Document the superuser-only partner surface with its return-once token.

**NOT in scope**:
- Any change under `navigator_auth/`. If an integration test fails, the fix
  belongs in whichever of TASK-118..127 owns that code — reopen it rather
  than patching here. (If a test reveals a genuine gap no task covers,
  **ESCALATE**; do not widen this task into implementation.)
- Adding, moving or rewriting unit tests. TASK-118..127 own
  `tests/unit/handlers/`.
- Translating, restructuring or rewriting the existing content of
  `documentation/pdp.md` — see the contract note about what that file
  actually is.
- Documenting the deferred surfaces (`UserManager`, groups, permissions,
  policies). Spec §1 Non-Goals lists them as audited-and-deferred; mentioning
  that the guard is reusable by them is fine, implying they are protected is
  not.
- Raising the `navigator-api` floor in `pyproject.toml`. That is spec §8 Q9,
  explicitly **not** part of FEAT-105 ("it would make a dependency upgrade a
  prerequisite of a security fix").

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/integration/test_auth_model_ownership.py` | CREATE | The three end-to-end scenarios |
| `tests/integration/__init__.py` | CREATE | New test package, **if absent** |
| `documentation/identity-vault.md` | MODIFY | Owner-or-superuser rule, admin view, `_filter` behaviour |
| `documentation/pdp.md` | MODIFY | The three policy names and the fail-closed contract |

---

## Codebase Contract

> Re-verified on `dev` @ `62fd419` (2026-10-23/24).

### `documentation/identity-vault.md` — structure to append into

Verified headings and their line numbers:

| Line | Heading |
|---|---|
| 1 | `# Identity Vault — Linked External Credentials` |
| 14 | `## How it works` |
| 33 | `## Storage & encryption` |
| 42 | `### Legacy tables` |
| 81 | `## HTTP API` |
| 109 | `## Provider notes` |
| 119 | `## Configuration` |
| 151 | `## Manual smoke test` |
| 163 | `## Login-flow fixes shipped with this feature` |

The `## HTTP API` section (`:81-107`) opens with:

```markdown
## HTTP API

All endpoints operate on the authenticated session user's own
identities only.

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/user/identities` | List linked identities (tokens never included) |
...
```

Note the sentence "All endpoints operate on the authenticated session user's
own identities only" — true of the **vault** endpoints it tabulates, and it
is exactly the claim that FEAT-105 extends to the generic CRUD surface. The
new section belongs after this one, and the existing sentence should be
scoped so it does not read as a claim about both surfaces (AC-5).

The file is English; keep it English.

### `documentation/pdp.md` — read this before touching it

**It is 26 lines of Spanish-language design brief, not reference
documentation.** Verified in full: a `# Policy-Based Access Control`
heading followed by a bulleted development plan ("Completar el desarrollo de
la lógica ABAC/PBAC de navigator-auth … con los siguientes cambios
estructurales"), including a `Policy(...)` code sample, the `POLICY_STORAGE_DIR`
default, and a closing "¿qué buscamos?" paragraph.

Spec §3 Module 9 names it as the place to document the three policy names.
So: **append a new English section** documenting the pack, and leave every
existing line untouched. Do not translate the brief, do not reorganize it,
and do not delete the plan items — some are still open work.

`# FILL IN: if appending an English section to a Spanish planning note reads
wrong to you, the alternative is a new file (e.g.
documentation/abac-auth-model-policies.md) linked from pdp.md. Either
satisfies spec §3 Module 9; pick one, and say which and why in the Completion
Note.`

### `tests/` layout — where integration tests go

Verified: `tests/` holds ~40 top-level `test_*.py` modules plus
`tests/unit/` (with `identity/`, `middlewares/`, `vault/`, and `handlers/`
added by this feature), `tests/fixtures/`, `tests/conftest.py` and
`tests/__init__.py`.

**There is no `tests/integration/` directory today.** Spec §4 separates
"Unit Tests" from "Integration Tests" without giving a path. Creating
`tests/integration/` with an `__init__.py` matches the existing
`tests/unit/<area>/__init__.py` convention
(verified: `tests/unit/__init__.py`, `tests/unit/identity/__init__.py`,
`tests/unit/middlewares/__init__.py`, `tests/unit/vault/__init__.py` all
exist).

`# FILL IN: check whether pytest configuration (pyproject.toml / pytest.ini /
setup.cfg) restricts testpaths or marks integration tests; if it does, follow
it instead of inventing a directory.`

### The three scenarios, from spec §4 "Integration Tests"

| Test | Description (verbatim from the spec) |
|---|---|
| `test_identity_surface_end_to_end_owner` | Owner links an identity through the vault, then reads it through `/api/v1/user_identity/{id}`: metadata present, zero token bytes anywhere in the payload. |
| `test_identity_surface_end_to_end_superuser` | Superuser reads, revokes and deletes a foreign identity; responses redacted, audit records written, a `PUT` refresh attempt refused. |
| `test_partner_key_lifecycle_superuser_only` | Superuser creates a partner key (token returned once), lists it (no token), revokes and deletes it; a regular user is refused at every step. |

### Fixtures spec §4 asks for

```python
@pytest.fixture
def identity_row():      # UserIdentity double with ciphered token columns
@pytest.fixture
def account_row():       # UserAccount double
@pytest.fixture
def partner_row():       # PartnerKey double with a plaintext JWT in `token`
@pytest.fixture
def owner_session():     # user_id=42, groups=["users"]
@pytest.fixture
def superuser_session(): # user_id=7, groups=["superuser"]
@pytest.fixture
def pdp_with_pack():     # PDP whose YAMLStorage points at abac/default_policies/
@pytest.fixture
def recording_conn():    # captures (sql, *args) so parameterization is assertable
```

`pdp_with_pack` is the one that needs real wiring: `YAMLStorage._parse_file`
is a **`@staticmethod`** taking a `Path`
(verified: `navigator_auth/abac/storages/yaml_storage.py:104-105`), so the
pack can be parsed directly from
`navigator_auth/abac/default_policies/auth_model_admin_access.yaml`
(TASK-120) without standing up `POLICY_STORAGE_DIR`. The `FakePDP` stub in
`tests/test_check_access.py:48-58` is the shape the decorators expect:

```python
class FakePDP:
    """Minimal PDP stub exposing the ``policies`` collection."""

    def __init__(self, policies):
        self._evaluator = None
        self._policies = policies

    @property
    def policies(self):
        return self._policies
```

`# FILL IN: _parse_file returns policy DICTS, not Policy objects
(yaml_storage.py:135-149). _find_policy (decorators.py:1003-1015) looks up
`getattr(policy, "name", None)`, which a dict does not answer. Decide how to
bridge — adapt the dicts through the PolicyAdapter the storage normally uses,
or construct ResourcePolicy objects from them
(navigator_auth/abac/policies/resource_policy.py:7) — and keep the
construction in the fixture so all three scenarios share it.`

### What the hardened surfaces answer (the behaviour under test)

From TASK-123..127's acceptance criteria, consolidated:

| Request | Expected |
|---|---|
| owner `GET /api/v1/user_identity/{own id}` | 200, metadata, no token material |
| non-owner `GET /api/v1/user_identity/{foreign id}` | 404, identical to a nonexistent id |
| non-superuser `?user_id=<other>` | 403 (not 400) |
| superuser `GET` foreign identity | 200 redacted, one audit record |
| superuser `PATCH {"enabled": false}` on a foreign identity | 202, audited |
| superuser `PATCH {"display_name": …}` on a foreign identity | 403 |
| superuser `PUT` (refresh) on a foreign identity | 403 |
| anyone `PATCH {"access_token": …}` | 400 |
| `?_filter=access_token=x` | 400 |
| `?_filter=auth_provider=git` | 200, statement contains `$1` |
| `:meta` | schema without the credential columns |
| non-superuser any verb on `/api/v1/partner/tokens*` | 403 |
| superuser `PUT` partner key | 201 **with** `token` |
| superuser `GET` the same key afterwards | 200, no `token` |
| superuser `PATCH`/`DELETE` partner key | 202, no `token`, audited |

### Verified route names (for building requests)

| Surface | Routes | Source |
|---|---|---|
| identities | `/api/v1/user_identity/{id:.*}`, `/api/v1/user_identity{meta:\:?.*}` | `navigator_auth/handlers/__init__.py:58-65` |
| accounts | `/api/v1/user_accounts/{id:.*}`, `/api/v1/user_accounts{meta:\:?.*}` | `:39-46` |
| partner keys | `/api/v1/partner/tokens/{id:.*}`, `/api/v1/partner/tokens{meta:\:?.*}` | `:48-56` |
| vault | `/api/v1/user/identities*` | `:67+` |

All six FEAT-105 routes must still exist with the same paths and verbs
(spec G4) — worth asserting directly (AC-4).

### Does NOT Exist (do not reference)

- `tests/integration/` — this task creates it.
- A live-database test harness in this repo. `tests/conftest.py` and the
  existing suite use `make_mocked_request` plus patched sessions and mocked
  connections (`tests/unit/identity/test_identity_handlers.py:20-60`); there
  is no fixture that provisions `auth.user_identities`. These "integration"
  tests are **cross-surface, in-process** tests over mocked connections, not
  DB tests. Do not try to stand up PostgreSQL.
- `aiohttp.test_utils.AioHTTPTestCase` / `TestClient` usage anywhere in this
  suite — verified, the house pattern is `make_mocked_request`. Driving the
  handlers directly keeps these tests consistent with the other ~40 modules.
- Any loader that reads `navigator_auth/abac/default_policies/`. Spec §6: no
  Python file references that directory; it is a pack an operator copies into
  `POLICY_STORAGE_DIR` (`navigator_auth/conf.py:705`). The fixture must read
  the file itself.
- `documentation/abac.md`, `documentation/policies.md`,
  `documentation/partners.md` — none exists. Spec §3 Module 9 names
  `identity-vault.md` and `pdp.md`.
- A changelog file to update. `# FILL IN: check for CHANGELOG.md / docs/
  release notes; if one exists and the repo convention is to add an entry,
  add one — otherwise skip and say so.`

---

## Implementation Blueprint

### Half A — `tests/integration/__init__.py` — CREATE

```python
# empty — marks tests/integration as a package, like tests/unit/__init__.py
```

### Half A — `tests/integration/test_auth_model_ownership.py` — CREATE

```python
"""Cross-surface ownership and redaction, end to end (FEAT-105, TASK-128).

Spec §4 "Integration Tests". The unit suites in tests/unit/handlers/ prove
each method; these three scenarios prove the SEQUENCES the acceptance
criteria are written about — e.g. "the token is returned exactly once" is a
property of a create-then-read pair, not of either response alone.

In-process and connection-mocked, like the rest of this suite
(tests/unit/identity/test_identity_handlers.py:20-60). No database.
"""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)

OWNER_ID = 42
SUPERUSER_ID = 7
OTHER_ID = 99

SENTINEL_ACCESS = b"SENTINEL-ACCESS-TOKEN-BYTES"
SENTINEL_REFRESH = b"SENTINEL-REFRESH-TOKEN-BYTES"
SENTINEL_JWT = "eyJhbGciOiJIUzI1NiJ9.SENTINEL-PARTNER.signature"

PACK = (
    Path(__file__).resolve().parents[2]
    / "navigator_auth" / "abac" / "default_policies"
    / "auth_model_admin_access.yaml"
)


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


@pytest.fixture
def owner_session():
    """user_id=42, groups=["users"]."""
    # FILL IN: FakeSession({"session": {"user_id": OWNER_ID,
    # "username": "owner", "groups": ["users"]}}).


@pytest.fixture
def superuser_session():
    """user_id=7, groups=["superuser"]."""
    # FILL IN: same shape with groups=["superuser"].


@pytest.fixture
def identity_row():
    """UserIdentity double with ciphered token columns and PII."""
    # FILL IN: every public column populated, plus access_token=SENTINEL_ACCESS,
    # refresh_token=SENTINEL_REFRESH, id_token=None, key_version=1,
    # user_id=OTHER_ID (so it is "foreign" by default; override per test).


@pytest.fixture
def account_row():
    """UserAccount double."""
    # FILL IN: all seven columns.


@pytest.fixture
def partner_row():
    """PartnerKey double with a plaintext JWT in `token`."""
    # FILL IN: all nine public columns plus token=SENTINEL_JWT.


@pytest.fixture
def recording_conn():
    """Captures (sql, *args) so parameterization is assertable."""
    # FILL IN: an async context manager recording every query/fetch_all/
    # fetch_one/fetchval call as (sentence, args, kwargs). Reuse the shape
    # from TASK-121's RecordingConn.


@pytest.fixture
def pdp_with_pack():
    """A PDP carrying the three FEAT-105 policies from the shipped pack."""
    # FILL IN:
    #  - assert PACK.exists() with a message naming the path.
    #  - dicts = YAMLStorage._parse_file(PACK)   (a @staticmethod)
    #  - bridge the dicts to policy OBJECTS: _find_policy
    #    (decorators.py:1003-1015) reads getattr(policy, "name", None), which
    #    a dict does not answer. Construct ResourcePolicy instances
    #    (abac/policies/resource_policy.py:7) or route the dicts through the
    #    PolicyAdapter the storage normally uses. Keep it HERE so all three
    #    scenarios share one construction.
    #  - return a FakePDP-shaped stub (tests/test_check_access.py:48-58).


def _patch_sessions(session):
    # FILL IN: patch navigator_auth.decorators.get_session AND
    # navigator_auth.handlers.guards.get_session.


def _app(pdp=None):
    # FILL IN: {"auth": MagicMock(), "authdb": MagicMock(), "redis":
    # MagicMock()} plus "abac": pdp when given.


def _body(response) -> str:
    """The response body as text, for sentinel scanning."""
    # FILL IN: handle both a web.Response and a raised web.HTTPException.


class TestIdentitySurfaceOwner:
    @pytest.mark.asyncio
    async def test_identity_surface_end_to_end_owner(
        self, owner_session, identity_row, pdp_with_pack
    ):
        """Owner links via the vault, then reads via the CRUD surface.

        Metadata present, zero token bytes anywhere in the payload.
        """
        # FILL IN:
        #  1. read the identity through the vault handler
        #     (navigator_auth/handlers/user_identities.py) as the owner and
        #     keep the payload — it is the masked() shape.
        #  2. read the SAME row through UserIdentityHandler as the owner.
        #  3. assert the metadata the owner needs is present in both
        #     (identity_id, auth_provider, enabled, expires_at...).
        #  4. assert neither SENTINEL_ACCESS nor SENTINEL_REFRESH appears
        #     ANYWHERE in either serialized body — bytes and their repr.
        #  5. assert the two payloads agree on the credential-related keys
        #     (has_refresh_token, has_id_token, expired, profile) — spec §8
        #     Q6's no-drift requirement, observed across the two surfaces
        #     rather than against masked()'s key set.
        # Bounded by AC-1.

    @pytest.mark.asyncio
    async def test_owner_cannot_reach_a_foreign_identity_by_any_route(
        self, owner_session, identity_row, pdp_with_pack
    ):
        """PK, list, ?user_id=, ?_filter= and :meta all refuse or exclude."""
        # FILL IN: drive all five shapes in one test and assert each refuses
        # (404 / 403 / 400) or returns only own rows. This is the "under any
        # combination" half of spec §5 criterion 3, asserted as a sequence.
        # Bounded by AC-1, AC-2.


class TestIdentitySurfaceSuperuser:
    @pytest.mark.asyncio
    async def test_identity_surface_end_to_end_superuser(
        self, superuser_session, identity_row, pdp_with_pack
    ):
        """Read, revoke and delete a foreign identity; refuse a PUT refresh.

        Responses redacted, audit records written.
        """
        # FILL IN:
        #  1. GET the foreign identity -> 200, redacted (no sentinels).
        #  2. PATCH {"enabled": false} -> 202, audited.
        #  3. PUT (the refresh path) -> 403: spec G5 gives the superuser
        #     revoke and delete only, and there is no identity:create /
        #     identity:refresh action.
        #  4. PATCH {"display_name": "x"} -> 403.
        #  5. DELETE -> allowed, audited.
        #  6. assert the AuditLog received one record per cross-user step
        #     (patch AuditLog in navigator_auth.handlers.guards) and that each
        #     answer carries .response and .rule.
        # Bounded by AC-2, AC-3.

    @pytest.mark.asyncio
    async def test_superuser_is_fully_denied_without_the_pack(
        self, superuser_session, identity_row
    ):
        """No PDP => the admin path is closed; the owner path still open."""
        # FILL IN: same steps with pdp=None; assert every cross-user step is
        # refused, then assert an OWNER read on the same app still succeeds.
        # Bounded by AC-3.


class TestPartnerKeyLifecycle:
    @pytest.mark.asyncio
    async def test_partner_key_lifecycle_superuser_only(
        self, superuser_session, partner_row, pdp_with_pack
    ):
        """Create (token once), list (no token), revoke, delete."""
        # FILL IN:
        #  1. PUT -> 201 and SENTINEL_JWT IS in the body.
        #  2. GET the same row -> 200 and SENTINEL_JWT is NOT in the body.
        #  3. GET the list and :meta -> no token, no `token` key.
        #  4. PATCH (revoke) -> 202, no token in the body.
        #  5. DELETE -> allowed, no token in the body.
        #  6. one audit record per step.
        # Bounded by AC-3.

    @pytest.mark.asyncio
    async def test_regular_user_is_refused_at_every_step(
        self, owner_session, partner_row, pdp_with_pack
    ):
        """All six verbs, 403, for an authenticated non-superuser."""
        # FILL IN: loop GET/PUT/PATCH/POST/DELETE/HEAD — bounded by AC-3.


class TestRoutesStillExist:
    def test_all_six_routes_are_registered(self):
        """Spec G4: the paths and verbs are unchanged by this feature."""
        # FILL IN: build an aiohttp Application, run
        # navigator_auth.handlers's route setup over it, and assert the six
        # route NAMES resolve: api_auth_useridentity_id,
        # api_auth_useridentity, api_auth_useraccount_id,
        # api_auth_useraccount, api_auth_partnerkey_id, api_auth_partnerkey
        # (verified: navigator_auth/handlers/__init__.py:39-65).
        # Bounded by AC-4.
```

**Why the owner scenario compares the two surfaces instead of checking one
against `masked()`'s key set.** TASK-125 already pins the handler against
`masked()`. What no unit test can see is the two **handlers** disagreeing in
practice — different serialization, a different `None` handling, a key
present in one and absent in the other. Driving both and diffing is the only
place that shows up.

**Why the sentinels are distinctive byte strings scanned over the whole
body.** `access_token` is `Optional[bytes]`; a leak can surface as a base64
string, as a `repr` (`b'SENTINEL…'`), or nested inside `auth_data`/`profile`
or `attributes`. Asserting "the key is absent" misses all three. Scan the
serialized text for the sentinel.

**Why `test_superuser_is_fully_denied_without_the_pack` asserts the owner
path still works.** It is spec §5 criterion 7's actual shape: fail-closed for
the admin path **while** self-service keeps working. An implementation that
denied everything would satisfy the first half, and it would be a broken
feature.

**Why `TestRoutesStillExist` is in this file.** Spec G4 and §5's
second-to-last criterion are about the whole feature, not any one handler, and
a route regression is exactly the sort of thing that nine green unit suites
would not notice. It is also the cheapest test here.

**Why these tests are connection-mocked and not DB-backed.** There is no
database fixture anywhere in this suite — the existing ~40 modules are all
`make_mocked_request` plus patched sessions. Spec §4 calls them "Integration
Tests" in the sense of *crossing modules*, not of touching infrastructure.
Standing up PostgreSQL would make the feature's verification depend on
something CI does not have.

### Half B — `documentation/identity-vault.md` — MODIFY (two edits)

```markdown
<!-- EDIT 1 — scope the existing claim.
anchor (verified: documentation/identity-vault.md:83-84):
    All endpoints operate on the authenticated session user's own
    identities only.
occurrences: 1 (verified: grep -cF 'All endpoints operate on the authenticated session user'"'"'s own' documentation/identity-vault.md)

Replace with a sentence that scopes it to the endpoints this section
tabulates, and points at the new section for the generic CRUD surface. -->

The endpoints below operate on the authenticated session user's own
identities only. The generic model CRUD surface at
`/api/v1/user_identity*` is governed separately — see
[Owner-or-superuser access to the auth model surfaces](#owner-or-superuser-access-to-the-auth-model-surfaces).
```

```markdown
<!-- EDIT 2 — append a new section after `## HTTP API` and before
`## Provider notes`
anchor (verified: documentation/identity-vault.md:109): `## Provider notes`
occurrences: 1 (verified: grep -cF '## Provider notes' documentation/identity-vault.md) -->

## Owner-or-superuser access to the auth model surfaces

`/api/v1/user_identity*`, `/api/v1/user_accounts*` and
`/api/v1/partner/tokens*` are generic model CRUD endpoints. Since 0.29.0
they enforce one rule: **a row is the prerogative of its owner, or of a
`superuser` — and a superuser never sees credentials.**

<!-- FILL IN: write this section. It must cover, in prose and a table:
  - the ownership rule and who the owner is (the row's `user_id`);
  - that a foreign row fetched by primary key answers 404, deliberately
    indistinguishable from a row that does not exist;
  - the redacted admin view: a superuser reads metadata only, and may only
    revoke (`enabled=false`) and delete — never refresh tokens, never edit
    another column;
  - that writes to the vault-managed columns (`access_token`,
    `refresh_token`, `id_token`, `key_version`, `provider_user_id`,
    `token_type`, `expires_at`, `refreshed_at`, `scopes`) answer 400 for
    everyone, the owner included, and that token refresh lives at
    `/api/v1/user/identities/{provider}/credential` instead;
  - `?_filter=<column>=<value>`: allowed only for a public column, executed
    as a parameterized query with the ownership predicate ANDed in; a
    credential or unknown column answers 400;
  - `?fields=` is intersected with the public column set, never unioned, so
    naming a credential column drops it;
  - `:meta` returns the schema without the credential columns;
  - the partner-key surface is superuser-only for every verb, and its signed
    `token` is returned exactly once, in the creation response;
  - the three ABAC policy names, with a pointer to pdp.md.
Keep the house voice: present tense, short declaratives, a table where there
are more than three cases. Match the existing `## HTTP API` table style. -->
```

**Why EDIT 1 is not optional.** As it stands, `## HTTP API`'s opening
sentence is the only statement in the docs about ownership on identity
endpoints, and a reader will take it to cover `/api/v1/user_identity*` too —
which was false before this feature and is true for different reasons after
it. Leaving it unscoped means the new section reads as a contradiction.

**Why the 404-is-deliberate point must be written down.** It looks like a
bug from the outside: a client holding a valid `identity_id` gets 404.
Someone will "fix" it to 403 for clarity, which restores the existence
oracle spec §2 layer 1 removed. The documentation is where that decision
survives.

### Half B — `documentation/pdp.md` — MODIFY (one append)

```markdown
<!-- AFTER — append at end of file. Leave all 26 existing lines untouched:
the file is a Spanish-language development brief, and some of its plan items
are still open work.
anchor (verified: documentation/pdp.md:26, the closing "¿qué buscamos?"
paragraph)
occurrences: 1 (verified: grep -cF '¿qué buscamos?' documentation/pdp.md) -->

---

## Shipped policy pack: auth model admin access (FEAT-105)

`navigator_auth/abac/default_policies/auth_model_admin_access.yaml` ships
three named policies. They govern the **admin** path of the auth model CRUD
surfaces; a row's own owner needs no policy at all.

| Policy | Grants to `superuser` | Actions |
|---|---|---|
| `user_identities_admin_access` | read (redacted), revoke and delete other users' linked identities | `identity:read`, `identity:revoke`, `identity:delete` |
| `user_accounts_admin_access` | read, revoke and delete other users' social accounts | `account:read`, `account:revoke`, `account:delete` |
| `partner_keys_admin_access` | manage partner keys (they have no owner) | `partner:read`, `partner:create`, `partner:revoke`, `partner:delete` |

<!-- FILL IN: finish the section. It must state:
  - that the pack is NOT loaded automatically — nothing in the codebase reads
    `default_policies/`; an operator copies the file into
    `POLICY_STORAGE_DIR` (default `BASE_DIR / env / policies`,
    navigator_auth/conf.py:705);
  - the fail-closed contract: with no PDP, with a policy undeclared, or with
    a policy that raises, the admin path is DENIED — a missing policy can only
    ever remove cross-user access, never grant it; owner access is unaffected;
  - that these policies never grant credential material: redaction is
    enforced in code and no policy can switch it off;
  - that `superuser_actions` on each handler is a second, code-level envelope,
    so widening a policy file cannot widen a handler;
  - that every cross-user and admin decision — allow and deny — is recorded
    through AuditLog.
Write it in English, as a new section. Do not translate or restructure the
Spanish brief above it. -->
```

**Why "the pack is not loaded automatically" is the first thing this section
says.** Spec §6 is explicit that no Python file references
`default_policies/`, and an operator who assumes shipping equals activating
will deploy with the admin path silently dead. That is the safe failure, but
it will be reported as a bug.

**Why the fail-closed contract is documented and not just tested.** It is the
one behaviour that looks like a malfunction from the outside — a superuser
being refused — and the natural "fix" is to grant on a missing policy.
Writing down that the denial is the design is what stops that.

### Steps (in order)

1. Confirm all three dependencies landed: TASK-125, TASK-126 and TASK-127
   must be in `sdd/tasks/completed/`, and `pytest tests/unit/handlers -q`
   must be green **before** you start. If it is not, stop — these tests
   cannot distinguish their own bugs from an unfinished surface.
2. Check for pytest configuration constraining test paths or markers
   (contract note) and follow it.
3. Create `tests/integration/__init__.py` and the test module. Fill the
   fixtures first, **`pdp_with_pack` before anything else** — all three
   scenarios depend on it and it is the one piece with a real unknown (the
   dict→object bridge).
4. Fill `test_identity_surface_end_to_end_owner`, then the superuser
   scenario, then the partner lifecycle, then `TestRoutesStillExist`.
5. If a scenario fails because a *surface* is wrong rather than the test:
   stop, reopen the owning task (TASK-123..127), and do not patch
   `navigator_auth/` from here.
6. Write Half B. Do `identity-vault.md` EDIT 1 before EDIT 2 so the two
   sections read consistently.
7. Re-read both documents end to end as a new operator would. The test of
   this half is whether someone can answer "why did my superuser get a 403?"
   from the docs alone.
8. Run `pytest tests/integration -v`, then the full gate:
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`
   and `ruff check navigator_auth/handlers/ navigator_auth/decorators.py`.
9. Confirm the blast radius: `git diff --name-only` lists only the four files
   in the table. **Nothing under `navigator_auth/`** (AC-7).

### FILL IN checklist

- [ ] pytest-config check for `tests/integration/` placement
- [ ] `owner_session` / `superuser_session` fixtures
- [ ] `identity_row` / `account_row` / `partner_row` fixtures with sentinels
- [ ] `recording_conn` fixture
- [ ] `pdp_with_pack` fixture — including the dict→policy-object bridge — AC-6
- [ ] `_patch_sessions` / `_app` / `_body` helpers
- [ ] `test_identity_surface_end_to_end_owner` — AC-1
- [ ] `test_owner_cannot_reach_a_foreign_identity_by_any_route` — AC-1, AC-2
- [ ] `test_identity_surface_end_to_end_superuser` — AC-2, AC-3
- [ ] `test_superuser_is_fully_denied_without_the_pack` — AC-3
- [ ] `test_partner_key_lifecycle_superuser_only` — AC-3
- [ ] `test_regular_user_is_refused_at_every_step` — AC-3
- [ ] `test_all_six_routes_are_registered` — AC-4
- [ ] `identity-vault.md` EDIT 1 — scope the existing claim — AC-5
- [ ] `identity-vault.md` EDIT 2 — the new section, all ten points — AC-5
- [ ] `pdp.md` append — the table plus the five stated facts — AC-6
- [ ] CHANGELOG check (contract note) — add an entry or record that none applies

---

## Acceptance Criteria

- [ ] **AC-1** `test_identity_surface_end_to_end_owner` passes: the owner reads their identity through both the vault and the CRUD surface, the metadata they need is present in both, the two agree on the credential-related keys, and neither sentinel token value appears anywhere in either serialized body.
- [ ] **AC-2** `test_identity_surface_end_to_end_superuser` passes: read (redacted), revoke (202) and delete succeed and are audited; a `PUT` refresh and a non-revoke `PATCH` on the foreign row are refused 403.
- [ ] **AC-3** `test_partner_key_lifecycle_superuser_only` passes: creation returns the token once, every later read omits it, revoke and delete succeed and are audited, and a non-superuser is refused on all six verbs. With no PDP, every admin step on every surface is denied while owner access keeps working.
- [ ] **AC-4** All six FEAT-105 routes still resolve by name with unchanged paths (spec G4).
- [ ] **AC-5** `documentation/identity-vault.md` documents the owner-or-superuser rule, the deliberate 404, the redacted admin view, the readonly-column 400 and where refresh actually lives, the `?_filter=` / `?fields=` / `:meta` behaviour, the superuser-only partner surface with its return-once token, and the three policy names — and the pre-existing "All endpoints operate on … own identities only" sentence is scoped so it no longer reads as a claim about the CRUD surface.
- [ ] **AC-6** `documentation/pdp.md` documents the three policy names with their actions, that the pack is not auto-loaded, the fail-closed contract, that no policy can grant credential material, the code-level `superuser_actions` envelope, and the audit guarantee — with every pre-existing line unchanged.
- [ ] **AC-7** No file under `navigator_auth/` is created or modified, and no existing test file is modified.
- [ ] **AC-8** `pytest tests/integration -v` passes, `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes, and `ruff check navigator_auth/handlers/ navigator_auth/decorators.py` is clean (spec §5's last two criteria).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/integration -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q
ruff check navigator_auth/handlers/ navigator_auth/decorators.py
```

```python
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
YAMLStorage._parse_file(PACK)   # @staticmethod — no instance needed
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §3 Modules 8 and 9, §4 "Integration Tests" and "Test Data / Fixtures", and
   **all of §5 Acceptance Criteria** (this task is where they are checked end
   to end).
2. **Check dependencies** — TASK-125, TASK-126 and TASK-127 must all be
   completed, and `pytest tests/unit/handlers -q` must be green first.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** Half A, then Half B.
5. If an integration test fails because a surface is wrong, **reopen the
   owning task** — do not modify `navigator_auth/` from here (AC-7). If it
   reveals a gap no task covers, ESCALATE.
6. **Verify** every acceptance criterion.
7. **Record in the Completion Note**: where you put the policy documentation
   (an appended section in `pdp.md` or a new linked file), how you bridged
   `_parse_file`'s dicts to policy objects, and whether a CHANGELOG entry
   applied.
8. **Move this file** to `sdd/tasks/completed/TASK-128-integration-tests-and-docs.md`.
9. **Update index** → `"done"`.
10. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
