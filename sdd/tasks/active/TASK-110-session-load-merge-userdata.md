# TASK-110: `load_session` merges fresh `userdata` (navigator-session 1.1.1)

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 9, §8 Q3 (resolved), G8, §7 Known Risks, Worktree Strategy.

**This task changes a different distribution.** `navigator-session` lives at
`/home/jesuslara/proyectos/navigator-session` (its own git repo, currently
`1.1.0` on branch `main` at `97a1763`). Nothing in this task touches
`navigator_auth/` except the dependency floor in `pyproject.toml:52`.

`RedisStorage.load_session` resolves a `session_id`, reads the payload from
Redis, and when a payload exists builds `SessionData(data=data, new=False)`
from the **stored** payload — the caller's fresh `userdata` is silently
discarded. There is no merge. `userdata` is consulted only to find a
`session_id`/identity and to seed `new_session` when Redis has nothing.

**Honest scope note, carried from the spec verbatim**: this fixes a real latent
defect but it is **not** the cause of the stale `auth_token` in spec §1 (b).
`load_session` has exactly **one** caller in `navigator-auth` (`auth.py:494`),
and every backend that reaches it has already written the session through
`remember()` → `new_session()` (`api.py`, `token.py`, `troc.py`, `basic.py`,
`django.py`; `passkey.py` and `exchange.py` delegate to `basic.open_session`),
which **overwrites** the payload wholesale (`redis.py:311`). So today the
discard re-reads *fresh* data. The user chose to fix it anyway rather than only
pin it with a test.

**The release trap is why this is its own module.** `navigator-auth` declares
`navigator-session>=1.1.0` (`pyproject.toml:52`) but overrides it with an
editable path source (`pyproject.toml:142`). Local development therefore picks
the change up immediately and *masks* the pin — so forgetting the version bump
fails **silently**: green locally, old behaviour in CI and production. The bump
and the floor raise are part of this task's definition of done, not follow-up.

---

## Scope

In `/home/jesuslara/proyectos/navigator-session`:
- `navigator_session/storages/redis.py`: add an **opt-in** merge to
  `load_session` so a caller passing fresh `userdata` updates the live session
  instead of being ignored. The default path must stay **byte-identical** —
  this storage is shared by every consumer of `navigator-session`, not just
  `navigator-auth`.
- `navigator_session/version.py`: `__version__` `1.1.0` → `1.1.1`.
- Tests next to the existing storage tests (see Test Specification).

In `/home/jesuslara/proyectos/navigator-auth`:
- `pyproject.toml:52`: `navigator-session>=1.1.0` → `>=1.1.1`.

**NOT in scope**: any broader refactor of `navigator-session`'s storage layer
(explicit spec Non-Goal); the cookie or Postgres storages; `new_session`
(`redis.py:275`) and its wholesale overwrite (`:311`) — that behaviour is what
navigator-auth currently relies on; changing `auth.py:494`'s call to opt in
(the navigator-auth-side regression test in TASK-111 pins today's invariant
either way, and flipping the caller is a separate decision).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `../navigator-session/navigator_session/storages/redis.py` | MODIFY | opt-in merge in `load_session` |
| `../navigator-session/navigator_session/version.py` | MODIFY | `1.1.0` → `1.1.1` |
| `../navigator-session/tests/test_redis_load_session_merge.py` | CREATE | three tests (see below) |
| `pyproject.toml` | MODIFY | floor `>=1.1.0` → `>=1.1.1` (line 52) |

---

## Codebase Contract

### Verified Imports (navigator-session)
```python
from aiohttp import web                                   # verified: storages/redis.py (web.Request / web.StreamResponse types)
import redis.asyncio as aioredis                          # verified: used at redis.py:137
from navigator_session.data import SessionData            # verified: constructed at redis.py:200-206
from navigator_session.conf import SESSION_KEY, SESSION_ID, SESSION_OBJECT, SESSION_REQUEST_KEY
                                                          # verified: used at redis.py:149-153, :220-224
```

### Verified Signatures (navigator-session @ `97a1763`, version `1.1.0`)
```python
# navigator_session/conf.py
SESSION_TIMEOUT = config.getint('SESSION_TIMEOUT', fallback=360000)   # verified: :24
SESSION_KEY = config.get('SESSION_KEY', fallback='id')                # verified: :43
SESSION_ID = config.get('SESSION_ID', fallback='session_id')          # verified: :44

# navigator_session/storages/redis.py
async def get_session_id(self, conn, identity) -> str:                # verified: :100
    session_id = await conn.get(f"user:{identity}")                   # verified: :103

async def load_session(self, request: web.Request, userdata: dict = None,
                       response: web.StreamResponse = None, new: bool = False,
                       ignore_cookie: bool = True) -> SessionData:    # verified: :111-118
    session_id = None                                                 # verified: :129
    # cookie branch when ignore_cookie is False                       # verified: :130-136
    conn = aioredis.Redis(connection_pool=self._redis)                # verified: :137
    if session_id is None: session_id = request.get(SESSION_ID, None) # verified: :145-146
    if not session_id: session_id = userdata.get(SESSION_ID, None) if userdata else None   # verified: :147-148
    session_identity = userdata.get(SESSION_KEY, None) if userdata \
                       else request.get(SESSION_KEY, None)            # verified: :149-151
    if not session_id: session_id = await self.get_session_id(conn, session_identity)       # verified: :152-154
    if session_id is None and new is False: return None               # verified: :155-157
    _id_ = f"session:{session_id}"                                    # verified: :162
    data = await conn.get(_id_)                                       # verified: :163-170
    if data is None:
        if new is True: return await self.new_session(request, userdata)   # verified: :171-174
        else: return None                                                  # verified: :175-177
    data = self._decoder(data)                                        # verified: :179
    # --- VALIDATION: ghost/empty session is DELETED, then new_session or None  # verified: :180-199
    session_content = data.get(SESSION_KEY)                           # verified: :184
    if not data or list(data.keys()) == ['session_id'] or session_content is None:  # verified: :185
    session_identity = data.get(SESSION_KEY, session_identity)        # verified: :203
    session = SessionData(id=session_id, identity=session_identity,
                          data=data, new=False, max_age=self.max_age) # verified: :205-211
    #   ^^^ `userdata` is DISCARDED here — there is no merge. This is the defect.
    except Exception: session = SessionData(..., data=None, new=True, ...)   # verified: :212-218
    self.session_info(session, request)                               # verified: :220
    session[SESSION_KEY] = session_id                                 # verified: :221
    request[SESSION_KEY] = session_identity; request[SESSION_ID] = session_id   # verified: :222-223
    request[SESSION_OBJECT] = session; request[SESSION_REQUEST_KEY] = session   # verified: :224-225

async def new_session(self, request, data=None, response=None):       # verified: :275
    session_id = await self.get_session_id(conn, session_identity)    # verified: :295  (REUSES the id)
    result = await conn.set(_id_, dt, self.max_age)                   # verified: :311-313  (OVERWRITES wholesale)

# navigator_session/middleware.py
if session.is_changed: await storage.save_session(request, response, session)   # verified: :45-57

# navigator_session/version.py
__version__ = '1.1.0'                                                 # verified: :9

# navigator_auth side (the one caller)
await self._session.storage.load_session(request, userdata, response=response)  # verified: navigator_auth/auth.py:494
```

### Does NOT Exist (do not reference)
- **No** merge parameter, flag, or hook on `load_session` today — you add one.
- **No** `SessionData.update()` / `.merge()`: check `navigator_session/data.py`
  for what the object actually supports before assuming an API. The payload
  reaches it as the `data=` constructor argument.
- **No** sync-down GitHub Action in `navigator-auth` despite `CLAUDE.md`'s
  claim — irrelevant here, but do not expect automation to propagate anything.
- **No** `uv sync` inside a worktree, ever: it repoints the shared `.venv` and
  breaks the main checkout's imports for every session on this machine (spec
  §7, `.claude/rules/worktree-management.md`).
- **No** separate installed copy of `navigator-session`: the `.venv` is
  editable-installed against `/home/jesuslara/proyectos/navigator-session`, so
  an edit there is **immediately live for every session and worktree on this
  machine**, including ones testing unrelated branches.

---

## Implementation Blueprint

### Steps (in order)
1. In the `navigator-session` repo, create a branch — do **not** commit on
   `main`. The working tree, not the branch, is what the shared `.venv`
   imports, so a half-finished edit there affects every other session on this
   machine while it exists. Keep the window short.
2. Block A: the opt-in merge.
3. Block B: the version bump. Do it in the **same commit** as Block A — a
   merge without the bump is the silent-failure mode described in Context.
4. Block C: the tests.
5. Block D: back in `navigator-auth`, raise the floor.
6. Run `pytest` in **both** repos.

### Block A — `navigator_session/storages/redis.py`
```python
# REPLACE — the `load_session` signature
# occurrences: 1 (verified: grep -c 'async def load_session' navigator_session/storages/redis.py)
    async def load_session(
        self,
        request: web.Request,
        userdata: dict = None,
        response: web.StreamResponse = None,
        new: bool = False,
        ignore_cookie: bool = True,
        merge_userdata: bool = False
    ) -> SessionData:
```
```python
# AFTER — insert below the line `session_identity = data.get(SESSION_KEY, session_identity)`
# occurrences: 1 (verified: grep -c 'session_identity = data.get(SESSION_KEY, session_identity)' \
#                 navigator_session/storages/redis.py)
            # Opt-in: fold the caller's fresh userdata over the stored payload.
            # Default stays False so every existing consumer of this storage
            # keeps byte-identical behaviour (1.1.0 discarded userdata here).
            if merge_userdata is True and userdata:
                data = {**data, **userdata}
```
**Why a keyword with a `False` default, placed exactly here**: the merge must
land *after* the ghost-session validation (`:180-199`, which inspects `data`
and may delete the key and bail) and *before* the `SessionData(...)`
construction (`:205-211`), because `data` is what that constructor receives.
Merging earlier would let a caller's `userdata` resurrect a session the
validation decided to delete; merging later would require mutating
`SessionData` after the fact, which routes through its `__setattr__` and marks
the session changed — a different, visible side effect.
`{**data, **userdata}` makes the caller's values win, which is the whole point
("fresh `userdata` updates the live session").
**FILL IN: decide whether `session[SESSION_KEY] = session_id` at `:221` must
still run after a merge that may have overwritten `SESSION_KEY`** — bounded by
"the default path must stay byte-identical" and by the existing
`session_identity = data.get(SESSION_KEY, session_identity)` resolution at
`:203`, which runs *before* your insert.

### Block B — `navigator_session/version.py`
```python
# REPLACE — the version string
# occurrences: 1 (verified: grep -c "__version__ = '1.1.0'" navigator_session/version.py)
__version__ = '1.1.1'
```
**Why in the same commit**: `navigator-auth`'s editable path source
(`pyproject.toml:142`) means the behaviour change is live locally with or
without this line. The bump is the *only* thing that makes the change visible
to CI and production resolution. Separated, it gets forgotten.

### Block C — `../navigator-session/tests/test_redis_load_session_merge.py` (CREATE)
```python
"""RedisStorage.load_session userdata merge (navigator-auth FEAT-103 Module 9).

1.1.0 discarded the caller's `userdata` whenever Redis already held a payload
(`storages/redis.py:205-211` built SessionData from the stored data alone).
1.1.1 adds an opt-in merge; the default path is unchanged.
"""
# FILL IN: imports and fakes — bounded by the existing storage-test conventions
# in this repo. Read `tests/test_session_data.py` and anything under
# `tests/integration/` FIRST and reuse their Redis double / fixture style
# rather than inventing one. Do NOT hit a real Redis in a unit test.


class TestLoadSessionMerge:
    async def test_load_session_merges_fresh_userdata(self):
        """With a payload already in Redis, the opt-in merge updates the named
        keys from `userdata` instead of discarding them."""
        # FILL IN — bounded by: seed Redis with a valid payload (it must pass
        # the ghost-session validation at redis.py:185, i.e. carry SESSION_KEY
        # and more than just 'session_id'), call
        # load_session(..., userdata={"auth_token": "NEW"}, merge_userdata=True),
        # assert the returned SessionData carries "NEW".

    async def test_load_session_default_path_is_unchanged(self):
        """Without the opt-in flag, the returned SessionData is byte-identical
        to 1.1.0's — the regression guard for every other consumer."""
        # FILL IN — bounded by: same seeded payload, call load_session with a
        # CONFLICTING userdata and NO merge_userdata, assert the stored value
        # wins and the userdata value is absent. This is the most important test
        # in this task: it is what makes the change safe for consumers outside
        # navigator-auth.

    async def test_load_session_no_payload_still_seeds_new_session(self):
        """The `data is None` + `new=True` branch (redis.py:171-174) keeps
        delegating to new_session."""
        # FILL IN — bounded by: empty Redis, new=True, assert new_session was
        # called with the userdata (patch/spy it), and that merge_userdata has
        # no effect on this branch either way.
```
**Why these three and no more**: the spec names exactly these
(§4 "Tests in the `navigator-session` repo"). The second one is the real
deliverable — it is the evidence that a shared library's default behaviour did
not move.

### Block D — `navigator-auth/pyproject.toml`
```toml
# REPLACE — the dependency floor
# occurrences: 1 (verified: grep -c 'navigator-session>=1.1.0' pyproject.toml -> 1, at line 52)
    "navigator-session>=1.1.1",
```
**Why**: without it, a fresh CI install resolves `1.1.0` from the index and the
merge simply is not there, while every local test passes via the editable
override at `pyproject.toml:142`. Note the override is **not** removed — local
development continues to use the path source.

### FILL IN checklist
- [ ] Block A: whether `session[SESSION_KEY] = session_id` (`:221`) needs
      adjusting when a merge overwrote `SESSION_KEY`.
- [ ] Block C: imports, Redis double and fixture style, copied from this repo's
      existing storage tests.
- [ ] Block C: all three test bodies.

---

## Implementation Notes

### Key Constraints
- **The default path must stay byte-identical.** Every consumer of
  `navigator-session` shares this storage. `merge_userdata` defaults to
  `False`; no existing caller passes it; nothing else changes.
- **The shared `.venv` is editable-installed against both repos.** An edit in
  `navigator-session`'s working tree is live for every session on this machine
  immediately. Work on a branch there and keep the edit window short.
- **Never `uv sync` inside a worktree.**
- This task's git work spans two repositories. `/sdd-done` for FEAT-103 will
  merge the navigator-auth side only — the navigator-session branch needs its
  own merge and `1.1.1` release there. Say explicitly in the Completion Note
  what state that repo was left in.

### References in Codebase
- `navigator_session/storages/redis.py:275-313` — `new_session`, which
  overwrites wholesale; the behaviour navigator-auth currently relies on.
- `navigator_session/middleware.py:45-57` — `is_changed` → `save_session`, why
  mutating `SessionData` after construction is a visible side effect.
- `navigator_auth/auth.py:494` — the single caller, left unchanged.

---

## Acceptance Criteria

- [ ] `load_session` merges fresh `userdata` on the opt-in path
- [ ] The default path is byte-identical to `1.1.0`'s, proven by test
- [ ] The `data is None` + `new=True` branch still delegates to `new_session`
- [ ] `navigator_session.__version__ == "1.1.1"`
- [ ] `navigator-auth`'s `pyproject.toml:52` floor reads `>=1.1.1`
- [ ] `pytest` passes in the **navigator-session** repo
- [ ] `pytest tests/ -v` passes in **navigator-auth** too (the editable source
      means this change is live there)
- [ ] The Completion Note states the branch/commit left in the
      `navigator-session` repo and whether it was merged there

---

## Test Specification

Three tests, in the `navigator-session` repo (spec §4):
`test_load_session_merges_fresh_userdata`,
`test_load_session_default_path_is_unchanged`,
`test_load_session_no_payload_still_seeds_new_session`. See Block C.

The navigator-auth-side regression test
(`test_api_login_session_is_written_by_remember_not_load_session`) belongs to
TASK-111, not here.

---

## Agent Instructions

1. **Read the spec** §3 Module 9, §8 Q3, and the Worktree Strategy's two
   cross-repo warnings.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint, on a branch in the `navigator-session` repo.
5. **Verify** all acceptance criteria, in both repos.
6. **Move this file** to `sdd/tasks/completed/TASK-110-session-load-merge-userdata.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**, including the cross-repo git state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
