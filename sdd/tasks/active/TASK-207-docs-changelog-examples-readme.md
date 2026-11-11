# TASK-207: Documentation — CHANGELOG behaviour changes and examples/README.md

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-195, TASK-196, TASK-202, TASK-205
**Assigned-to**: unassigned

---

## Context

Spec §2 New Public Interfaces, §10 Documentation, AC20. The spec's `docs.policy` is `required` but this
repository has no `wiki/` tree, so §10 names the deliverables instead: `CHANGELOG.md` (the public
behaviour changes, the custom-IdP exception contract, the anonymous-access migration) and
`examples/README.md` (pinned backends, short-key warning, the PKCE walk-through). It runs last because it
documents what every other task changed (directly: TASK-195, 196, 202, 205; transitively TASK-198, 200,
201, 203, 204).

---

## Scope

- `CHANGELOG.md`, under `# Unreleased`, after the existing entries — one entry per item:
  1. **Behaviour change** — `@is_authenticated()` never admits a request through `NoAuth` (or any backend
     with `_anonymous_auth = True`) and rejects restored guest sessions with 401; keep anonymous access with
     the auth exclude list or `@allow_anonymous` / `request.allow_anonymous`. A backend's unexpected
     exception is logged and skipped (401, never 500).
  2. **Behaviour change** — the OAuth2 token endpoint answers `invalid_grant` instead of issuing a
     session-less token when the resource owner is unknown or disabled; the refresh grant also revokes that
     chain. `/oauth2/authorize` and device verification send such a session to the login form; consent
     answers 401 `access_denied`.
  3. **Behaviour change + contract** — identity-store failures answer a generic 503 (`server_error`) and
     never revoke refresh chains; `IdentityProvider.user_from_id` raises the new public
     `navigator_auth.exceptions.IdentityStoreUnavailable` for infrastructure failures instead of
     `UserNotFound`. Custom IdPs must raise `UserNotFound` only for a confirmed missing user.
  4. `/oauth2/userinfo` omits profile/email claims it cannot supply instead of returning `""`.
  5. Device login now returns to the pre-filled device verification form (explicit approval still required).
  6. `APIKeyAuth` declines non-API-key bearers; the `allow_hosts` exempt branch publishes `request["userdata"]`.
  7. Examples: both OAuth2 examples pin `backends=[Oauth2Provider]`, `authz_backends=[]`; the
     `oauth2_server.py` pages do PKCE (S256).
- `examples/README.md`: in the `oauth2_3lo_server.py` section explain the pinned backends,
  `authz_backends=[]` and the short-key warning (mirror the identity-vault explanation at `:134-148`);
  in the `oauth2_server.py` section describe the PKCE walk-through and the `crypto.subtle` secure-context
  requirement (`http://localhost` works, a LAN IP does not).

**NOT in scope**: code changes; Sphinx `docs/` pages (none listed in §10); docstrings (owned by each code task).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `CHANGELOG.md` | MODIFY | Entries under `# Unreleased` |
| `examples/README.md` | MODIFY | 3LO pinned-backend section; `oauth2_server.py` PKCE walk-through |
| `tests/test_oauth2_examples_wiring.py` | MODIFY | Two doc assertions (CHANGELOG + README), so AC20 is checked by pytest |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` (2026-11-11). FEAT-106 adds its own CHANGELOG entries under
> `# Unreleased` (13 lines on its branch) — append after them, never reorder or rewrite them.

### Existing anchors
```text
CHANGELOG.md:1                 # Unreleased            (first entry today: FEAT-107 BREAKING write envelope)
examples/README.md:3           ## `oauth2_3lo_server.py` — end-to-end OAuth2 3LO (Authorization Code + PKCE)
examples/README.md:58          ### Example-only shortcuts   (mentions `AuthHandler(enable_authdb=False)` at :63 — now pinned)
examples/README.md:77          ## `identity_vault_server.py` — Identity Vault: login + linked credentials
examples/README.md:134-148     ### It shows an empty session with a "Log out" button   (the explanation to mirror)
examples/README.md:163         ## `oauth2_server.py` — OAuth2 client registrations reference
examples/README.md:170         ## Other examples
```

### Facts to document (all created by the dependency tasks)
```python
navigator_auth.exceptions.IdentityStoreUnavailable           # TASK-200 (AuthException, status 503)
BaseAuthBackend._anonymous_auth / NoAuth._anonymous_auth      # TASK-198
navigator_auth.decorators.allow_anonymous                     # existing (decorators.py:64)
examples/oauth2_3lo_server.py: _BACKENDS, _warn_on_short_secret()   # TASK-195 (AUTH_SECRET_KEY, 32 bytes)
examples/static/oauth2_index.html, callback.html: PKCE + state      # TASK-196 (sessionStorage key nav_oauth2_index_pkce)
```

### Does NOT Exist
- No `wiki/` directory and no `sdd/config.json` `techwiki` setting — the techwiki check only warns `docs_no_pages`.
- ~~`OAUTH_REQUIRE_KNOWN_OWNER`~~ or any new setting — do not document configuration that does not exist.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "CHANGELOG.md", "action": "MODIFY"},
    {"path": "examples/README.md", "action": "MODIFY"},
    {"path": "tests/test_oauth2_examples_wiring.py", "action": "MODIFY"}
  ],
  "contract_symbols": []
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Re-read the merged code for each fact above (names, status codes, messages) — *why*: document what shipped.
2. Write the CHANGELOG entries — *why*: AC20, the three spec §2 behaviour changes are client-visible.
3. Update the README sections — *why*: AC20.

### `CHANGELOG.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '^# Unreleased' CHANGELOG.md) -->
<!-- FILL IN: append the seven entries listed in Scope as `- **…** …` bullets after the last existing bullet
     under `# Unreleased` (FEAT-107 and FEAT-106 entries stay first). Mark items 1–3 "(FEAT-108, behaviour
     change)"; include the migration sentence for item 1 and the custom-IdP rule for item 3 — bounded by AC20. -->
```

### `examples/README.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '^## `identity_vault_server.py` — Identity Vault: login + linked credentials' examples/README.md) -->
<!-- BEFORE the `---` that precedes it (end of the 3LO section, :75), insert: -->
### Why it pins its backends

`make_app()` constructs `AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False)`.
<!-- FILL IN: explain, as at :134-148, that navigator_auth.conf star-imports settings.settings last (so local
     settings would add NoAuth, APIKeyAuth, Azure, …) and that authz_backends=[] stops an inherited
     allow_hosts from admitting requests without a session; then the startup warning when AUTH_SECRET_KEY is
     shorter than 32 bytes (env/.env wins over the example's default; set a ≥ 32-byte key there). -->

<!-- Also update the `AuthHandler(enable_authdb=False)` bullet under "Example-only shortcuts" (:63) to the pinned call. -->

<!-- occurrences: 1 (verified: grep -c '^## Other examples' examples/README.md) -->
<!-- BEFORE `## Other examples` (:170), at the end of the oauth2_server.py section, insert: -->
### Browser walk-through (PKCE)

<!-- FILL IN: open http://localhost:5000/login → Authorize: the page generates a PKCE pair (S256) and a random
     state in sessionStorage; the callback page checks state and sends code_verifier with Get Token.
     crypto.subtle needs a secure context — http://localhost works, a LAN IP does not. Mention that the app
     now pins backends=[Oauth2Provider], authz_backends=[] like the 3LO example. -->
```

### `tests/test_oauth2_examples_wiring.py` (MODIFY) — append (file created by TASK-196)
```python
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "examples" / "README.md"


def test_changelog_records_feat108_behaviour_changes():
    """AC20 — the client-visible changes and the custom-IdP contract are in the Unreleased section."""
    unreleased = CHANGELOG.read_text().split("\n# ", 1)[0]
    for needle in ("FEAT-108", "IdentityStoreUnavailable", "allow_anonymous", "invalid_grant", "503"):
        assert needle in unreleased, needle


def test_readme_documents_pinned_backends_and_pkce():
    """AC20 — both new README subsections exist and name the facts they explain."""
    text = README.read_text()
    assert "### Why it pins its backends" in text and "authz_backends=[]" in text
    assert "### Browser walk-through (PKCE)" in text and "crypto.subtle" in text
```
**Why**: the techwiki check is advisory here (no `wiki/` tree) and not a registered test runner, so AC20 is
asserted by pytest in a file that is already in the feature Validation Contract. Keep the two headings
above verbatim — the tests depend on them. You may still run
`parrot sdd techwiki check --spec sdd/specs/oauth2-3lo-issues.spec.md --root .` (expected: `docs_no_pages` warning).

### FILL IN checklist
- [ ] Seven CHANGELOG entries; AC20.
- [ ] Two README subsections + the shortcuts bullet; AC20.
- [ ] The two doc tests pass.

---

## Acceptance Criteria

- [ ] AC20: `CHANGELOG.md` records the behaviour changes and the custom-IdP exception contract (spec §2 New Public Interfaces) and how to keep anonymous access (exclude list / `allow_anonymous`); `examples/README.md` documents the pinned backends and the PKCE walk-through.
- [ ] Every name, status code and message in the docs matches the merged code.

---

## Validation Commands

- `pytest tests/test_oauth2_examples_wiring.py -q`

---

## Test Specification

`test_changelog_records_feat108_behaviour_changes`, `test_readme_documents_pinned_backends_and_pkce`
(appended to `tests/test_oauth2_examples_wiring.py`). The techwiki check is advisory (`docs_no_pages`).

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the anchors** — re-run each `grep -c` before editing; a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `FILL IN`.
7. **Verify** — run the Validation Commands.
8. **Commit** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-207 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
