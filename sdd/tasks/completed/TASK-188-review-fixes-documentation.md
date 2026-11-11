# TASK-188: Documentation — docs/two_factor_auth.rst and CHANGELOG 0.30.0

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-178, TASK-180, TASK-183, TASK-187
**Assigned-to**: unassigned

---

## Context

Spec §10 Documentation (`docs.policy: required`, `pages: []`, `api_modules: [navigator_auth.mfa]`). There is no
`wiki/` tree in this repository; the spec directs the FEAT-106 user guide `docs/two_factor_auth.rst` and
`CHANGELOG.md` to be updated instead. This task runs last: it documents behaviour every implementation task
delivered (TASK-171…187). Its own validation is a small doc-contract test, because `parrot sdd techwiki check`
is not a registered test runner (it stays an acceptance criterion; it is advisory and reports
`docs_no_pages` as a warning because the spec declares `pages: []`).

---

## Scope

Update `docs/two_factor_auth.rst` for (spec §10):
- the OAuth2 login second factor and the `POST /oauth2/login/mfa` route (`nav_oauth2_login_mfa`), including the
  503 when 2FA is on and BasicAuth's MFA slot is missing/unavailable (D4);
- the settings `AUTH_MFA_RETRY_INTERVAL` (default `15`) and `AUTH_MFA_LOCK_TIMEOUT` (default `5.0`), and the
  self-healing availability that replaces "startup still succeeds so the deployment can be repaired";
- the `user_mfa_secrets` table, migration `002_mfa_secrets.sql`, and the `mfa` vault-target entry point
  (`navigator_session.vault_targets`: `mfa = "navigator_auth.mfa.targets:factory"`) with the **reinstall note**
  for `navigator-vault` (entry points are read from installed metadata: `uv pip install -e .`);
- backup-code regeneration now needing factor proof (`403 strong_factor_proof_required`, D7);
- `mfa`/`amr` in OAuth2 access tokens, refresh chains, introspection and userinfo, and request-local assurance
  isolation for bearer requests (ABAC uses the presented token, never the shared session — D8, D9);
- OAuth credential generation invalidation (`oauth_user_generation`), transactional recovery-confirmation
  consumption (`recovery_confirm_consumptions`), and strict revocation failure behaviour (503, password unchanged);
- fail-closed credential changes (503 `mfa_unavailable` when 2FA is on and MFA is down; 409 `credentials_changed`
  on hash drift);
- admin `password_reset` now ending the target user's sessions and tokens.

Add a `CHANGELOG.md` entry for 0.30.0 covering the same points. Create `tests/test_mfa_review_fixes_docs.py`.

**NOT in scope**: code or docstring changes in `navigator_auth/` (owned by TASK-171…187); a `wiki/` tree;
`docs/password_recovery.rst` and `docs/settings.rst` (spec §10 names only the two files above — mention them in
the Completion Note if they now read stale); bumping `navigator_auth/version.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `docs/two_factor_auth.rst` | MODIFY | Document every review-fix behaviour change (spec §10) |
| `CHANGELOG.md` | MODIFY | 0.30.0 entry for the FEAT-106 review fixes |
| `tests/test_mfa_review_fixes_docs.py` | CREATE | Doc-contract test: required terms present, stale statements gone |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`; code identical to the spec's `3f14b3c`).
> The documented symbols are created by the dependency tasks — confirm each exists in the worktree before
> describing it (the Steps say how).

### Verified Imports
```python
# tests/test_mfa_review_fixes_docs.py uses only the standard library:
import re
from pathlib import Path
```

### Existing Signatures to Use
```text
docs/two_factor_auth.rst (283 lines) — sections and anchors used below:
  line 1    "Two-factor authentication for BasicAuth" (title)
  line 15   "The second-factor decision runs inside ``BasicAuth.authenticate()``. A provider"   (How it works)
  line 25   "closed with ``mfa_unavailable``. Startup still succeeds so the deployment can be" (→ self-healing)
  line 45   settings-table row ``AUTH_MFA_NOTIFY_CALLBACK`` (last row; table border follows at 46)
  line 88   "require a fresh factor by inspecting ``amr`` and rejecting ``trusted_device``."
  line 136-137 "Backup codes are ten 8-character codes, shown once on initial TOTP / confirmation, consumed once each,
               and regenerated only with password / re-authentication."   (STALE after TASK-183)
  line 234  "Password changes, recovery completion, TOTP enrolment or disenrolment,"   (Remember this device)
  line 263  "Protected seed storage"; line 266 "TOTP seeds are sealed by the vault kernel in ``auth.user_vault_secrets`` beneath"
            (STALE after TASK-174)
  line 272  "Accepted bounds"
CHANGELOG.md (257 lines): line 1 "# Unreleased" followed by the FEAT-106 bullet; releases use "# vX.Y.Z" headings (250, 254).
navigator_auth/version.py: __version__ = "0.29.0" (not changed by this task).
```

Symbols to document (created by dependency tasks; confirm with `grep -rn` in the worktree):
```text
navigator_auth/conf.py: AUTH_MFA_LOCK_TIMEOUT (float, fallback 5.0) — TASK-171; AUTH_MFA_RETRY_INTERVAL (int, fallback 15) — TASK-173
navigator_auth/mfa/services.py: MfaServicesSlot.ready, get_ready_mfa_services, mfa_services_lease — TASK-173
navigator_auth/mfa/sql/002_mfa_secrets.sql, navigator_auth/mfa/targets.py (MfaSecretTarget, factory) — TASK-174
pyproject.toml [project.entry-points."navigator_session.vault_targets"] mfa = "navigator_auth.mfa.targets:factory" — TASK-174
navigator_auth/security_state/ (recovery_confirm_consumptions, oauth_user_generation, GENERATION_CLAIM "gen") — TASK-175
navigator_auth/mfa/events.py: TransitionAborted; navigator_auth/mfa/exceptions.py: MfaUnavailable — TASK-177
navigator_auth/mfa/login.py: SecondFactorGate — TASK-181
backup-codes 403 strong_factor_proof_required — TASK-183
POST /oauth2/login/mfa (nav_oauth2_login_mfa), templates/oauth/mfa.html — TASK-184
OAuth generation enforcement — TASK-185; mfa/amr propagation — TASK-186; AUTH_BEARER_CONTEXT_KEY / ABAC overlay — TASK-187
```

### Does NOT Exist
- ~~a `wiki/` directory~~ — none in this repository (spec §10); `techwiki check` will warn `docs_no_pages` — expected.
- ~~`parrot sdd techwiki check` as a validation runner~~ — it is not a registered test runner; it is an acceptance criterion.
- ~~an OIDC `id_token` `amr` claim~~ / ~~`acr` step-up~~ — non-goals; do not document them as features.
- ~~a "logout everywhere" endpoint~~ — still absent (rst line 236-237); self-service `password_change` still does not revoke
  other sessions (non-goal) — do not claim it does.
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "docs/two_factor_auth.rst", "action": "MODIFY"},
    {"path": "CHANGELOG.md", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_docs.py", "action": "CREATE"}
  ],
  "contract_symbols": []
}
```

---

## Implementation Notes

### Pattern to Follow
```rst
.. existing table style (docs/two_factor_auth.rst:31-46): fixed-width columns, ``literal`` names
``AUTH_MFA_NOTIFY_CALLBACK``             unset              Dotted callback path receiving ``MfaSecurityNotice``.
```

### Key Constraints
- Keep the existing reStructuredText style: `` ``literal`` `` for names, the fixed-width settings table (do not break
  column alignment — Sphinx rejects misaligned simple tables), section underlines matching title length.
- Describe only behaviour that exists in the worktree; verify each item with `grep` before writing it.
- No secrets, keys or real tokens in examples.
- CHANGELOG: keep `# Unreleased` as the top heading; the new bullet states "0.30.0" explicitly.

### References in Codebase
- `docs/passkey.rst` — cross-reference style (`:doc:` roles).
- `CHANGELOG.md:3-14` — FEAT-106 bullet style to mirror.

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm each documented symbol exists: `grep -rn "AUTH_MFA_RETRY_INTERVAL\|AUTH_MFA_LOCK_TIMEOUT" navigator_auth/conf.py`,
   `grep -n "targets:factory" pyproject.toml`, `grep -rn "nav_oauth2_login_mfa\|strong_factor_proof_required" navigator_auth`,
   `ls navigator_auth/security_state` — *why*: docs must describe the shipped code, not the spec.
2. Write `tests/test_mfa_review_fixes_docs.py` first and watch it fail — *why*: it is the contract for this task.
3. Edit `docs/two_factor_auth.rst` section by section (blocks below) — *why*: spec §10 lists every required topic.
4. Add the CHANGELOG bullet — *why*: spec §10 "a 0.30.0 entry for these fixes".
5. Run the Validation Commands and `parrot sdd techwiki check --spec sdd/specs/basicauth-otp-2fa-review-fixes.spec.md --root .`
   — *why*: AC; expected status `ok` or `warning` (`docs_no_pages`), never `invalid`.

### `tests/test_mfa_review_fixes_docs.py` (CREATE)
```python
"""Doc contract for the FEAT-106 review fixes (spec §10 Documentation).

Fails when docs/two_factor_auth.rst or CHANGELOG.md misses a review-fix behaviour
change, or still states behaviour the fixes removed.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "two_factor_auth.rst"
CHANGELOG = ROOT / "CHANGELOG.md"

REQUIRED_TERMS = (
    "AUTH_MFA_RETRY_INTERVAL",
    "AUTH_MFA_LOCK_TIMEOUT",
    "/oauth2/login/mfa",
    "user_mfa_secrets",
    "002_mfa_secrets.sql",
    "navigator_session.vault_targets",
    "navigator_auth.mfa.targets:factory",
    "strong_factor_proof_required",
    "amr",
    "introspect",
    "userinfo",
    "refresh",
    "oauth_user_generation",
    "recovery_confirm_consumptions",
    "password_reset",
    "mfa_unavailable",
    "credentials_changed",
)
STALE_STATEMENTS = (
    "TOTP seeds are sealed by the vault kernel in ``auth.user_vault_secrets``",
    "regenerated only with password re-authentication.",  # old wording ends here; the new one continues "… **and** fresh proof"
    "Startup still succeeds so the deployment can be repaired without masking the outage",
)


def _normalized(path: Path) -> str:
    """Return the file text with every whitespace run collapsed to one space."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_guide_documents_every_review_fix():
    """Every spec §10 topic is named in the 2FA guide."""
    text = _normalized(GUIDE)
    missing = [term for term in REQUIRED_TERMS if term not in text]
    assert not missing, f"docs/two_factor_auth.rst is missing: {missing}"


def test_guide_has_vault_reinstall_note():
    """The mfa vault target is visible to navigator-vault only after reinstalling the package."""
    # FILL IN: assert re.search(r"reinstall|uv pip install -e", text) — bounded by spec §7 "Entry-point discovery".


def test_guide_drops_stale_statements():
    """Statements the review fixes made false are gone."""
    text = _normalized(GUIDE)
    stale = [sentence for sentence in STALE_STATEMENTS if sentence in text]
    assert not stale, f"stale statements remain: {stale}"


def test_changelog_has_0_30_0_entry():
    """CHANGELOG.md names the 0.30.0 review-fix release."""
    # FILL IN: assert "0.30.0" in the text and that the entry mentions FEAT-106 — bounded by spec §10.
```
**Why this shape**: a registered-runner validation that fails on any missing §10 topic or any sentence the
fixes made false. Whitespace is normalized so rst line wrapping does not matter.

### `docs/two_factor_auth.rst` (MODIFY) — availability and settings
```rst
.. occurrences: 1 (verified: grep -c 'Startup still succeeds so the deployment can be' docs/two_factor_auth.rst)
.. REPLACE — the sentence "Startup still succeeds so the deployment can be repaired without masking the outage."
.. (verified: two_factor_auth.rst:25-26) with:
Startup still succeeds, and availability heals without a restart: the first MFA decision
after ``AUTH_MFA_RETRY_INTERVAL`` seconds rebuilds the services (one rebuild at a time).
A missing ``AUTH_OTP_SECRET`` or ``authdb`` pool is a permanent misconfiguration and is
never retried.
```
```rst
.. occurrences: 1 (verified: grep -c '``AUTH_MFA_NOTIFY_CALLBACK``             unset' docs/two_factor_auth.rst)
.. AFTER — insert below the ``AUTH_MFA_NOTIFY_CALLBACK`` row (verified: two_factor_auth.rst:45), before the closing border:
``AUTH_MFA_RETRY_INTERVAL``              ``15``             Seconds between rebuilds of unavailable MFA services.
``AUTH_MFA_LOCK_TIMEOUT``                ``5.0``            Seconds to wait for the per-user lock; a timeout is ``mfa_unavailable``.
```

### `docs/two_factor_auth.rst` (MODIFY) — OAuth2 form, tokens and ABAC
```rst
.. occurrences: 1 (verified: grep -c 'require a fresh factor by inspecting ``amr`` and rejecting ``trusted_device``.' docs/two_factor_auth.rst)
.. AFTER — insert a new section below that paragraph (verified: two_factor_auth.rst:88), before "E-mail delivery callback":
OAuth2 login form
-----------------

.. FILL IN: document — bounded by spec §3 M6 and AC1-AC6:
..   * the same SecondFactorGate guards ``POST /oauth2/login``; a factor owed renders ``oauth/mfa.html``
..     (``Cache-Control: no-store``, no session cookie); ``POST /oauth2/login/mfa`` (route ``nav_oauth2_login_mfa``)
..     verifies it and redirects to ``/oauth2/authorize`` preserving PKCE, ``state``, ``nonce``, ``scope``, ``prompt``;
..   * the trusted-device cookie works here too; 2FA on with BasicAuth's MFA slot missing/unavailable answers 503.

OAuth2 tokens and ABAC
----------------------

.. FILL IN: document — bounded by spec §3 M9, D8, D9, AC23-AC29 and §3 M4 generation contract:
..   * an access token minted after an MFA'd OAuth2 login carries ``mfa`` and ``amr``; refresh rotation copies them
..     from the parent token; introspection echoes ``amr``/``mfa`` and userinfo echoes ``amr``; no claim when no factor;
..   * bearer requests: ABAC reads assurance from the validated presented token, never from the shared session;
..   * ``oauth_user_generation``: a password reset or recovery advances the generation; older codes, carriers,
..     access and refresh tokens fail everywhere; storage failure fails closed.
```

### `docs/two_factor_auth.rst` (MODIFY) — backup codes, credential changes, seed storage
```rst
.. occurrences: 1 (verified: grep -c 'confirmation, consumed once each, and regenerated only with password' docs/two_factor_auth.rst)
.. REPLACE — "regenerated only with password re-authentication." (verified: two_factor_auth.rst:137-138) with:
regenerated only with password re-authentication **and** fresh proof of a strong
factor (a current TOTP code, an unused backup code, or a fresh passkey session);
without the proof ``POST /auth/mfa/backup-codes`` answers ``403``
``strong_factor_proof_required``.
```
**Why**: D7/AC19 — the password alone no longer regenerates codes. The new wording continues past
"re-authentication" with "**and**", so the STALE_STATEMENTS entry (which includes the old trailing period) does not trip
on it; keep that period if you reword.
```rst
.. occurrences: 1 (verified: grep -c 'Password changes, recovery completion, TOTP enrolment or disenrolment,' docs/two_factor_auth.rst)
.. FILL IN: after the paragraph starting at two_factor_auth.rst:234, add a "Credential changes" paragraph — bounded by
..   spec §3 M3/M4, AC13-AC15, AC28, AC31, AC32: one transaction for change + version bump + device revocation + audit;
..   503 ``mfa_unavailable`` when 2FA is on and MFA is down; 409 ``credentials_changed`` on drift; admin
..   ``password_reset`` ends the target's sessions and tokens; recovery consumption is recorded in
..   ``recovery_confirm_consumptions`` and a revocation failure rolls the change back (503).
```
```rst
.. occurrences: 1 (verified: grep -c 'TOTP seeds are sealed by the vault kernel in ``auth.user_vault_secrets`` beneath' docs/two_factor_auth.rst)
.. REPLACE — the first sentence of "Protected seed storage" (verified: two_factor_auth.rst:266-268) with:
TOTP seeds are sealed by the vault kernel in their own table, ``auth.user_mfa_secrets``,
whose identity columns ``(user_id, provider, key)`` are the seed's associated data, so a
copied seed cannot be opened. Migration ``002_mfa_secrets.sql`` moves existing ``mfa:``
rows out of ``auth.user_vault_secrets``. Master-key rotation re-seals them through the
``mfa`` target of the ``navigator_session.vault_targets`` entry point
(``mfa = "navigator_auth.mfa.targets:factory"``); reinstall the package
(``uv pip install -e .``) so ``navigator-vault`` discovers it.
```

### `CHANGELOG.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '# Unreleased' CHANGELOG.md) -->
<!-- AFTER — insert below `# Unreleased` (verified: CHANGELOG.md:1) and its blank line, ABOVE the FEAT-106 bullet: -->
- **FEAT-106 review fixes (0.30.0).** Fixes every high-severity finding from the PR #633 review.
  <!-- FILL IN: one sentence each — bounded by spec §1 table and §10: OAuth2 login second factor
       (`/oauth2/login/mfa`); MFA seeds in `user_mfa_secrets` with the `mfa` vault target (reinstall note);
       one-connection lock discipline and `AUTH_MFA_LOCK_TIMEOUT`; self-healing services and
       `AUTH_MFA_RETRY_INTERVAL`; atomic, fail-closed credential changes; backup-code regeneration needs factor
       proof; `mfa`/`amr` in OAuth2 tokens with request-local ABAC assurance; OAuth credential generation;
       `password_reset` revokes sessions; strict revocation and transactional recovery consumption. -->
```

### FILL IN checklist
- [ ] `test_guide_has_vault_reinstall_note` body — bounded by spec §7 "Entry-point discovery".
- [ ] `test_changelog_has_0_30_0_entry` body — bounded by spec §10.
- [ ] rst "OAuth2 login form", "OAuth2 tokens and ABAC", "Credential changes" prose — bounded by the ACs named in each block.
- [ ] CHANGELOG bullet prose — bounded by spec §1 and §10.

---

## Acceptance Criteria

- [ ] `docs/two_factor_auth.rst` covers every spec §10 topic; stale statements about seed storage, password-only
      backup regeneration and restart-only recovery are gone.
- [ ] `CHANGELOG.md` has a 0.30.0 entry for the FEAT-106 review fixes under `# Unreleased`.
- [ ] `parrot sdd techwiki check --spec sdd/specs/basicauth-otp-2fa-review-fixes.spec.md --root .` reports `ok` or
      `warning` (`docs_no_pages` is expected), never `invalid`.
- [ ] The settings table still renders (column alignment intact).
- [ ] No code under `navigator_auth/` changed.

## Validation Commands

- `pytest tests/test_mfa_review_fixes_docs.py -q`

---

## Test Specification

See the `tests/test_mfa_review_fixes_docs.py` block above — four tests: required terms, reinstall note,
stale statements, CHANGELOG 0.30.0 entry.

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§10 Documentation, §1 table, §7 Decisions).
3. **Check dependencies** — TASK-178, TASK-179, TASK-180, TASK-183 and TASK-187 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — run Step 1's greps; re-count every rst anchor.
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands and the techwiki check.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-188 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

---

## Completion Note

Haiku (native) delivered nothing (Bash blocked); gemini and codex-spark seats failed on infrastructure (missing parrot.clients.google module; unsupported codex-spark model). Implemented by the orchestrator in the a1 sub-worktree; merged by hand (`git merge --no-ff`; the engine merge looked at a stale failed a2 record). tests/test_mfa_review_fixes_docs.py: 4 passed; documented symbols verified present in navigator_auth/. Possibly stale (not in scope): docs/password_recovery.rst and docs/settings.rst. Closed via `parrot sdd task close`.
