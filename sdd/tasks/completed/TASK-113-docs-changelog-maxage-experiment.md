# TASK-113: Docs, and run the §8 Q1 `max_age` experiment

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: done
**Priority**: low
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-106, TASK-107, TASK-109
**Assigned-to**: unassigned

---

## Context

Spec §5 last two criteria, §8 Q1 (resolved), §3 Module 8 "Unblocks".

Two deliverables that no implementation task owns:

1. **`docs/` update** — spec §5: *"`docs/` updated: the new session keys,
   `get_live_provider_token`, and the `expires_in` / `expires_at` change (the
   last one noted as client-visible)"*. Plus the two Azure settings from
   TASK-109.
2. **The §8 Q1 experiment** — spec §5: *"The §8 Q1 experiment has been run and
   its outcome recorded in §7 as a one-line note — either `max_age` affects the
   Graph token's lifetime, or the 7 minutes are tenant policy"*.

**The experiment requires a real Azure login against the live tenant.** It
cannot be simulated, mocked, or inferred. If you cannot perform it, the honest
outcome is to leave the criterion unchecked and say so — **do not** write a
result you did not measure. The spec already records the hypothesis as
unverified for exactly this reason.

---

## Scope

**Docs** (`docs/`, reStructuredText, wired through `docs/index.rst`'s toctree):
- The four new session keys: `id_token`, `external_expires_at`,
  `has_refresh_token`, `external_provider_user_id` — including the explicit
  warning that `session["refresh_token"]` is **Navigator's own** token and the
  provider's refresh token is never in the session.
- `ExternalAuth.get_live_provider_token` — what it is for (a session can
  outlive the provider token by ~850×), that it is **on demand** and not a
  middleware, and that a consumer reading `session["auth_token"]` directly
  still gets a dead token.
- The `expires_in` / `expires_at` change, marked **client-visible**, pointing
  at the existing B1 decision (`backends/oauth2/backend.py:9`).
- `AZURE_FLOW_TTL` and the narrowed `AZURE_SESSION_TIMEOUT`, in
  `docs/settings.rst`.

**Experiment**:
- With TASK-109 landed (`max_age` adjustable on its own), raise or remove
  `max_age` at `azure.py:212`, log in, take `session["auth_token"]`, decode it,
  and compute `exp - iat`.
- Record the outcome as a one-line note in the spec's §7 Known Risks, and flip
  §8 Q1's note to state which of the two explanations held.

**NOT in scope**: `CHANGELOG.md` (TASK-107 owns it — do not duplicate the
entry); changing `max_age`'s committed value (spec Non-Goals — the experiment
is a measurement, not a change); chasing a tenant policy change (explicit spec
Non-Goal); the `ai-parrot` `IdentityMappingService` 42P10 issue (spec §8 Q5 —
owned by the ai-parrot side).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `docs/settings.rst` | MODIFY | `AZURE_FLOW_TTL`, narrowed `AZURE_SESSION_TIMEOUT` |
| `docs/vault.rst` | MODIFY | credential capture + `get_live_provider_token` (or a new page — see FILL IN) |
| `docs/api.rst` | MODIFY | the `expires_in` / `expires_at` response change, marked client-visible |
| `sdd/specs/external-provider-token-capture.spec.md` | MODIFY | §7 one-line experiment note; §8 Q1 outcome |

---

## Codebase Contract

### Verified docs layout
```
docs/
  index.rst        # toctree (verified: :33-40) lists: api, config, settings,
                   #   token_exchange, and more below :40 — read it before
                   #   adding a page, and add any NEW page to the toctree or
                   #   Sphinx will warn (and this repo treats docs warnings
                   #   as noise worth avoiding)
  api.rst          # HTTP surface
  settings.rst     # settings reference; existing section shape verified below
  vault.rst        # "User Vault" — already documents auth.user_identities and
                   #   the navigator_session.vault cipher (verified: :1-7)
  token_exchange.rst, passkey.rst, security.rst, config.rst, policies.py, ...
```

```rst
.. docs/settings.rst — the section + definition-list shape to copy
   (verified: :1-20)

Settings
=========

Token Exchange (FEAT-096)
--------------------------

``TOKEN_EXCHANGE_MAX_TTL``
   Integer, seconds. Fallback session/JWT lifetime used when the external
   provider token reports no expiry (e.g. classic GitHub OAuth tokens).
   Defaults to the same value as the platform's ``SESSION_TIMEOUT``.
```

### Verified facts to document (do not re-derive these)
```
Measured (spec §6, 2026-10-22, real token from a live session["auth_token"]):
  aud       https://graph.microsoft.com        <- a Graph token, NOT a Navigator JWT
  iat       1792689808   exp 1792690227
  lifetime  419 s = 7.0 min
A Navigator JWT on the same tree, for comparison:
  session_timeout 360000 s (100 h)
  => the session can outlive the provider token by ~850x.

New session keys (spec §2 "Data Models"):
  id_token                   Optional[str]  provider OIDC id_token
  external_expires_at        Optional[str]  ISO-8601; name reused from
                                            exchange.py:206-209 / basic.py:152
  has_refresh_token          bool           presence marker, NEVER the token
  external_provider_user_id  Optional[str]  verified login account binding

The refresh token lives ciphered in auth.user_identities via
IdentityStore.save_linked_identity (identity/store.py:112) — never in the
session, never in an HTTP response.

expires_in / expires_at: extends the EXISTING named decision
"B1: expires_in is seconds (int)" (backends/oauth2/backend.py:9, :1861-1863,
:1953, :2056) to the legacy login publishers. `usr.expires_in` changes the
same way and gains `usr.expires_at`; it is an UNDECLARED dynamic attribute
(identities.py declares access_token at :164 but no expires_in), reaching
consumers via save_encoded_data(request, "user", user) (abstract.py:304).

AZURE_FLOW_TTL   getint, 600 — Redis TTL of the login-flow record (azure.py:217).
                 600 matches every sibling flow TTL in conf.py (:350, :506,
                 :543, :726, :785, :854); PASSKEY_CHALLENGE_TTL (:590) is 300.
AZURE_SESSION_TIMEOUT  getint, 120 — the OIDC max_age freshness requirement
                 only (azure.py:212), enforced by MSAL on the callback with a
                 hardcoded 120 s skew (msal/oauth2cli/oidc.py:310-328).
```

### The experiment procedure (spec §8 Q1, verbatim intent)
```
Needs TASK-109 (max_age adjustable independently of the flow TTL).
1. Raise or remove `max_age` at azure.py:212.
2. Log in through the Azure browser flow against the live tenant.
3. Read session["auth_token"] and decode it (claims only — do NOT paste the
   token anywhere, do NOT send it to any service; decode locally).
4. Compute exp - iat.
Outcome A: the lifetime changes  => Q1 and Q4 share one cause; max_age is the
           lever.
Outcome B: the lifetime does not change => the 7 minutes are tenant policy, and
           every Graph-using session refreshes roughly every 5 minutes at
           IDENTITY_REFRESH_LEEWAY=120.
Either outcome is a ONE-LINE note in spec §7. Neither blocks a module.
Unverified hypothesis on record: `max_age` is an OIDC freshness request and the
token carries exactly freshness claims (acrs ["p1","pfdr"], xms_pftexp = iat +
25.5 h) — suggestive, NOT evidence.
```

### Does NOT Exist (do not reference)
- **No** existing docs page for the identity-credential **capture** path.
  `docs/vault.rst` covers storage and the cipher; it does not cover the login
  negotiation. Extending it is likely right; a new page needs a toctree entry.
- **No** docs page listing session keys. Check `docs/api.rst` and
  `docs/token_exchange.rst` (which already mentions `external_expires_at`
  territory) before inventing a location.
- **No** Markdown in `docs/` — it is Sphinx/reStructuredText (`docs/conf.py`,
  `docs/Makefile`), except `../README.md` which is `include`d at
  `docs/index.rst:24`.
- **No** way to run the experiment without a live Azure tenant login. There is
  no fixture, no sandbox tenant, and no recorded cassette for it.

---

## Implementation Blueprint

### Steps (in order)
1. Read `docs/index.rst`'s full toctree and `docs/settings.rst`,
   `docs/vault.rst`, `docs/api.rst` — decide placement **before** writing, and
   prefer extending an existing page over adding one.
2. Block A: `docs/settings.rst` — the two Azure settings.
3. Block B: the capture/refresh documentation.
4. Block C: the `expires_in` / `expires_at` client-visible note.
5. Block D: the experiment, **if** a live login is available; otherwise record
   honestly that it was not run.
6. `make -C docs html` (or whatever this repo's docs build is — check
   `docs/Makefile`) and confirm no new warnings.

### Block A — `docs/settings.rst`
```rst
.. AFTER — append a new section; match the existing heading underline style
   (``=====`` for the title, ``------`` for sections) verified at :1-6
.. occurrences: n/a (new section)

Azure / Entra ID (FEAT-103)
----------------------------

``AZURE_SESSION_TIMEOUT``
   Integer, seconds. The OIDC ``max_age`` freshness requirement sent to Entra
   ID on ``initiate_auth_code_flow``. MSAL enforces it on the callback with its
   own hardcoded 120-second skew, so a user who lingers on the Microsoft login
   screen longer than this gets an authentication error. Defaults to ``120``.
   **This is not a TTL** — before FEAT-103 the same setting also governed the
   Redis lifetime of the login-flow record; that job moved to
   ``AZURE_FLOW_TTL``.

``AZURE_FLOW_TTL``
   Integer, seconds. Redis lifetime of the pending login-flow record written
   when the browser is redirected to Microsoft. If it expires before the user
   returns, the callback answers *"Lost Authentication Flow, please try
   again."* Defaults to ``600``, matching every other flow-record TTL in
   ``navigator_auth/conf.py``.
```
**Why document them together**: they were one setting until FEAT-103, and the
single most likely future mistake is re-merging them. The cross-reference in
each entry is the guard.

### Block B — capture and `get_live_provider_token`
```rst
.. FILL IN: write this section. Placement decision first — extend
   ``docs/vault.rst`` (which already covers ``auth.user_identities`` and the
   cipher, :1-7) or add a new page plus a ``docs/index.rst`` toctree entry.
   Bounded by spec §5: it must cover (a) the four new session keys, (b)
   ``get_live_provider_token``, and (c) the warning below. Use the verified
   facts block in the Codebase Contract above — do not re-derive the numbers.

   It MUST state, in these terms:
   - The provider's refresh token is NEVER in the session and NEVER in an HTTP
     response. It is ciphered into ``auth.user_identities``. The session carries
     only ``has_refresh_token``.
   - ``session["refresh_token"]`` is NAVIGATOR's own refresh token, indexed in
     Redis as ``auth:refresh_token:<tok>`` for 90 days. It is a different
     credential with a colliding name.
   - A session can outlive the provider access token by ~850x (a measured
     7-minute Entra token inside a 100-hour session). A consumer that reads
     ``session["auth_token"]`` directly still gets a dead token;
     ``get_live_provider_token`` is the supported way to obtain a live one.
   - ``get_live_provider_token`` is ON DEMAND. There is deliberately no
     middleware refreshing on every request.
   - It never falls back to another linked account: a session bound to external
     account A is never served account B's credential.
```

### Block C — the `expires_in` / `expires_at` change
```rst
.. FILL IN: add to ``docs/api.rst`` (or wherever that file documents the
   login/refresh/token response bodies — read it first). Bounded by spec §5:
   the change must be marked CLIENT-VISIBLE. Required content:
   - ``expires_in`` is now an integer number of seconds remaining (RFC 6749
     §4.2.2). It previously carried an absolute epoch, which no client could
     correctly consume.
   - ``expires_at`` is new and carries the absolute epoch.
   - This extends the repo's existing ``B1`` decision
     (``navigator_auth/backends/oauth2/backend.py``) to the legacy login
     publishers; the OAuth2 provider backend already behaved this way.
   - ``request.user.expires_in`` changes identically and gains
     ``request.user.expires_at``. That attribute is undeclared on ``Identity``,
     so there is no version to bump — any consumer reading it as a timestamp
     must switch to ``expires_at``.
   Do NOT duplicate the CHANGELOG entry (TASK-107 owns it); cross-reference it.
```

### Block D — the experiment
```markdown
# FILL IN — only if a live Azure login is available.
#
# Procedure: see "The experiment procedure" in the Codebase Contract above.
#
# Then edit sdd/specs/external-provider-token-capture.spec.md:
#  1. §7 Known Risks — replace the bullet beginning "**The 7-minute lifetime
#     has no verified cause** (§8 Q1)" with the measured outcome, in ONE line,
#     stating the measured lifetime and the max_age value used.
#  2. §8 Q1 — append "— *Measured <date>*: <outcome>" to the resolution note.
#  3. Revision History — add a row.
#
# IF THE EXPERIMENT WAS NOT RUN: change nothing in the spec, leave spec §5's
# criterion unchecked, and state plainly in the Completion Note that it was not
# run and why. A fabricated measurement is worse than a missing one — the spec
# explicitly records the hypothesis as unverified, and a result nobody measured
# would read as corroboration.
#
# Handling the token: decode it LOCALLY (claims only). Never paste it into any
# service, never commit it, never log it. If it reaches a transcript, treat it
# as a leaked credential.
```

### FILL IN checklist
- [ ] Placement decision for Block B (extend `docs/vault.rst` vs. new page +
      toctree entry).
- [ ] Block B: the section text.
- [ ] Block C: the `docs/api.rst` location and text.
- [ ] Block D: run the experiment and record it, **or** record that it was not
      run and why.

---

## Implementation Notes

### Key Constraints
- `docs/` is Sphinx/reStructuredText. A new page that is not in
  `docs/index.rst`'s toctree produces a build warning.
- Do not duplicate the `CHANGELOG.md` entry — TASK-107 writes it; cross-link.
- **Do not fabricate the experiment result.** This is the one acceptance
  criterion in FEAT-103 that cannot be satisfied by code, and the spec is
  already explicit that the hypothesis is unverified.
- Never commit, log or transmit a real token taken during the experiment.

### References in Codebase
- `docs/settings.rst:1-20` — section and definition-list style.
- `docs/vault.rst:1-7` — the existing `auth.user_identities` / cipher page.
- `docs/index.rst:33-40` — the toctree.
- `docs/token_exchange.rst` — an existing feature page written for FEAT-096;
  the closest model for a FEAT-103 page if a new one is warranted.

---

## Acceptance Criteria

- [ ] `docs/` documents the four new session keys, including the
      `session["refresh_token"]` collision warning
- [ ] `docs/` documents `get_live_provider_token`, its on-demand nature, and
      the ~850× session/token asymmetry
- [ ] `docs/` documents the `expires_in` / `expires_at` change and marks it
      client-visible, including `usr.expires_at`
- [ ] `docs/settings.rst` documents `AZURE_FLOW_TTL` and the narrowed
      `AZURE_SESSION_TIMEOUT`
- [ ] The docs build produces no new warnings
- [ ] Either: the §8 Q1 experiment has been run and its outcome recorded as a
      one-line note in spec §7 plus an update to §8 Q1 — **or** the Completion
      Note states explicitly that it was not run, and why
- [ ] No token value appears in any committed file

---

## Test Specification

No automated tests. The docs build is the check; the experiment is a manual
measurement whose evidence is the recorded `exp - iat` value and the `max_age`
used.

---

## Agent Instructions

1. **Read the spec** §5's last two criteria, §8 Q1, §3 Module 8 ("Unblocks"),
   and §7 Known Risks.
2. **Check dependencies** — TASK-106, TASK-107, TASK-109 in
   `sdd/tasks/completed/`. The experiment is impossible before TASK-109.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve every `FILL IN`.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-113-docs-changelog-maxage-experiment.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note** — and be explicit about the experiment.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Docs half DONE: docs/settings.rst (AZURE_SESSION_TIMEOUT narrowed + AZURE_FLOW_TTL), docs/vault.rst (new "External provider credential capture" section: the four session keys, refresh-token-never-in-session, `session["refresh_token"]` collision warning, get_live_provider_token on-demand semantics, ~850x asymmetry, no cross-account fallback, masked check_credentials), docs/api.rst (client-visible expires_in/expires_at + usr.expires_at, cross-ref to CHANGELOG; CHANGELOG itself not duplicated). Placement: extended vault.rst/api.rst (no new page, so no toctree change). The measured 419 s figure is quoted from the spec §6, not re-measured by me.
**Docs build NOT verified**: sphinx and docutils are not installed in the shared venv, so `make -C docs html` was not run; the RST was written to match the existing page style but is unbuilt.
**Experiment (§8 Q1): NOT run.** It needs a live Azure/Entra login by the operator against the real tenant, which this unattended run cannot perform. NOTHING was measured and NO result was written: the spec file was deliberately left unmodified (§7 bullet "The 7-minute lifetime has no verified cause" and §8 Q1 unchanged; §5's experiment criterion remains unchecked). Operator procedure: with AZURE_SESSION_TIMEOUT now independent of the flow TTL, raise it (or remove max_age at AzureAuth.authenticate) locally, log in via the browser flow, decode session["auth_token"] LOCALLY (claims only, never paste/commit it), compute exp - iat; if it differs from 419 s then max_age is the lever (Q1/Q4 share a cause), otherwise the 7 minutes are tenant policy. Record as a one-line note in spec §7 and update §8 Q1 + revision history.
**Deviations from spec**: spec file not modified (experiment unrun) although the task table lists it as MODIFY; task closed as done-with-issues.
