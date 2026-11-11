# TASK-148: Documentation — `docs/two_factor_auth.rst`, CHANGELOG, docs index

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-147
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 13** and **§10 Documentation** (policy:
`required`), closing spec **AC21**. The page is the operator contract: how to
turn 2FA on, what each setting does, what the delivery callback receives, how a
tenant is enforced safely, how administrators recover, and — just as important —
the bounds the feature knowingly accepts (shared mailbox R7, unverified
addresses R4, the `PASSKEY_USER_VERIFICATION` caveat R6).

It runs last (after TASK-147's end-to-end tests) so every statement can be
checked against code that exists and passes: **document what was built**. If
the implementation diverged from the spec or the contract in a way the
completed tasks' Completion Notes record, the docs follow the code and the
divergence is mentioned in this task's Completion Note.

Decomposition decisions the docs must describe (contract `feat106_contract.md`):
D1 (refusal codes), D6 (`AUTH_MFA_NOTIFY_CALLBACK`), D7 (membership from
`organization_users`), D8–D10 (policy/state semantics), D11 (AMR values), D13
(enabled-but-unavailable refuses every BasicAuth login), D18
(`apply_tenant_policy` recipe), D20 (replacement proof), D21 (backup codes),
D22 (global logout unwired), D23 (passkey removal revokes devices).

---

## Scope

- Create `docs/two_factor_auth.rst` covering **every** item of spec §10 plus the
  decision-derived items above (checklist in the blueprint).
- Add `two_factor_auth` to the root `toctree` in `docs/index.rst`, after
  `passkey`.
- Add a FEAT-106 entry at the top of `# Unreleased` in `CHANGELOG.md`, in the
  house style of the FEAT-105 entry (bold lead sentence, behaviour-change flag,
  new public surfaces, link to the page).
- Build the docs to check the page renders.

**NOT in scope**: any code change; `docs/settings.rst` (not required by §10);
README changes; an API reference generator run beyond what `sphinx` already does
for `navigator_auth.mfa` (spec `api_modules`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `docs/two_factor_auth.rst` | CREATE | Operator documentation |
| `docs/index.rst` | MODIFY | Add the page to the toctree |
| `CHANGELOG.md` | MODIFY | FEAT-106 entry under `# Unreleased` |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11). Line numbers of code written by
> TASK-129…TASK-147 are not known yet — cite symbols, not lines, in the page.

### Existing docs to match in tone and structure

- `docs/password_recovery.rst` — callback contract and "navigator-auth never
  sends e-mail" wording (spec cites `docs/password_recovery.rst:9`).
- `docs/passkey.rst` — `PASSKEY_USER_VERIFICATION` documentation (R6 caveat
  cross-reference target).
- `docs/vault.rst` — the session vault the reserved `mfa:` namespace is carved out of.

### Settings (TASK-129, spec M1 + D6) — names and defaults to document

| Setting | Default | Notes |
|---|---|---|
| `AUTH_BASIC_2FA_ENABLED` | `False` | global kill switch; off ⇒ login path byte-identical (AC20) |
| `AUTH_OTP_SECRET` | — | HMAC key; **required** when enabled, no fallback (D13) |
| `AUTH_OTP_CHALLENGE_TTL` | `300` | seconds |
| `AUTH_OTP_MAX_ATTEMPTS` | `5` | per challenge; 5th failure burns it |
| `AUTH_OTP_CODE_LENGTH` | `6` | e-mail code digits |
| `AUTH_OTP_RATE_USER` / `AUTH_OTP_RATE_IP` | `10/hour` / `30/hour` | strict limiter, fails closed (D19) |
| `AUTH_OTP_EMAIL_CALLBACK` | — | dotted path; receives `OtpNotificationPayload` |
| `AUTH_TOTP_ISSUER` | `Navigator` | label in authenticator apps |
| `AUTH_MFA_BACKUP_CODE_COUNT` / `_LENGTH` | `10` / `8` | |
| `AUTH_MFA_NOTIFY_CALLBACK` | — | dotted path; receives `MfaSecurityNotice` (D6) |

### HTTP surface (contract §3 TASK-140/141/142)

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/v1/login` | — | owing a factor ⇒ `401 {"mfa_required": true, "challenge", "providers", "preferred", "expires_in"}`; refusal ⇒ `{"error": <code>, "message"}` |
| `POST /auth/mfa/challenge` | challenge token | resend (e-mail); identical response either way |
| `POST /auth/mfa/verify` | challenge token | `{challenge, provider, code, remember_device?}` ⇒ session |
| `POST /auth/mfa/totp/enroll` | session + fresh password | pending seed (5 min) |
| `POST /auth/mfa/totp/confirm` | same session | installs TOTP; initial backup codes once (D21) |
| `DELETE /auth/mfa/totp` | session + fresh password | disenrol (downgrade) |
| `POST /auth/mfa/backup-codes` | session + fresh password | regenerate (strong-factor users) |
| `DELETE /auth/mfa/{user_id}` | `mfa:disenroll` + tenant ownership | admin disenrol |

Refusal codes (D1): `strong_factor_required` (403), `no_factor_available` (403),
`mfa_unavailable` (503). AMR values (D11): `pwd`, `otp` (e-mail), `totp`,
`backup`, `trusted_device`.

### Anchors

| File | Anchor | Occurrences |
|---|---|---|
| `docs/index.rst` | `   passkey` (toctree entry, :41) | 1 (verified: `grep -cF '   passkey' docs/index.rst`) |
| `CHANGELOG.md` | `# Unreleased` (:1) | 1 (verified: `grep -cF '# Unreleased' CHANGELOG.md`) |

### Does NOT Exist (Anti-Hallucination)

- ~~SMS OTP~~, ~~external-IdP enforcement~~, ~~an HTTP admin API for the tenant
  policy~~, ~~e-mail verification~~ — spec non-goals; document them as such.
- ~~a `security_admin` group shipped by navigator-auth~~ — the pack *names* it;
  the deployment must create it (spec §6).
- ~~a "logout everywhere" endpoint~~ — D22: the revocation hook exists, the
  endpoint does not.
- ~~`pyotp` / `qrcode`~~ — the QR is rendered client-side from the `otpauth://` URI.

---

## Implementation Blueprint

### `docs/two_factor_auth.rst` — CREATE (four blocks, one file)

**Block 1 — overview, enabling, settings:**

```rst
Two-factor authentication for BasicAuth
=======================================

FEAT-106 adds a second factor to ``BasicAuth`` (username + password): **TOTP**
(Google-Authenticator-compatible) and **e-mail one-time codes**, enforced per
tenant. No new runtime dependency: TOTP comes from ``cryptography``.

.. contents::
   :local:
   :depth: 2

How it works
------------

.. FILL IN: 2-3 paragraphs — bounded by spec §2 Overview, G1-G8:
   * the second factor is checked inside ``BasicAuth.authenticate()``; a provider can
     never create a session on its own;
   * owing a factor returns ``401`` with a challenge envelope and NO token;
   * ``TokenExchangeAuth`` is never challenged; a passkey sign-in satisfies enforcement
     with no OTP (AC10, AC11);
   * external-IdP logins are out of scope (the IdP enforces MFA);
   * ``AUTH_BASIC_2FA_ENABLED=False`` leaves the login path byte-identical (AC20);
   * enabled but MFA storage unavailable (tables missing, Redis/Postgres down,
     ``AUTH_OTP_SECRET`` unset) refuses every BasicAuth login with ``mfa_unavailable``
     — fail closed, startup still succeeds (D13, AC24).

Settings
--------

.. FILL IN: a list-table of the settings in this task's Codebase Contract, with defaults
   and one-line meaning each. Call out: AUTH_OTP_SECRET is required (no SECRET_KEY
   fallback); the rate limiters fail CLOSED on a Redis error, unlike password recovery's.

Login flow and responses
------------------------

.. FILL IN: the 401 envelope (exact JSON keys), the verify request body, the three
   refusal codes with HTTP status, the AMR values (D11) and what ABAC sees
   (``mfa=True``; ``amr`` lets a policy demand a FRESH factor and reject
   ``trusted_device`` — AC19). Include a short curl-style example of the two steps.
```

**Block 2 — delivery callbacks, state machine, providers:**

```rst
E-mail delivery callback
------------------------

navigator-auth never sends e-mail. With ``AUTH_OTP_EMAIL_CALLBACK`` set to a
dotted path, the callable (sync or async) receives an ``OtpNotificationPayload``:

.. FILL IN — bounded by spec §2 OtpNotificationPayload, R9, AC14:
   field list (email, display_name, username, code, expires_at, found); the code is
   the ONLY place a live code exists — never log it, never ``model_dump()`` it (its
   repr is redacted); a raising callback is contained and logged at WARNING; the HTTP
   response is identical whether delivery succeeded or not (no enumeration oracle);
   a broken callback is an outage for every e-mail-state user in an enforced tenant (R9).

Security notifications (``AUTH_MFA_NOTIFY_CALLBACK``)
-----------------------------------------------------

.. FILL IN — bounded by D6: optional dotted path receiving ``MfaSecurityNotice``
   (email, display_name, username, event, occurred_at, actor) after downgrades
   (TOTP disenrol, admin disenrol, last-passkey removal); unset => logged at INFO.

Per-user state: none → email → totp
-----------------------------------

.. FILL IN — bounded by D10, spec M7, AC9, AC27:
   * table: OFF/OPTIONAL+unenrolled => no challenge; ENFORCED => e-mail floor (no
     enrolment needed); TOTP confirmed => totp;
   * a STRONG factor (confirmed TOTP or a registered passkey) CLOSES the e-mail path;
   * deleting the last passkey of an ordinary user without TOTP reopens e-mail, is
     audited and revokes trusted devices (D23);
   * backup codes: 10 x 8, shown once (initial set at TOTP confirmation, D21),
     single-use, regenerate with password re-authentication;
   * a user with no factor available (no address, or passkey-only without backup
     codes) gets ``no_factor_available`` — passkey holders sign in with the passkey.

Enrolling and replacing TOTP
----------------------------

.. FILL IN — bounded by spec §3 "Pending enrollment and replacement", D20, AC29:
   fresh password on every enrolment; replacing an existing strong factor ALSO needs a
   current TOTP code, an unused backup code, or a passkey sign-in session younger than
   AUTH_OTP_CHALLENGE_TTL (never an e-mail code or a trusted-device cookie); the pending
   seed lives 5 minutes, bound to user/session/security version, and never replaces the
   active seed before confirmation; confirmation is single-use, marks its TOTP step used,
   revokes trusted devices and invalidates outstanding challenges. QR rendering is
   client-side from the ``otpauth://`` URI.
```

**Block 3 — tenant policy, pre-flight, admin disenrolment:**

```rst
Per-tenant policy
-----------------

Policy is data in ``auth.tenant_mfa_policy`` (``org_id``, ``mode`` =
``off|optional|enforced``, ``remember_days``). It is read on every login.

.. FILL IN — bounded by D7, D8, D9, AC22:
   * membership comes from ``auth.organization_users`` keyed by the authenticated user —
     never from ``X-Org-Id``/``X-Client-Id``; deployments must have that table (as
     ``auth.vw_users`` does) for tenant enforcement; no membership => no policy (OFF),
     never a global default;
   * several organizations => strictest mode wins, smallest remember_days among
     non-OFF orgs wins.

Changing a policy (the transactional recipe)
--------------------------------------------

.. FILL IN — bounded by D18, AC18, AC23, AC30: always use
   ``navigator_auth.mfa.policy.apply_tenant_policy(...)`` (show the call with every
   keyword argument), never a bare ``UPDATE``: hardening (stricter mode, or fewer
   remember_days) bumps every member's security version, revokes the tenant's trusted
   devices and writes an ``auth.user_mfa_audit`` row in ONE transaction; relaxing only
   audits. Note the context digest also catches raw SQL edits, but devices are only
   revoked by the recipe.

Pre-flight before enforcing
---------------------------

.. FILL IN — bounded by spec M12, AC15, R3, R4: ``python -m scripts.preflight_mfa --org-id N``;
   B1 (active member without a usable address) and B2 (active superuser without a strong
   factor) each block; exit codes 0/1/2; it cannot detect a WRONG address; it is an
   activation check — the login path keeps enforcing both rules afterwards.

Administrative disenrolment and separation of duties
----------------------------------------------------

.. FILL IN — bounded by spec M10/M11, AC16, AC26, R1, D21:
   * ``DELETE /auth/mfa/{user_id}`` needs the ``mfa:disenroll`` action from
     ``abac/default_policies/mfa_admin_access.yaml`` (granted to ``security_admin``,
     which the deployment must create) AND the actor's organizations must include the
     target's; it switches TOTP off and invalidates backup codes, nothing else; revokes
     trusted devices; writes a durable audit row; notifies the user;
   * ``.. warning::`` adding ``mfa:*`` or ``"*"`` to ``admin_full_access.yaml`` collapses
     the separation of duties; without the pack NOBODY can disenrol (fail closed);
   * R1: ``UserManager`` can still edit ``email`` — a principal holding BOTH user CRUD
     and ``mfa:disenroll`` can take over an account (accepted, follow-up FEAT-107).
```

**Block 4 — remember-me, recovery, security notes:**

```rst
Remember this device
--------------------

.. FILL IN — bounded by spec M6, AC17, AC18, AC19, D15, D22, D23:
   offered only to strong-factor users when remember_days > 0; skips the OTP, never the
   password; HttpOnly + Secure + SameSite=Lax cookie ``nav_mfa_device``; rotates on every
   use, replay revokes the family, window never extended; session has
   ``amr=["pwd","trusted_device"]``. Invalidation list: password change, recovery
   completion, TOTP enrol/disenrol, admin disenrol, tenant hardening, passkey removal.
   "Logout everywhere" has a revocation hook but no endpoint yet (D22); single-session
   logout does not revoke devices.

Recovering an enforced superuser
--------------------------------

.. FILL IN — bounded by spec §3 "Superuser invariant and recovery", AC33:
   an enforced superuser without a strong factor gets ``strong_factor_required`` — no
   e-mail fallback, no trusted device, including after promotion or factor loss;
   self-removal of the last strong factor is refused; recovery = a backup code while TOTP
   is still registered, another registered passkey, or the audited operator procedure
   (temporarily remove the privileged role → recover/re-enrol → restore the role only
   after the strong-factor check passes). No password-only or e-mail-only grace session.

Challenges, attempts and invalidation
-------------------------------------

.. FILL IN — bounded by spec §3 "Challenge validity" and "Retry accounting", AC30, AC31:
   five attempts per challenge (attempts 1-4 keep it, the 5th failure burns it, a correct
   code consumes it); resend needs the live challenge, rotates the e-mail code and keeps
   the original expiry and attempt budget; password change/reset, recovery completion,
   factor changes, passkey registration/removal and policy hardening invalidate
   outstanding challenges; Redis/Postgres failures refuse verification.

Protected seed storage
----------------------

.. FILL IN — bounded by spec §3 "Protected seed namespace", AC25, AC28: TOTP seeds are
   sealed by the vault kernel in ``auth.user_vault_secrets`` under the reserved ``mfa:``
   prefix with an MFA-specific AAD (a copied seed fails to open); the session-vault HTTP
   API rejects ``mfa:`` keys and hides them from listings; the session vault loader never
   decrypts them; seeds are read during verification without a session and a vault error
   refuses the login.

Accepted bounds
---------------

.. FILL IN — bounded by R4, R6, R7, §1 Non-Goals:
   * shared mailbox (R7): a compromised mailbox yields both the e-mail factor and the
     password-reset path — why superusers may not stay on the e-mail floor;
   * unverified addresses (R4): the floor is worth the tenant's address hygiene;
   * ``PASSKEY_USER_VERIFICATION`` (R6): "a passkey satisfies enforcement" holds only while
     it is ``required`` (the default); lowering it makes passkeys single-factor —
     cross-reference :doc:`passkey`;
   * non-goals: SMS, external-IdP enforcement, policy HTTP API, e-mail verification.
```

**Why the page is FILL IN-heavy.** Prose must describe the code as merged, not
as planned; the blueprint fixes the section list and the facts each section must
contain (each bounded by a spec item or decision), so a reviewer can tick AC21
section by section.

### `docs/index.rst` — MODIFY

```rst
   passkey
   two_factor_auth
```

`# AFTER — insert "   two_factor_auth" below "   passkey" (verified: docs/index.rst:41)`
`# occurrences: 1 (verified: grep -cF '   passkey' docs/index.rst)`

**Why there.** It sits with the other authentication pages (`token_exchange`,
`passkey`, `password_recovery`); 2FA is read right after passkeys because
passkeys are its strongest factor.

### `CHANGELOG.md` — MODIFY

`# AFTER — insert below "# Unreleased" and its blank line (verified: CHANGELOG.md:1)`
`# occurrences: 1 (verified: grep -cF '# Unreleased' CHANGELOG.md)`

```markdown
- **Two-factor authentication for BasicAuth (FEAT-106, opt-in).** TOTP
  (Google-Authenticator-compatible) and e-mail one-time codes as a second factor
  for username/password logins, enforced per tenant through the new
  `auth.tenant_mfa_policy` table. Off by default (`AUTH_BASIC_2FA_ENABLED`); when
  off the login path is unchanged. # FILL IN: 4-8 more lines — the 401
  `mfa_required` envelope (integrator-visible), the `/auth/mfa/*` routes, the six
  new tables, new settings (`AUTH_OTP_*`, `AUTH_TOTP_ISSUER`, `AUTH_MFA_*`), the
  `mfa_admin_access.yaml` pack and `mfa:disenroll`, `scripts/preflight_mfa.py`,
  the reserved `mfa:` vault namespace (generic vault API now rejects it), and
  "See `docs/two_factor_auth.rst`". Mirror the FEAT-105 entry's style.
```

**Why first.** Newest entry first, matching the existing `# Unreleased` list.

### Steps (in order)

1. Confirm TASK-147 is done and read the Completion Notes of TASK-129…147 for
   any deviation that the docs must reflect.
2. Write the page, section by section; verify each claim against the code
   (grep the symbol) before writing it.
3. Add the toctree entry and the CHANGELOG entry.
4. Build the docs (see Test Specification) and fix warnings introduced by the page.
5. Tick the AC21 checklist below.

### FILL IN checklist

- [ ] How it works (incl. D13 fail-closed, AC20)
- [ ] Settings table (incl. `AUTH_MFA_NOTIFY_CALLBACK`)
- [ ] Login flow / envelope / refusal codes / AMR / ABAC fresh-factor note
- [ ] E-mail callback contract (navigator-auth never sends e-mail)
- [ ] Security notifications (D6)
- [ ] State machine + what closes e-mail + passkey deletion (D23)
- [ ] Enrolment & replacement proof (D20) + pending seed rules
- [ ] Per-tenant policy, strictest wins, membership requirement (D7)
- [ ] `apply_tenant_policy` recipe (D18)
- [ ] Pre-flight (B1/B2, exit codes, R4 limit)
- [ ] Admin disenrolment, `security_admin`, `mfa:*`/`"*"` warning, R1
- [ ] Remember-me + invalidation list + unwired global logout (D22)
- [ ] Enforced-superuser recovery procedure
- [ ] Challenge attempts / resend / invalidation rules
- [ ] Protected seed namespace
- [ ] Accepted bounds R4, R6, R7 + non-goals
- [ ] toctree entry; CHANGELOG entry

---

## Acceptance Criteria

- [ ] **AC-1** `docs/two_factor_auth.rst` exists and covers every spec §10 item: the `AUTH_OTP_*` settings; the `AUTH_OTP_EMAIL_CALLBACK` contract and that navigator-auth never sends e-mail; the `none → email → totp` state machine and what closes the e-mail path; the per-tenant table and strictest-wins; the pre-flight and both blocking conditions; the `mfa:disenroll` policy, the group it must be granted to and the `mfa:*`/`"*"` warning; the remember-me invalidation list; R7, R4 and the `PASSKEY_USER_VERIFICATION` caveat (R6); the protected seed namespace; pending enrolment/replacement proof; challenge invalidation and resend/attempt rules; the transactional policy-change recipe; enforced-superuser recovery.
- [ ] **AC-2** It also documents D6 (`AUTH_MFA_NOTIFY_CALLBACK`), D7 (membership requirement), D13 (fail-closed when unavailable) and D22 (global logout unwired).
- [ ] **AC-3** `docs/index.rst` lists `two_factor_auth` in the root toctree.
- [ ] **AC-4** `CHANGELOG.md` has a FEAT-106 entry as the first item under `# Unreleased`.
- [ ] **AC-5** The Sphinx build introduces no new warning from `two_factor_auth.rst`.
- [ ] **AC-6** No secret, real address or real code appears in examples (use `user@example.com`, `123456`).
- [ ] Closes spec **AC21**.

---

## Test Specification

```bash
source .venv/bin/activate
python -m sphinx -b html -q docs /tmp/feat106-docs 2>&1 | grep -i "two_factor_auth" ; true
grep -c "two_factor_auth" docs/index.rst          # 1
head -5 CHANGELOG.md | grep -c "FEAT-106"         # 1
for term in AUTH_OTP_EMAIL_CALLBACK AUTH_MFA_NOTIFY_CALLBACK apply_tenant_policy preflight_mfa \
            mfa:disenroll security_admin PASSKEY_USER_VERIFICATION organization_users \
            strong_factor_required trusted_device; do
  grep -q "$term" docs/two_factor_auth.rst || echo "MISSING: $term"
done
```

(If Sphinx or its extensions are not installed in `.venv`, record that in the
Completion Note and rely on `python -m docutils docs/two_factor_auth.rst /dev/null`
or `rst2html.py` for a syntax check.)

---

## Agent Instructions

1. **Read the spec** — §10 Documentation, §1 Non-Goals, §3 Security contracts,
   §7 R1/R4/R6/R7/R9; contract D1, D6, D7, D10, D13, D18, D20–D23.
2. **Check dependencies** — TASK-147 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Write** what the merged code does; where it differs from the spec, follow the
   code and note it below.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-148-mfa-docs-changelog.md`.
7. **Update index** → `"done"`; set the per-spec index `completed_at` if this is
   the last task.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: gpt-5.6-terra (codex), 1 attempt
**Date**: 2026-11-11
**Notes**: docs/two_factor_auth.rst (283 lines), docs/index.rst toctree entry and CHANGELOG FEAT-106 entry delivered. Worker checks: toctree count 1, CHANGELOG head matches FEAT-106, all required terms present in the page. AC-5 (Sphinx build without new warnings) NOT verified — sphinx is not installed in the shared venv; run the docs build in CI. Page documents flows that TASK-141/TASK-147 left under-tested (see ledger issues 64aa9130a1e1, c8f556d572ea).

**Deviations from spec**: none | describe if any
