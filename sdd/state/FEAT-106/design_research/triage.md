# Design Research triage — FEAT-106 basicauth-otp-2fa

Model: `gpt-5.6-luna` (codex-cli 0.166.0, reasoning_effort=high) · 11 suggestions
All 20 `affected_paths` passed repository containment and `test -e`.

Evidence spot-checks performed before adopting (CLAUDE.md: verify the reviewer):
- S4: `load_vault_for_session(session, user_id, db_pool, ...)` — `vault/integration.py:50-57`;
  requires a session object, and its docstring states "Vault failure MUST NOT block
  login — errors are logged and None is returned". **Claim confirmed.**
- S5: `auth_startup` runs `await backend.on_startup(app)` for every backend BEFORE
  `setup_vault_keyring(app)` and `setup_vault_tables(...)` — `auth.py:181,188,190`.
  **Claim confirmed, and sharper than stated**: a provider built in
  `BasicAuth.on_startup()` cannot capture the vault KeyRing, because it does not exist yet.
- S6: `_resolve_tenant` falls back to `(1, 1)` and prioritizes kwargs/trusted headers
  over `userinfo` — `abac/context.py:29`. **Claim confirmed.**

| # | Suggestion (kind) | Disposition | Reason | Landed in |
|---|---|---|---|---|
| S1 | Resolve MFA policy per request, not at backend startup (architecture) | CONFIRM (narrowed) | Right about the hazard; the design already resolves per login, but M9's wording let "builds the policy resolver" be read as caching a snapshot. Narrowed to: the resolver object is process-lifetime, the table read is per login, no caching. | §3 M7, M9; AC22 |
| S2 | Define an explicit non-session MFA challenge contract (api) | CONFIRM (corroboration) | Independently reached the same conclusion during §4 research, including the `if userdata: break` → `load_session` path. Valuable as agreement, not new information. | §2 Overview, §7 R2, M9, M10, AC6, AC7 |
| S3 | Make every MFA dependency fail closed (risk) | CONFIRM (extended) | The limiter was already inverted, but the reviewer correctly extends the posture to the vault read and the policy read — `vault/integration.py` logs-and-continues by design. | §7 R5, AC12 |
| S4 | Do not use the session-scoped vault API before a session exists (architecture) | CONFIRM | Verified. Verification runs before `open_session()`, so `load_vault_for_session` is both unusable (needs a session) and wrong (fails open). The seed must use the vault crypto primitives directly. | §3 M3, §7 R12 |
| S5 | Treat MFA schema initialization as a required migration (architecture) | CONFIRM in part / REJECT in part | CONFIRM: swallowing DDL failure would make MFA silently absent — a bypass — so logins must fail closed when the tables are missing and 2FA is enabled, and M8's "logs, never raises" contradicted G7. REJECT the "prevent MFA-enabled startup" half: hard-failing startup turns a missing table into a total outage for every tenant, including those with 2FA off. Fail the logins, not the process. | §3 M8, M9, §7 R13 |
| S6 | Protect tenant lookup from header and global-default confusion (risk) | CONFIRM | Verified. `_resolve_tenant` would let a trusted header pick the tenant and silently fall back to the `(1,1)` global policy. MFA must read organization membership from the authenticated user record and reject ambiguity. The §6 row citing `_resolve_tenant` as the mechanism was actively misleading and is corrected. | §3 M7, §6 Integration Points, §7 R14 |
| S7 | Specify factor-state transitions independently from passkey credentials (architecture) | CONFIRM | Real gap: passkey credentials carry no shared MFA state, and the spec did not say what happens when the last passkey is deleted — the e-mail path must reopen, or the user is locked out. | §3 M7, §2 edge cases, test |
| S8 | Require reauthentication and explicit authorization for factor management (api) | CONFIRM in part | The re-auth requirements were already specified (disenrol, backup-code regeneration) and `mfa:disenroll` already gates the admin route. The genuinely missing piece is a **tenant-ownership check**: a `security_admin` of one tenant must not disenrol a user of another. | §3 M10, AC16 |
| S9 | Do not treat existing UserDevices as trusted MFA devices (risk) | CONFIRM (corroboration) | Already an explicit "Does NOT Exist" entry with the same reasoning (1460-day device JWTs, ciphered `api_key`, referenced nowhere). Agreement, not new. | §6 Does NOT Exist, §3 M6 |
| S10 | Make security-transition audit records durable and action-specific (risk) | CONFIRM | The spec leaned on auditing as the mitigation for R1 (the `UserManager` takeover path), but `AuditLog` is best-effort and records authorization decisions, not factor-state changes — so the mitigation was weaker than claimed. Adds one table. | §3 M8, §7 R1, AC23 |
| S11 | Test invariants at the session boundary and under races (testing) | CONFIRM (extended) | Most invariants were already in §4; two were missing — concurrent submissions of the same challenge must consume exactly once, and cross-tenant policy/factor isolation. | §4 Unit + Integration |

Summary: **11** confirmed (2 in part) · **0** rejected outright · **0** escalated.

Note on the brief: the rendered template describes the project as "ai-parrot, an
async-first Python framework for AI agents". That is the shipped template's
boilerplate, not this repository (navigator-auth). Left verbatim per the §3b rule
against editing the brief; the reviewer had read-only repository access and its
citations are all navigator-auth paths, so the mismatch did not skew the output.
