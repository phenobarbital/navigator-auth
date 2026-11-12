---
id: FEAT-109
title: "PBAC example: add_policy() grants never reach the evaluator (428 on /dashboard/), plus log noise, short JWT key and an unmigrated vault secret"
slug: policy-issues
type: feature
mode: investigation
status: review
source:
  kind: inline
  jira_key: null
  jira_url: null
  fetched_at: 2026-11-11
  summary_oneline: "PBAC example (policy_server.py): unauth-path warnings, short HMAC key warning, vault integrity error, 428 deny on /dashboard/"
overall_confidence: medium
base_branch: dev
projects: [abac, auth-backends, examples]
tags: [pbac, pdp, add-policy, abac-middleware, hmac-key, vault-migration]
research_state: sdd/state/FEAT-109/
created: 2026-11-11
updated: 2026-11-11
---

# FEAT-109 — PBAC example: add_policy() grants never reach the evaluator, plus log noise, short JWT key and an unmigrated vault secret

> **Mode**: investigation
> **Confidence**: medium
> **Source**: `inline`
> **Audit**: [`sdd/state/FEAT-109/`](../state/FEAT-109/)

---

## 0. Origin

The original request, preserved verbatim. The full source is at `sdd/state/FEAT-109/source.md`.

> policy-issues -- minor issues testing PBAC Example at `python examples/policy_server.py`
>
> * warnings at middleware:
> ```
> [WARNING] 2026-11-11 14:27:10,443 root(middleware.py:43) :: Access to /.well-known/appspecific/com.chrome.devtools.json is not Authenticated.
> [WARNING] 2026-11-11 14:27:10,516 root(middleware.py:43) :: Access to /client-config is not Authenticated.
> [WARNING] 2026-11-11 14:27:16,993 root(middleware.py:43) :: Access to /favicon.ico is not Authenticated.
> ```
> * Warning of insecure key:
> ```
> jwt/api_jwt.py:147: InsecureKeyLengthWarning: The HMAC key is 6 bytes long, which is below the minimum recommended length of 32 bytes for SHA256.
> jwt/api_jwt.py:368: InsecureKeyLengthWarning: The HMAC key is 6 bytes long, ...
> ```
> * Integrity error at vault:
> ```
> [ERROR] navigator.vault(session_vault.py:457) :: Vault secret failed integrity check: user=35 key=account error=UnsupportedFormatError
> [INFO]  navigator.vault(session_vault.py:490) :: Vault loaded for user=35: 0 secret(s), 1 integrity failure(s)
> ```
> * Clicking on Dashboard I got an error `http://localhost:5000/dashboard/` or any other URL (was working before):
> ```
> {"status":428,"reason":"Error: Some preconditions failed: No Matching Policies were found, Deny access."}
> ```

**Initial signals** (extracted, not interpreted):
- Verbs: "got an error", "was working before" → regression-shaped bug; three log-level complaints.
- Named entities: PBAC example, `middleware.py:43`, PyJWT HMAC key, `session_vault.py:457`, `/dashboard/`, HTTP 428.
- Components / labels: none (inline source).
- Acceptance criteria provided: no.

---

## 1. Synthesis Summary

Running `examples/policy_server.py` shows four independent problems; only the 428 is a functional bug.
Every URI decision goes through `PDP.authorize`, which asks only the `PolicyEvaluator`. But the example
grants `/dashboard/` with a classic `Policy` registered through `PDP.add_policy`, which appends to a list
the evaluator never reads. Because the example pre-loads the evaluator, `PDP._load_policies` also skips
storage, so nothing matches and the PDP returns 428 "No Matching Policies". The gap most likely dates from
the April 2026 classic→Rust migration (`migrate-classic-policies-abac-rust`), which explains why no recent
commit shows it. The other three issues are log noise in `abac_middleware`, a 6-byte `AUTH_SECRET_KEY`
with no length check in `navigator_auth/conf.py`, and a v1 vault secret that was never migrated to the
FEAT-099 v2 format. Recommendation: one `/sdd-spec` covering a library fix plus example cleanup for the 428,
log hygiene, a startup key-length warning, and the vault migration runbook step.

---

## 2. Codebase Findings

> All entries are grounded in `sdd/state/FEAT-109/findings/` and were probe-verified at HEAD `c25272a`
> (78/78 checks verified; one line-range drift in F010 corrected below). **No fabricated paths or symbols.**

### 2.1 Localization

| # | Path | Symbol | Lines | Role | Evidence |
|---|------|--------|-------|------|----------|
| 1 | `navigator_auth/abac/pdp.py` | `PDP.authorize` | 393-448 | decides URI access through the evaluator only; raises `PreconditionFailed` (428) when no policy matched | F004 |
| 2 | `navigator_auth/abac/pdp.py` | `PDP.add_policy` | 103-108 | public API; appends a classic `Policy` to `self._policies` only, never loads it into the evaluator | F004 |
| 3 | `navigator_auth/abac/pdp.py` | `PDP._load_policies` | 110-141 | startup storage load; returns early at **line 115** when the evaluator already holds policies | F004, F007 |
| 4 | `navigator_auth/abac/pdp.py` | `PDP._load_policy_dicts` | 142-153 | the only path that adapts policies (`PolicyAdapter.adapt_batch`) and loads them into the evaluator (line 153) | F004 |
| 5 | `navigator_auth/abac/policies/adapter.py` | `PolicyAdapter._adapt_classic` | 186-221 | converts a classic `Policy` dict into a `ResourcePolicy` (subjects, tenant `(1,1)` default) | F011 |
| 6 | `navigator_auth/abac/errors.py` | `PreconditionFailed` | 77-80 | builds the HTTP 428 returned to the browser | F004 |
| 7 | `examples/policy_server.py` | `create_app` | 528-603 | pre-loads the evaluator (`load_from_directory` at 560, `load_policies` at 563), then `pdp.add_policy(policy)` at 586 | F005 |
| 8 | `examples/policy_server.py` | `public_dashboard` | 125-132 | the only ALLOW policy for `urn:uri:/dashboard/` (no subject constraint) | F005 |
| 9 | `sdd/specs/migrate-classic-policies-abac-rust.spec.md` | PDP module change | 37, 92 | April 2026 migration that made `authorize()` evaluator-only while promising an unchanged PDP interface; `add_policy` not covered | F014 |
| 10 | `navigator_auth/abac/middleware.py` | `abac_middleware` | 16-58 | WARNING at **line 43** for every unauthenticated, non-excluded request, then passes it through; duplicate dead `except` at 47-56 | F002 |
| 11 | `navigator_auth/conf.py` | `EXCLUDE_DEFAULTS` | 63-72 | default auth exclude list — no `/favicon.ico`, no `/.well-known/*` | F002 |
| 12 | `navigator_auth/auth.py` | `AuthHandler.add_exclude_list` | 844-853 | per-app fnmatch exclude-list API the example uses | F002 |
| 13 | `navigator_auth/conf.py` | `SECRET_KEY` | 305-308 | `AUTH_SECRET_KEY` taken verbatim, no minimum length; random 32-byte fallback only when unset | F003 |
| 14 | `navigator_auth/backends/idp/__init__.py` | `SECRET_KEY` JWT use | 250, 267, 432 | HS256 `jwt.encode`/`jwt.decode` with `SECRET_KEY` — source of PyJWT's `InsecureKeyLengthWarning` | F003 |
| 15 | `.venv/…/navigator_session/vault/session_vault.py` | `SessionVault.load_for_session` | 420-460 | per-row open; logs "failed integrity check", audits `integrity_fail`, skips the row (dependency code) | F001 |
| 16 | `.venv/…/navigator_session/vault/envelope.py` | `UnsupportedFormatError` | 69, 118-134 | raised for any blob that is not a v2 (`0xA2`) envelope (dependency code) | F001 |

### 2.2 Constraints Discovered

- **The pre-load guard is intentional.** `PDP._load_policies` skips the startup storage load when the
  evaluator is already populated, and `tests/test_yaml_storage_double_load.py::TestPDPDoubleLoadPrevention`
  pins it. *Implication*: do not remove the guard; route `add_policy()` into the evaluator instead.
  *Evidence*: F004, F007
- **Authorization is evaluator-only.** `self._policies` is kept only "for backward compatibility".
  *Implication*: any policy that must affect access has to be adapted and loaded into the evaluator.
  *Evidence*: F004
- **The migration promised an unchanged PDP public interface.** *Implication*: restoring `add_policy`'s
  effect honours an existing contract; it is a bug fix, not a new API. *Evidence*: F014
- **Fail-closed by default.** `ABAC_DEFAULT_EFFECT` falls back to `deny`, every default YAML pack declares
  `defaults.effect: deny`, and the Rust engine denies on error. *Implication*: no allow-by-default shortcut.
  *Evidence*: F006, F013
- **No test covers the 428 path or `add_policy`.** *Implication*: the fix needs regression tests for both.
  *Evidence*: F007
- **The warning branch is a pass-through.** The request is still served. `tests/test_probes.py` refers to
  a separate tracker for repeated unauthenticated probes. *Implication*: changing the log level or exclude
  list must not change authorization or that tracker. *Evidence*: F002
- **One key, several signers.** `SECRET_KEY` signs IdP authorization codes/JWTs and CSRF tokens;
  `PARTNER_KEY` (16 bytes) is the fallback for `AUTH_TOKEN_SECRET`. *Implication*: rotating invalidates
  in-flight tokens and CSRF cookies; the startup check must cover both keys. *Evidence*: F003
- **Vault code is a dependency.** `SessionVault` and the v2 envelope live in `navigator-session`; per-row
  fail-closed loading is the FEAT-099 design. *Implication*: the vault error is an operational migration
  step, not a navigator-auth code change. *Evidence*: F001, F009, F012

### 2.3 Recent History (Relevant)

| Commit | When | Message | Touched files | Evidence |
|--------|------|---------|---------------|----------|
| `f6be206`, `7300e6d` | 2026-10-24 | TASK-120 auth-model ABAC policy pack (+ fix) | `abac/default_policies/auth_model_admin_access.yaml` | F008 |
| `d31f568`, `6d1fc36` | 2026-10-13 | fix-organizations-orgid: normalize legacy session users; fail closed on `TypeError` | `navigator_auth/auth.py` (`get_session_user`, actual lines 744-755) | F010 |
| `416a5f8` | 2026-10-08 | fix(csrf): scope the check by authentication mechanism | `middlewares/csrf.py`, `auth.py`, `conf.py` | F002 |
| `a3706f0` | 2026-10-03 | fix(abac): structured tuple cache key | `abac/policies/evaluator.py` | F008 |
| `f2885be` | 2026-09-30 | fix(abac): keep abac_middleware after the authentication middlewares | `auth.py`, `abac/pdp.py` | F008, F002 |
| FEAT-099 (`5af071b`…`d7dbc8f`) | 2026-09-16 | vault-crypto-hardening: v2 envelope mandatory, v1 rejected at runtime | `navigator_auth/vault/`, `navigator-session` | F009 |
| `1e3ebbc` | 2026-06-30 | PDP policy and config auth (last edit of the example) | `examples/policy_server.py` | F002 |
| — | ≈2026-04 | `migrate-classic-policies-abac-rust`: `authorize()` → evaluator | `abac/pdp.py` | F014 |

None of the commits in the 45-day window changes PDP, evaluator, middleware or YAML-storage behaviour in a
way that would produce the 428 (F008). The gap predates the window (F014).

---

## 3. Hypothesis

### Hypothesis 1 — `add_policy()` grants never reach the evaluator, so `/dashboard/` matches nothing · Confidence: medium

**Supporting evidence**: F004, F005, F006, F007, F013, F014
**Contradicting evidence**: F008 (no recent commit), resolved by F014 (the gap predates the window)
**Reasoning**: `examples/policy_server.py` pre-loads the evaluator (560, 563), then registers
`public_dashboard` (`urn:uri:/dashboard/`) with `pdp.add_policy` (586). `PDP.add_policy` (pdp.py:103)
only appends to `self._policies`. The non-empty evaluator makes `_load_policies` return at pdp.py:115.
`PDP.authorize` asks only the evaluator, finds no policy for `/dashboard/`, and with a deny default raises
`PreconditionFailed` → 428. Every link is read and probe-verified. The rating stays medium because the
chain has not been reproduced at runtime.

**Suggested next probe**: in `examples/policy_server.py`, right after `pdp.setup(app)` (line 589),
temporarily print `[p.name for p in pdp._evaluator._index.all()]` and confirm `public_dashboard` is
absent; then `GET /dashboard/` with a logged-in session and expect the 428. The spec's first test should
assert the opposite (an `add_policy` grant is enforced by `PDP.authorize`).

### Hypothesis 2 — Before the pre-load guard, a DB-stored `/dashboard/` grant used to match · Confidence: low

**Supporting evidence**: F004, F008
**Contradicting evidence**: —
**Reasoning**: Before the guard, `_load_policies` loaded DB/YAML storage into the evaluator. If the
example database held a URI grant, `/dashboard/` would have matched. The guard was not dated and the
example DB was not inspected; the git budget was exhausted.

**Suggested next probe**: `git log -S '_index.all()' -- navigator_auth/abac/pdp.py` and
`grep -n dashboard examples/sql/*`.

### Hypothesis 3 — Session-user normalization (2026-10-13) changed the subject · Confidence: low

**Supporting evidence**: F010
**Contradicting evidence**: F004, F005. A 428 means no policy matched the resource at all, and
`public_dashboard` has no subject constraint.
**Suggested next probe**: search the server log for `NAV: Unable to decode User session` (auth.py:755).

### Secondary issues (cause established)

| Symptom | Cause | Agreed fix (§5) | Evidence |
|---------|-------|-----------------|----------|
| `Access to X is not Authenticated.` WARNINGs | `abac_middleware` logs at WARNING on the root logger for every anonymous, non-excluded request; browser probe paths are not excluded | demote to DEBUG + default probe-path exclusions + drop the dead `except` | F002 |
| `InsecureKeyLengthWarning` (6 bytes) | `AUTH_SECRET_KEY` is 6 chars in `env/.env` (and `env/prod/.env`); no length validation | startup warning for `SECRET_KEY` and `AUTH_TOKEN_SECRET` < 32 bytes + rotate env values | F003 |
| `UnsupportedFormatError` for user 35 `account` | pre-FEAT-099 v1 blob never migrated; per-row fail-closed by design | operational: `navigator-vault migrate --dry-run` then `--run --backup-dir …` (after `002_vault_crypto_hardening.sql`) | F001, F009, F012 |

---

## 4. Confidence Map

| ID | Claim | Evidence | Confidence | Reasoning |
|----|-------|----------|------------|-----------|
| C1 | `PDP.authorize` checks access only through the evaluator and raises 428 when nothing matched | F004 | high | direct read; probe-verified |
| C2 | `PDP.add_policy` only appends to `self._policies` | F004 | high | probe-verified signature at pdp.py:103 |
| C3 | `_load_policies` returns early at pdp.py:115 when the evaluator holds policies | F004 | high | anchor verified at line 115 |
| C4 | The example pre-loads the evaluator and grants `/dashboard/` only via `add_policy` | F005 | high | anchors verified at 560, 586, 130 |
| C5 | C1–C4 together produce the 428 on `/dashboard/` and other `add_policy`-covered URIs | F004, F005 | medium | chain of verified facts; not reproduced at runtime |
| C6 | The pre-load guard is intentional and tested | F004, F007 | high | test class at test_yaml_storage_double_load.py:219 |
| C7 | No test references `PreconditionFailed` or `add_policy` | F007 | high | absent-probe over `tests/` |
| C8 | Default effect is deny; no default pack grants `/dashboard/` | F006, F013 | high | conf.py:710 verified; packs read |
| C9 | No commit in the last 45 days explains the regression | F008, F002, F014 | medium | window searched; gap dated earlier by F014 |
| C10 | Session-user normalization contributes to the 428 | F010 | low | timing only; contradicted by C4 |
| C11 | `abac_middleware.py:43` logs a root WARNING for anonymous, non-excluded requests and still serves them | F002 | high | anchor verified at line 43 |
| C12 | Neither `EXCLUDE_DEFAULTS` nor the example excludes `/favicon.ico`, `/.well-known/*`, `/client-config` | F002, F005 | high | direct read |
| C13 | It is unexplained why the 404 `SystemRoute` skip (middleware.py:28) does not silence these paths | F002 | low | REPL says 404s are `SystemRoute`; needs a live repro |
| C14 | middleware.py:47-56 has a duplicate, unreachable `except (TypeError, KeyError)` | F002 | high | direct read |
| C15 | The 6-byte key is `AUTH_SECRET_KEY` from `env/.env` (same length in `env/prod/.env`); nothing checks length | F003 | high | lengths measured; conf.py:305 verified |
| C16 | `SECRET_KEY` signs IdP JWTs/codes and CSRF tokens; `PARTNER_KEY` (16 B) backs `AUTH_TOKEN_SECRET` | F003 | high | direct read |
| C17 | User 35's `account` secret is most likely an unmigrated v1 blob | F001, F009, F012 | medium | documented error meaning; row not inspected |
| C18 | The vault failure is non-fatal by design and its code lives in navigator-session | F001, F009, F012 | high | direct read + FEAT-099 spec |
| C19 | Tenant scoping is not the cause (classic policies default to global `(1,1)`) | F011 | medium | adapter read; global match from a test name |
| C20 | How an adapted classic policy with empty groups/users (`public_dashboard`) matches subjects is unverified | F011 | low | `SubjectSpec.from_dict` not read |
| C21 | `add_policy` lost its effect in the April 2026 classic→Rust migration | F014 | medium | spec lines 37/92 read; omission inferred from absent grep |

Distribution: **12** high, **5** medium, **4** low.

> C20 matters for the library fix: if empty subjects mean "match nobody" after adaptation, `public_dashboard`
> would still 428 once loaded. The spec must settle this, by reading `SubjectSpec.from_dict` and adding a test,
> before the first task is written.

---

## 5. Open Questions

### Resolved (during proposal phase)

- [x] **Where should the 428 fix go?** — *Resolved*: Library + example: make `PDP.add_policy()` load
  classic policies into the evaluator (keep the startup-load guard), add regression tests, and clean up the
  example. *Resolves claims*: C5, C20 (scope)
- [x] **How should the "not Authenticated" noise be handled?** — *Resolved*: Both: demote to DEBUG, add
  default exclusions for `/favicon.ico` and `/.well-known/*`, and remove the duplicate dead `except`.
  *Resolves claims*: C11, C12, C14
- [x] **How should startup treat HMAC keys under 32 bytes?** — *Resolved*: Warn at startup for
  `AUTH_SECRET_KEY` and `AUTH_TOKEN_SECRET`/`PARTNER_KEY`, and rotate the env values to 32+ bytes.
  *Resolves claims*: C15, C16
- [x] **When did `/dashboard/` last work?** — *Resolved*: "Not sure." The regression date stays open;
  F014 points to the April 2026 migration. *Resolves claims*: C9 (partially)

### Unresolved (defer to spec / implementation)

- [ ] **Do empty-subject classic policies match everyone after `PolicyAdapter._adapt_classic`?** — *Owner*: tbd
  *Blocks claims*: C20
  *Plausible answers*: a) empty = match all (fix is just loading) · b) empty = match none (adapter needs a rule)
- [ ] **Why does the 404 `SystemRoute` skip not silence `/favicon.ico`?** — *Owner*: tbd
  *Blocks claims*: C13
  *Plausible answers*: a) a catch-all/static route matches these paths · b) the running build differs
- [ ] **Is `env/prod/.env` tracked by git?** If yes, a weak production secret is committed, which raises
  the priority of the key rotation. — *Owner*: tbd
- [ ] **Vault**: run `navigator-vault migrate --dry-run` on the example DB to confirm user 35's row is v1
  (C17). No code change expected in navigator-auth.

---

## 6. Recommended Next Step

**`/sdd-spec FEAT-109`** — *Rationale*: the only scope fork (library vs example, U1) is resolved, and
every fix site is localized and probe-verified. The remaining medium confidence is about runtime
reproduction, so the spec's first acceptance test should be "`add_policy` grant is enforced by
`PDP.authorize`". Suggested module split: (1) PDP `add_policy` → evaluator + tests; (2) example cleanup;
(3) `abac_middleware` log level, probe-path exclusions and dead `except`; (4) startup HMAC key-length
warning + env rotation note; (5) vault runbook note (docs only).

### Alternatives

- **`/sdd-brainstorm FEAT-109`** — if you want to reconsider retiring `self._policies` / `add_policy`
  entirely in favour of evaluator-native `ResourcePolicy` registration.
- **`/sdd-task FEAT-109`** — not recommended: five small modules with a shared test surface fit a spec.
- **Manual review** — only if the runtime probe in §3 H1 contradicts the chain.

---

## 7. Research Audit

| Artifact | Path |
|----------|------|
| State checkpoints | `sdd/state/FEAT-109/state.json` |
| Source (raw) | `sdd/state/FEAT-109/source.md` |
| Research plan | `sdd/state/FEAT-109/research_plan.json` |
| Findings (digests) | `sdd/state/FEAT-109/findings/F001-*.md` … `F014-*.md` |
| Lane originals (pre-merge) | `sdd/state/FEAT-109/findings/.audit/` (FC-001…007, FG-001…004, FW-001…008) |
| Synthesis (JSON) | `sdd/state/FEAT-109/synthesis.json` |

**Budget consumed** (profile `default`, parallel lanes codebase / git / wiki):
- Files read: 19 / 40
- Grep calls: 24 / 25
- Git calls: 10 / 10 (git lane exhausted, so H2 was not dated)
- Wall time: ≈ 240s / 300s for research
- Truncated: **no** (all 16 planned queries executed; one depth-1 follow-up, F014)

**Merge**: 18 lane findings → 13 canonical (5 merged on shared `(path, symbol)`), plus F014 from the follow-up.
**Citation probe**: 78 checks, 78 verified (HEAD `c25272a`). One manual line-range correction in F010
(`get_session_user` is at auth.py:744-755, not 737-746).

**Mode determination**: `auto` → `investigation` ("got an error", "was working before").

---

## 8. Provenance

| Field | Value |
|-------|-------|
| Generated by | `/sdd-proposal v1.0` |
| Synthesis prompt | `sdd/templates/synthesis.prompt.md v1.0` |
| Plan prompt | `sdd/templates/research_plan.prompt.md v1.0` |
| Schema versions | state=1.0, synthesis=1.0, research_plan=1.0 |
| Operator | Claude Code (Opus 5.5) for Jesus Lara |
