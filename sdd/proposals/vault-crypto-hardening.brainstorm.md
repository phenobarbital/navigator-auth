# Brainstorm: Vault Crypto Hardening (server-keyed session layer + AEAD associated data)

**Date**: 2026-09-15
**Author**: Jesus Lara
**Status**: exploration
**Recommended Option**: A

> **Scope note:** this is a cross-repo feature. The cryptographic core lives in
> `navigator-session` (`navigator_session/vault/`), which has no `sdd/` tree, so the brainstorm
> is filed here in `navigator-auth` (its main consumer). Affected repos:
> `navigator-session` (core), `navigator-auth` (Session Vault HTTP API + Identity Vault),
> `ai-parrot` (direct consumers of the vault crypto) and `navigator-frontend-next` (vault UI,
> forced re-login, integration status).

---

## Problem Statement

The Session Vault (`auth.user_vault_secrets`) and every table that reuses its crypto
(`auth.user_identities` credentials, ai-parrot credentials/BYOK/user-bot configs) use sound
primitives — AES-256-GCM (or ChaCha20-Poly1305), HKDF-SHA256, 96-bit random nonces, key-id
prefix for rotation — but two design flaws undermine them:

1. **Session-layer key is derived only from public-ish data.**
   `encrypt_for_session()` uses `HKDF(session_uuid, "vault-session")`. `session_uuid` is the
   session cookie value (`storages/redis.py:133`) and is literally part of the Redis key name
   (`vault:{session_uuid}:{key}`, `session_vault.py:118`). Consequences:
   - Anyone who can read Redis (live access, RDB/AOF snapshot, backup) holds both the
     ciphertext and the key seed in the same record → every cached secret is decryptable.
   - Anyone who steals a session cookie can decrypt `ciphertext_mem` offline.
   - Non-HTTP callers are worse: ai-parrot's `VaultTokenSync` uses a *deterministic*
     `session_uuid = "telegram-persistent:{user_id}"`, so the key is guessable with zero access.
   - `auth.user_vault_audit.session_id` stores the raw `session_uuid` → a DB reader can harvest
     live session ids (session hijack).
   In practice the session layer is obfuscation, not encryption.

2. **No AEAD associated data (AAD).** `encrypt_for_session` / `encrypt_for_db` pass
   `associated_data=None`. Ciphertexts are not bound to their owner or location, so an attacker
   with write access to PostgreSQL (SQLi, compromised migration role, rogue DBA) can:
   - copy user A's `ciphertext_db` into user B's row (cross-user substitution);
   - swap values between keys of the same user;
   - swap `access_token` ↔ `refresh_token` ↔ `id_token` within one `auth.user_identities` row;
   and decryption succeeds silently. ai-parrot already noticed this and built an in-plaintext
   `_ctx` envelope as a workaround (`parrot/handlers/models/_encrypted_field.py`), which only
   covers one of its tables.

Additionally, the cipher algorithm is chosen by env var (`VAULT_CIPHER_BACKEND`) and is **not
recorded in the ciphertext**, so flipping it makes all existing data undecryptable.

**Who is affected:** end users (their stored API keys, OAuth tokens, BYOK keys), operators
(Redis/DB backups become sensitive assets), and developers of every service consuming the vault.

**Why now:** the vault is spreading (Identity Vault FEAT-096, ai-parrot integrations,
Telegram/CLI token sync). Every new consumer copies the flaw or invents its own workaround.

## Constraints & Requirements

Decisions taken during discovery (Rounds 1–3):

- **Threat model (all in scope):** Redis read/dump, stolen session cookie, PostgreSQL write
  access, DB dump without master keys (must not regress).
- **Session-layer secret:** derived from the existing master keys (`VAULT_MASTER_KEY_v{N}`);
  no new environment variable to operate.
- **AAD granularity:** purpose + row + field. It must prevent substitution across users, across
  rows of the same user, and across columns of the same row.
- **Redis key names:** must not reveal session ids or secret names — HMAC them with a
  server-side secret.
- **Migration:** single **offline batch** in a maintenance window. After migration the legacy
  (v1) format is **rejected** — no dual-read at runtime.
- **Active sessions on deploy:** purge `vault:*` and invalidate sessions → users are forced to
  re-login. Frontend must handle this gracefully.
- **Public API:** **breaking change** in `navigator-session` (major bump). AAD is mandatory in
  the crypto API. ai-parrot consumers are migrated **in this feature** and covered by the same
  batch migration.
- **HTTP API:** `GET /api/v1/user/vault/{key}` stops returning plaintext values to the browser
  (metadata only). Values are consumed server-side only.
- **Frontend:** vault management UI (list / create / update / delete; write-only values),
  forced re-login UX, integration status when a stored token cannot be decrypted.
- Deterministic persistent vault sessions (`VaultTokenSync`, Telegram/CLI) must keep working.
- Never log plaintext, ciphertext, derived keys or raw session ids.
- Stay on `cryptography` (already a dependency, `>=41.0`); no new crypto runtime dependency
  unless an option justifies it.
- Vault failures must still never block authentication (`vault/integration.py` contract).

---

## Options Explored

### Option A: Versioned "Sealed Envelope v2" in navigator-session

Replace the two ad-hoc formats with one versioned, self-describing envelope and a single
seal/open API that **requires** a structured context:

- **Header**: `format_version (1B) ‖ alg_id (1B) ‖ key_id (2B) ‖ nonce (12B) ‖ ct ‖ tag`.
  The algorithm is recorded per ciphertext, so `VAULT_CIPHER_BACKEND` only selects the
  algorithm for *new* writes.
- **AAD** = canonical, length-prefixed encoding of `(header, purpose, layer, context fields…)`.
  Length-prefixing avoids ambiguity (`"a:b" + "c"` vs `"a" + "b:c"`). The header is
  authenticated too, so `key_id` / `alg_id` cannot be tampered with.
- **Session layer**: `HKDF(master_key[kid], info = "navigator-vault/session/v2" ‖ session_uuid)`.
  The session key now requires a master key; `key_id` travels in `ciphertext_mem`, so a master
  key rotation does not break live caches.
- **Redis naming**: `vault:v2:{HMAC(naming_key, session_uuid)}:{HMAC(naming_key, key)}` with
  `naming_key` derived from the master key ring. The audit table stores the same HMAC instead
  of the raw session id.
- **Context registry**: a declarative description per protected table/column (purpose name,
  which columns form the context, which columns hold ciphertext). The same registry drives
  runtime seal/open, `rotate_master_key`, and the offline v1→v2 migrator, so consumers cannot
  drift.
- **Offline migrator**: a CLI (dry-run, verify, resumable, per-table stats) that decrypts v1
  (legacy code kept only inside the migrator) and re-seals as v2 with the right context.

✅ **Pros:**
- Fixes both flaws plus the unrecorded-algorithm hazard in one format change.
- Minimal operational change: same env vars, same master keys, same rotation semantics.
- One registry for runtime, rotation and migration — ai-parrot's `_ctx` workaround disappears.
- Deterministic persistent sessions (`VaultTokenSync`) keep working (derivation stays
  deterministic, just keyed).
- No new dependency; uses `cryptography` primitives already in use.

❌ **Cons:**
- Breaking change across four repos that must be released and deployed together.
- Forced re-login for every user at deploy time.
- Moving/renaming a secret (key rename, identity re-link, `provider_user_id` change) now
  requires re-encryption — by design.
- Master-key compromise still exposes everything (same as today; addressed only by Option B).

📊 **Effort:** Medium–High (core is Medium; the cross-repo migration and frontend push it up)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `cryptography` | `AESGCM`, `ChaCha20Poly1305`, `HKDF`, `hmac`/`hashes` | Already a dependency (`>=41.0`) in navigator-session and navigator-auth |
| `hmac` / `hashlib` (stdlib) | HMAC-SHA256 for Redis names and audit session ids | `hmac.compare_digest` where comparing |
| `orjson` | Existing value serializer | Unchanged |
| `redis` asyncio client | `SCAN`-based purge of `vault:*` / `session:*` in the runbook | Avoid `KEYS` in production |
| `asyncpg` | Batch migrator | Same pool patterns as `key_rotation.py` |

🔗 **Existing Code to Reuse:**
- `navigator-session/navigator_session/vault/crypto.py` — HKDF derivation, serializer, AEAD selection (to be restructured)
- `navigator-session/navigator_session/vault/config.py` — master key ring loading, `VaultConfig` validation
- `navigator-session/navigator_session/vault/key_rotation.py` — batching/transaction/offset logic (becomes registry-driven)
- `navigator-session/navigator_session/vault/session_vault.py` — public `SessionVault` API (context = user_id + key)
- `navigator-auth/navigator_auth/identity/crypto.py` — `IdentityCipher` (gains context argument)
- `navigator-auth/navigator_auth/identity/store.py` — `save_linked_identity`, `decrypt_credential`
- `ai-parrot/.../handlers/models/_encrypted_field.py` — its `(user_id, chatbot_id, field)` context is the model to generalize
- `navigator-frontend-next/src/lib/api/http.ts` — existing 401 → `/login` redirect

---

### Option B: Per-user envelope encryption (KEK → per-user DEK) + AAD

Introduce a key hierarchy: master keys become **KEKs** that only wrap a random per-user
**Data Encryption Key** stored in a new table (e.g. `auth.user_vault_keys`, one wrapped DEK per
user and purpose). Secrets are encrypted with the user's DEK and AAD (same context model as
Option A). The session layer uses a random per-session key held only in process memory (and a
KEK-wrapped copy in Redis for multi-worker).

✅ **Pros:**
- Master key rotation only re-wraps DEKs (one row per user) instead of re-encrypting every
  secret → rotation becomes cheap and fast.
- **Crypto-shredding**: deleting a user's DEK irrecoverably erases all their secrets (GDPR
  "right to erasure", including in backups).
- Per-user blast radius if a single DEK leaks from memory.
- Clean path to an external KMS later (KEK in AWS KMS / Vault Transit, DEKs stay local).

❌ **Cons:**
- New table, new lifecycle (DEK creation on first write, concurrency on creation, DEK cache).
- More moving parts to migrate in the same offline window.
- Larger change to `SessionVault` loading and to every ai-parrot consumer.
- Does not reduce the forced re-login or the cross-repo coordination of Option A.

📊 **Effort:** High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `cryptography` | AEAD, HKDF, `aes_key_wrap` (RFC 3394/5649) for DEK wrapping | Already a dependency |
| `asyncpg` | New `user_vault_keys` table + migrator | — |
| AWS KMS / HashiCorp Vault Transit (future) | External KEK | Not required now; `hvac` already used by navconfig |

🔗 **Existing Code to Reuse:**
- Everything listed in Option A
- `navigator-auth/navigator_auth/vault/migrations.py` — table bootstrap pattern for the new keys table

---

### Option C: Adopt Google Tink keysets (library-managed AEAD)

Replace the hand-rolled crypto with **Tink** (`tink` on PyPI): master keys become a Tink
keyset (encrypted with a primary key or a KMS), AEAD with associated data is the only API Tink
exposes, and key rotation (primary key switching, key id prefix) is built into the library.
Session layer uses a Tink `DeterministicAead`/`PRF` primitive keyed from the keyset for key
derivation and Redis naming.

✅ **Pros:**
- Misuse-resistant, audited library: AAD, key ids, algorithm ids and rotation handled by Tink.
- Native KMS integrations (AWS KMS, GCP KMS) for the keyset-encryption key.
- Less custom crypto code to review and maintain.

❌ **Cons:**
- New heavy dependency with native wheels (protobuf, C++ bindings); Python support lags other
  languages and wheel availability for new CPython versions / free-threaded builds is a risk
  for this ecosystem (Cython/Rust extensions, Python 3.14).
- Changes the operator contract: `VAULT_MASTER_KEY_v{N}` env vars must become a keyset.
- Tink's ciphertext format still needs our own context model (AAD content is ours to define),
  so the registry work of Option A remains.
- Unconventional for this codebase; every consumer must learn a new API.

📊 **Effort:** High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `tink` | AEAD, PRF, keyset management, KMS envelope | 1.x; check wheels for CPython 3.12–3.14 before committing |
| `protobuf` | Tink keyset serialization | Transitive |

🔗 **Existing Code to Reuse:**
- `navigator-session/navigator_session/vault/key_rotation.py` — batching only
- `navigator-session/navigator_session/vault/session_vault.py` — public API surface

---

### Option D: Minimal patch — keyed session derivation + in-plaintext context envelope

Keep the current ciphertext formats. Fix flaw 1 by changing only the HKDF input to include the
master key. Fix flaw 2 the way ai-parrot did: wrap the plaintext in an envelope carrying the
context (`{"_v": 2, "_ctx": {...}, "v": value}`) and verify the context after decryption.
Since the envelope is inside the AEAD, substitution is still detected.

✅ **Pros:**
- Smallest code change; no header/format redesign.
- Proven pattern already in ai-parrot (`_encrypted_field.py`).
- Could ship behind the same offline migration.

❌ **Cons:**
- Context is verified *after* decryption, by application code — easy to forget in a new
  consumer; AAD makes the check mandatory at the cipher level.
- Does not record the algorithm in the ciphertext; `key_id` stays unauthenticated metadata.
- Context validation logic duplicated per consumer unless a registry is added anyway.
- Couples the crypto layer to the JSON serializer (envelope must be parsed to validate).

📊 **Effort:** Low–Medium

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `cryptography` | Existing primitives | No change |
| `orjson` | Envelope serialization | Existing |

🔗 **Existing Code to Reuse:**
- `ai-parrot/.../handlers/models/_encrypted_field.py` — envelope build/verify logic
- `navigator-session/navigator_session/vault/crypto.py` — unchanged formats

---

## Recommendation

**Option A** is recommended because:

- It is the only option that satisfies every discovery decision with the least new machinery:
  master-key-derived session secret (no new env var), mandatory AAD at the cipher level
  (purpose + row + field), HMAC'd Redis names, breaking API, one offline migration.
- Compared with **Option D**, it enforces context binding in the AEAD itself rather than in
  application code, and it fixes the unauthenticated `key_id` and unrecorded algorithm issues.
  Since we are already paying for a breaking change and a forced re-login, the marginal cost of
  doing the format properly is small.
- Compared with **Option B**, it avoids a new key table and DEK lifecycle in an already large
  cross-repo change. What we trade off: rotation still re-encrypts every row, and there is no
  per-user crypto-shredding. The v2 header's `alg_id`/`format_version` bytes leave room to
  introduce per-user DEKs later as a v3 without another redesign — Option B is a natural
  follow-up, not a competitor.
- Compared with **Option C**, it avoids a native dependency with uncertain wheel coverage for
  this ecosystem (CPython 3.14, free-threaded builds) and keeps the operator contract
  (`VAULT_MASTER_KEY_v{N}`, `VAULT_ACTIVE_KEY_ID`) intact.

---

## Feature Description

### User-Facing Behavior

**At deploy (one time):**
- All users are logged out. The next request with an old cookie gets `401`; the frontend
  redirects to `/login` (existing `http.ts` behaviour) and shows a short notice explaining the
  session ended due to a security update.
- After logging in again, stored secrets and linked integrations work as before — data was
  migrated, not discarded.

**Vault management UI (navigator-frontend-next, under `/profile`):**
- A "Secrets" section lists the user's vault entries: name, last updated, key version (no
  values, ever).
- Create / update: a form with name + value; the value field is write-only (masked input, never
  pre-filled, never echoed back by the API). Updating overwrites.
- Delete with confirmation (soft-delete server-side).
- Validation errors surfaced inline (empty name, name > 255 chars, forbidden characters,
  per-user limit of 50 secrets).

**Integrations (agent integrations panel):**
- Each integration shows `connected`, `disconnected`, or a new **`needs_reconnect`** state when
  the stored OAuth token exists but cannot be decrypted/verified (e.g. a row that failed
  migration and was quarantined, or tampering detected). The UI offers "Reconnect", which runs
  the existing connect flow.

**HTTP API (navigator-auth):**
- `GET /api/v1/user/vault` returns metadata entries instead of bare key names.
- `GET /api/v1/user/vault/{key}` returns metadata only (no `value`); plaintext is never sent to
  the browser.
- `POST` / `DELETE` unchanged in shape.
- Vault decryption failures return a distinct, non-500 error code (e.g. `vault_unavailable`)
  so the UI can distinguish "vault broken" from "server error".

### Internal Behavior

**navigator-session (core):**
1. *Envelope v2*: header (`format_version`, `alg_id`, `key_id`, nonce) + AEAD ciphertext/tag.
   The full header plus the canonical context is the AAD.
2. *Context model*: a typed context object (purpose, layer, ordered fields). Canonical encoding
   is length-prefixed and versioned. Suggested purposes:
   - `user-vault` / layer `db`: `(user_id, key)`
   - `user-vault` / layer `session`: `(HMAC(session_uuid), user_id, key)`
   - `identity` / layer `db`: `(user_id, auth_provider, provider_user_id, field)` where `field`
     ∈ {`access_token`, `refresh_token`, `id_token`}
   - ai-parrot purposes (credentials, BYOK, user-bot `mcp_config`/`tools_config`) defined by
     ai-parrot through the same registry.
3. *Key schedule* (all HKDF-SHA256 from the master key ring, domain-separated `info` strings):
   DB key per `key_id`, session key per `(key_id, session_uuid)`, naming key for Redis/audit
   HMACs.
4. *Seal/Open API*: seal requires a context; open requires the *expected* context and fails
   closed (`InvalidTag` → typed `VaultIntegrityError`). Legacy `encrypt_for_*` / `decrypt_for_*`
   are removed from the public API (legacy decrypt lives only in the migrator module).
5. *SessionVault*: uses the new API with `(user_id, key)` context, HMAC'd Redis names, stores
   HMAC session id in audit, exposes metadata (name, `updated_at`, `key_version`) for listing.
6. *Registry-driven rotation*: `rotate_master_key` re-seals rows using each table's registered
   context columns.
7. *Offline migrator CLI*: pre-flight (all master keys present, all v1 rows decryptable),
   dry-run report, per-table batches in transactions, resumable, post-verify (every row opens
   as v2 with its context), final report. Rows that cannot be decrypted are **reported**; the
   run does not complete successfully unless the operator passes an explicit quarantine flag,
   which soft-deletes those rows and writes an audit record.

**navigator-auth:**
- `IdentityCipher` encrypt/decrypt take the identity context; `IdentityStore` builds it from
  `(user_id, auth_provider, provider_user_id)` + field, and re-seals when `provider_user_id`
  changes on upsert.
- `VaultView` returns metadata only; maps `VaultIntegrityError` to the distinct error code.
- Identity tables and `auth.user_vault_secrets` registered in the context registry.

**ai-parrot:**
- `security/credentials_utils.py`, `handlers/credentials.py`, `studio/byok.py`,
  `auth/broker.py`, `handlers/agent.py` pass explicit contexts.
- `_encrypted_field.py` drops the `_ctx` in-plaintext envelope in favour of AAD (migrator
  unwraps v1 envelopes and verifies their `_ctx` before re-sealing).
- `VaultTokenSync` keeps its deterministic session scheme; `IntegrationsHandler` reports
  `needs_reconnect` on `VaultIntegrityError`.

**Deployment runbook (single maintenance window):**
1. Stop all app instances (auth, parrot, workers, Telegram/CLI resolvers).
2. Backup PostgreSQL (vault + identity + parrot credential tables).
3. Run migrator dry-run → review report → run migration → post-verify.
4. Purge Redis `vault:*` and `session:*` via `SCAN` (forced re-login).
5. Deploy the new major versions of navigator-session, navigator-auth, ai-parrot and the
   frontend together.
6. Start services; smoke-test login, vault CRUD, one integration.

### Edge Cases & Error Handling

- **Tampered / swapped ciphertext** → `VaultIntegrityError`; logged as a security event with
  table, row identity and purpose (never values), audit row `operation='integrity_fail'`.
  Session vault loading skips the entry (current non-blocking behaviour) instead of failing
  login.
- **Unknown `key_id`** (master key removed too early) → distinct error, not `InvalidTag`, so
  operators can tell "missing key" from "tampering".
- **`VAULT_CIPHER_BACKEND` changed** → new writes use the new algorithm; old ciphertexts still
  open because `alg_id` is in the header.
- **Nullable context fields** (`provider_user_id IS NULL`) → canonical encoding distinguishes
  `NULL` from empty string.
- **Identity re-link / `provider_user_id` changes** → tokens re-sealed with the new context in
  the same transaction.
- **Secret key rename** → not supported as an in-place UPDATE; must be delete + set.
- **Master key rotation during live sessions** → `ciphertext_mem` carries `key_id`, so caches
  keep working as long as the old key stays in the ring until sessions expire (TTL). The Redis
  *naming* key must not change on rotation (see Open Questions).
- **Non-integer `user_id`** (username-based backends) → vault stays skipped, as today.
- **Redis absent** → in-process cache only, unchanged.
- **Soft-deleted rows** (`deleted_at IS NOT NULL`) → migrated or purged (see Open Questions);
  they must never remain as v1 because v1 is rejected.
- **Partial migration failure** → batches are transactional and the migrator is resumable;
  deployment must not proceed until post-verify passes.
- **Frontend**: a `401` burst right after deploy must not loop (single redirect, notice shown
  once); vault UI treats `vault_unavailable` as a recoverable banner, not a crash.

---

## Capabilities

### New Capabilities
- `vault-sealed-envelope-v2`: versioned AEAD envelope (format, algorithm, key id, nonce) with mandatory canonical AAD.
- `vault-context-registry`: declarative per-table/column context definitions shared by runtime, rotation and migration.
- `vault-keyed-session-layer`: session-layer key and Redis/audit naming derived from the master key ring.
- `vault-offline-migrator`: v1 → v2 batch migration CLI with dry-run, verify, resume and quarantine.
- `vault-management-ui`: frontend secrets page (list / create / update / delete, write-only values).
- `integration-reconnect-status`: `needs_reconnect` integration state end-to-end (parrot → frontend).

### Modified Capabilities
- Session Vault (`navigator-session` vault spec): crypto API is breaking, audit stores HMAC session ids, metadata listing.
- Identity Vault (FEAT-096, `auth.user_identities` credentials): context-bound encryption.
- Session Vault HTTP API (`/api/v1/user/vault`): no plaintext values returned, metadata responses, distinct integrity error.
- Master key rotation (`key_rotation.py`): registry-driven re-sealing across all registered tables.

---

## Impact & Integration

| Affected Component | Impact Type | Notes |
|---|---|---|
| `navigator-session/navigator_session/vault/crypto.py` | modifies (breaking) | New envelope + seal/open API; legacy functions removed from public API |
| `navigator-session/navigator_session/vault/session_vault.py` | modifies | Context-bound, HMAC'd Redis names, metadata, audit HMAC |
| `navigator-session/navigator_session/vault/key_rotation.py` | modifies | Registry-driven, multi-table |
| `navigator-session/navigator_session/vault/config.py` | extends | Naming-key derivation, cipher/alg id mapping |
| `navigator-session` package version | breaking | Major bump (currently `0.10.2`) |
| `auth.user_vault_secrets`, `auth.user_vault_audit` | data migration | Re-sealed; `session_id` column holds HMAC |
| `navigator-auth/navigator_auth/identity/crypto.py`, `store.py` | modifies | Context argument, re-seal on re-link |
| `auth.user_identities` (credential columns) | data migration | Re-sealed with identity context |
| `navigator-auth/navigator_auth/handlers/vault.py` | modifies (breaking API) | No plaintext in GET; metadata; error code |
| `navigator-auth` `pyproject.toml` | depends on | `navigator-session>=<new major>` |
| `ai-parrot` security/credentials_utils, handlers/credentials, studio/byok, auth/broker, handlers/agent | modifies | Pass contexts to new API |
| `ai-parrot-server/.../models/_encrypted_field.py` | modifies | Replace `_ctx` envelope with AAD; migrator unwraps v1 |
| `ai-parrot-server/.../services/vault_token_sync.py` | depends on | Deterministic session scheme must keep working |
| `ai-parrot-server/.../handlers/integrations.py` | extends | `needs_reconnect` status |
| `navigator-frontend-next/src/routes/profile` | extends | New secrets management section |
| `navigator-frontend-next/src/lib/api/` | extends | Vault API client; `IntegrationDescriptor.status` |
| `navigator-frontend-next/src/lib/api/http.ts`, `src/routes/login` | modifies | Forced re-login notice, no redirect loop |
| Redis | ops | Purge `vault:*` and `session:*` at deploy; new `vault:v2:` key namespace |
| Deployment / CI | ops | Coordinated multi-repo release + maintenance-window runbook |

---

## Parallelism Assessment

- **Internal parallelism:** high once the core lands. `navigator-session` envelope + registry +
  keyed session layer is the blocking foundation. After its API is frozen, these tracks are
  independent (different repos, different files):
  1. navigator-auth (Identity Vault contexts, `VaultView` metadata/errors);
  2. ai-parrot consumer migration + `needs_reconnect`;
  3. offline migrator (depends on the registry, not on consumers' code);
  4. navigator-frontend-next (vault UI, re-login notice, integration status) — can start
     against the agreed API contract even before backend work finishes.
- **Cross-feature independence:** potential conflicts in navigator-auth with in-flight identity
  work — FEAT-096 (Identity Vault, `identity/crypto.py`, `identity/store.py`) and FEAT-098
  (password recovery worktree touches `auth.py` and `handlers/vault.py`). In ai-parrot, the
  O365 device-code features (FEAT-266/267) touch `vault_token_sync.py`. Sequence or rebase
  accordingly.
- **Recommended isolation:** `mixed`.
- **Rationale:** the core crypto task must be sequential and first (everything depends on its
  API); the downstream tracks live in separate repositories with no shared files, so each can
  run in its own worktree in parallel. The final migration + runbook task depends on all of
  them and is sequential again.

---

## Open Questions

- [ ] Redis/audit **naming key** stability: derive from a pinned key version (e.g. a
      `VAULT_NAMING_KEY_ID` or always `v1`) so master-key rotation does not orphan live Redis
      caches, or accept that rotation also purges `vault:*`? — *Owner: Jesus Lara*
- [ ] Soft-deleted rows (`deleted_at IS NOT NULL`): migrate them to v2 or hard-delete them
      during the migration window? — *Owner: Jesus Lara*
- [ ] `VaultTokenSync` writes keys like `jira:access_token`, but `SessionVault._validate_key`
      rejects `:` — verify the actual key separator in use and whether the v2 canonical
      encoding should lift that restriction. — *Owner: ai-parrot maintainers*
- [ ] Session key derivation granularity: per-`(key_id, session_uuid)` HKDF (compartmentalized,
      one derivation per vault instance) vs a single session KEK with `session_uuid` only in AAD
      (cheaper). Security is equivalent against the stated threat model. — *Owner: Jesus Lara*
- [ ] Exact ai-parrot table/column inventory and their context tuples (credentials, BYOK,
      user-bot configs, broker) to register before the migrator is written. — *Owner: ai-parrot maintainers*
- [ ] Should `navigator-session` get its own `sdd/` tree for the core spec, or does the whole
      feature stay tracked in navigator-auth? — *Owner: Jesus Lara*
- [ ] Follow-up feature for per-user DEKs / crypto-shredding (Option B as envelope v3)? —
      *Owner: Jesus Lara*
- [ ] Frontend placement: dedicated `/profile/secrets` route vs a tab inside the existing
      profile page, and the wording of the forced re-login notice. — *Owner: frontend team*
