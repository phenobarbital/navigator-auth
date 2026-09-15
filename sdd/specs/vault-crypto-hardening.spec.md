# Feature Specification: Vault Crypto Hardening (Sealed Envelope v2)

**Feature ID**: FEAT-099
**Date**: 2026-09-15
**Author**: Jesus Lara
**Status**: approved
**Target version**: navigator-session 1.0.0 · navigator-auth 0.28.0 · ai-parrot next minor · navigator-frontend-next (no version)

> **Inputs:** `sdd/proposals/vault-crypto-hardening.brainstorm.md` — Option A
> ("Sealed Envelope v2"), discovery decisions from three rounds (2026-09-15).
> **Cross-repo feature.** The cryptographic core lives in `../navigator-session`
> (no `sdd/` tree there); this spec and its tasks are tracked in navigator-auth.
> Repos touched: `navigator-session`, `navigator-auth`, `ai-parrot`
> (`packages/ai-parrot`, `packages/ai-parrot-server`), `navigator/navigator-frontend-next`.
> **Breaking change** in all three Python packages; they are released and deployed
> together behind a single offline migration window (§2 Deployment Runbook).

---

## 1. Motivation & Business Requirements

### Problem Statement

The Session Vault (`auth.user_vault_secrets`) and every store that reuses its crypto use sound
primitives (AES-256-GCM / ChaCha20-Poly1305, HKDF-SHA256, random 96-bit nonces, key-id prefix)
but two design flaws defeat them.

**F1 — The session-layer key is derived from non-secret data.**
`encrypt_for_session()` (`navigator_session/vault/crypto.py`) derives its key as
`HKDF(session_uuid, "vault-session")`. `session_uuid` is:

- the session cookie value (`navigator_session/storages/redis.py:133`);
- embedded in plaintext in the Redis key name `vault:{session_uuid}:{key}`
  (`session_vault.py:118`) — a Redis read/snapshot yields ciphertext **and** key seed together;
- stored raw in `auth.user_vault_audit.session_id` — a DB reader can harvest live session ids;
- *deterministic and guessable* for non-HTTP callers: ai-parrot's `VaultTokenSync` uses
  `"telegram-persistent:{user_id}"` / `"cli-persistent:{user_id}"`
  (`parrot/services/vault_token_sync.py:52`).

The session layer is therefore obfuscation, not encryption.

**F2 — No AEAD associated data.** All seal/open calls pass `associated_data=None`. Ciphertexts
are not bound to owner, row or column. With write access to storage an attacker can move
user A's secret into user B's row, swap two secrets of one user, or swap `access_token` ↔
`refresh_token` ↔ `id_token` inside one `auth.user_identities` row; decryption succeeds
silently. ai-parrot built an in-plaintext `_ctx` envelope to compensate
(`parrot/handlers/models/_encrypted_field.py`), for one table only.

**F3 — Algorithm not recorded.** `VAULT_CIPHER_BACKEND` selects the AEAD per process and is not
written into ciphertexts; changing it makes all existing data undecryptable.

**F4 — Latent functional bug uncovered during research.** `SessionVault._validate_key` rejects
`:` (because of the Redis key layout), but `VaultTokenSync.store_tokens` writes keys such as
`jira:access_token`. The `ValueError` is swallowed by a broad `except` and logged, so Telegram /
CLI token persistence silently stores nothing.

**Who is affected:** end users (API keys, OAuth tokens, BYOK LLM keys, MCP/tool configs),
operators (Redis and DB backups are currently sensitive assets), developers of every vault
consumer.

### Protected stores (inventory)

| Store | Engine | Row identity | Encrypted field(s) | Crypto entry point today |
|---|---|---|---|---|
| `auth.user_vault_secrets` | PostgreSQL | `(user_id, key)` | `ciphertext_db` | `SessionVault` → `encrypt_for_db` |
| Session cache `vault:{sid}:{key}` | Redis + process memory | `(session_uuid, user_id, key)` | value | `encrypt_for_session` |
| `auth.user_identities` | PostgreSQL | `(user_id, auth_provider, provider_user_id)` | `access_token`, `refresh_token`, `id_token` | `IdentityCipher` → `encrypt_for_db` |
| `user_credentials` | DocumentDB | `(user_id, name)` | `credential` (base64) | `parrot.security.credentials_utils` |
| `user_llm_keys` (BYOK) | DocumentDB | `(user_id, provider)` | `api_key` (base64) | `credentials_utils` via `studio/byok.py`, `auth/broker.py` |
| `{PARROT_SCHEMA}.users_bots` | PostgreSQL | `(user_id, chatbot_id)` | `mcp_config`, `tools_config` | `_encrypted_field.seal/unseal` (`_ctx` envelope) |

### Goals

- **G1** — Session-layer keys, Redis key names and audit session references require a server
  secret derived from the existing master key ring (no new mandatory env var).
- **G2** — Every ciphertext is bound by **mandatory AEAD AAD** to *purpose + row identity +
  field*; substitution across users, rows or columns fails with an integrity error.
- **G3** — One versioned, self-describing envelope (format version, algorithm id, key id,
  nonce) for DB and session layers; the header is authenticated.
- **G4** — One **context registry** drives runtime seal/open, master-key rotation and the
  migration, for every store in the inventory (PostgreSQL and DocumentDB).
- **G5** — An **offline batch migrator** converts all v1 data to v2 with dry-run, mandatory
  pre-migration raw export (backup), verify, resume, restore and explicit quarantine; after
  migration v1 is rejected at runtime.
- **G6** — `GET /api/v1/user/vault/{key}` no longer returns plaintext; the HTTP API exposes
  metadata only.
- **G7** — Frontend: vault secrets management UI (list/create/update/delete, write-only
  values), graceful forced re-login after deploy, `needs_reconnect` integration status.
- **G8** — Fix F4: vault key names may contain `:`; `VaultTokenSync` persists tokens.

### Non-Goals (explicitly out of scope)

- Per-user DEKs / crypto-shredding (brainstorm Option B) — possible future envelope v3.
- External KMS (AWS KMS, Vault Transit) or Google Tink.
- Runtime dual-read of v1 and v2 (decided: offline migration, v1 rejected afterwards).
- Keeping sessions alive across the deploy (decided: purge + forced re-login).
- Revealing secret values to the browser, including behind step-up auth.
- Fixing multi-worker cache consistency of `SessionVault.keys()` / `exists()` (they read the
  in-process cache only) beyond what the new metadata listing needs.
- Changing password hashing, JWT signing, `libs/cipher.pyx` (`AUTH_TOKEN_SECRET` AES-CFB) or
  navconfig's `FileCypher` — separate concerns.

---

## 2. Architectural Design

### Overview

`navigator-session` gains a small crypto kernel under `navigator_session/vault/`:

1. **`KeyRing`** — loads `VAULT_MASTER_KEY_v{N}` / `VAULT_ACTIVE_KEY_ID`, selects the write
   algorithm, and derives per-purpose sub-keys with HKDF-SHA256 using v2-only, domain-separated
   `info` labels. It never exposes raw master keys to callers.
2. **Envelope v2** — `seal(plaintext, context, keyring)` / `open_sealed(blob, context, keyring)`.
   AAD = canonical encoding of *(header ‖ context)*. Opening requires the **expected** context
   and fails closed.
3. **`VaultContext`** — typed context: `purpose`, `layer`, ordered identity fields.
4. **Context registry** — `ProtectedTarget` descriptors (store name, engine adapter, context
   builder, encrypted fields). Packages contribute targets through the entry-point group
   `navigator_session.vault_targets`; rotation and migration discover them.
5. **Migrator** — `navigator-vault` CLI (dry-run → migrate → verify → report), with the only
   copy of v1 decryption isolated in a `legacy_v1` module.

Downstream packages stop importing `encrypt_for_db` / `decrypt_for_db` and call the kernel with
their context. navigator-auth serves metadata-only vault endpoints; ai-parrot migrates its five
call sites and reports `needs_reconnect`; the frontend adds the secrets UI and handles the
forced re-login.

### Envelope v2 format

```
offset  size  field
0       1     format_version   0xA2   (v1 blobs start with key_id's high byte; 0xA2 cannot
                                       collide for key ids < 41472)
1       1     alg_id           0x01 AES-256-GCM · 0x02 ChaCha20-Poly1305
2       2     key_id           uint16 big-endian
4       12    nonce            os.urandom(12)
16      n     ciphertext
16+n    16    tag
```

- Header (16 bytes) is part of the AAD → `key_id` / `alg_id` tampering fails authentication.
- Minimum blob length: 32 bytes.
- DocumentDB fields keep their base64 text representation; PostgreSQL `bytea` unchanged.

### Key schedule (HKDF-SHA256, 32-byte outputs)

| Sub-key | IKM | `info` |
|---|---|---|
| DB key | `master_key[key_id]` | `"navigator-vault/v2/db" ‖ alg_id` |
| Session key | `master_key[key_id]` | `"navigator-vault/v2/session" ‖ alg_id ‖ lp(session_uuid)` |
| Naming key | `master_key[naming_key_id]` | `"navigator-vault/v2/naming"` |

`lp(x)` = 4-byte big-endian length prefix + UTF-8 bytes. v2 labels differ from v1
(`"vault-db-v{N}"`, `"vault-session"`), so no v1 key is ever reused. Session keys are derived
once per `SessionVault` instance and cached in memory. `naming_key_id` = `VAULT_NAMING_KEY_ID`
if set, else the **lowest** key id in the ring (stable across normal rotations; see §6).

### Canonical AAD encoding

```
AAD = "NAVVAULT-AAD" ‖ header(16B) ‖ lp(purpose) ‖ lp(layer) ‖ u16(field_count)
      ‖ for each (name, value): lp(name) ‖ type_tag(1B) ‖ lp(encoded_value)
type_tag: 0x00 NULL (empty value) · 0x01 str (UTF-8) · 0x02 int (decimal ASCII) · 0x03 UUID (canonical lowercase)
```

Field order is fixed by the target definition; `NULL` and `""` are distinct.

### Registered contexts

| Target | purpose | layer | Context fields (ordered) | Field name in AAD |
|---|---|---|---|---|
| user vault (DB) | `user-vault` | `db` | `user_id`, `key` | — (single field) |
| user vault (session) | `user-vault` | `session` | `sid_hmac`, `user_id`, `key` | — |
| identity credentials | `identity` | `db` | `user_id`, `auth_provider`, `provider_user_id`, `field` | `access_token` · `refresh_token` · `id_token` |
| parrot credentials | `parrot-credential` | `db` | `user_id`, `name`, `field` | `credential` |
| parrot BYOK | `parrot-llm-key` | `db` | `user_id`, `provider`, `field` | `api_key` |
| parrot user bots | `parrot-user-bot` | `db` | `user_id`, `chatbot_id`, `field` | `mcp_config` · `tools_config` |

### Component Diagram

```
                     ┌──────────────────── navigator-session ────────────────────┐
 env VAULT_MASTER_KEY_v{N}, VAULT_ACTIVE_KEY_ID, VAULT_CIPHER_BACKEND, [VAULT_NAMING_KEY_ID]
                     │                                                            │
                     ▼                                                            │
                  KeyRing ──► db_key / session_key / naming_hmac                  │
                     │                                                            │
       VaultContext ─┼─► envelope.seal / open_sealed ─► VaultIntegrityError       │
                     │            ▲                     UnknownKeyVersionError    │
                     │            │                     UnsupportedFormatError    │
     registry (entry points: navigator_session.vault_targets)                     │
        │        │           │                                                    │
        │   key_rotation   migrate CLI (navigator-vault) ─► legacy_v1 (read-only) │
        │                                                                          │
   SessionVault (user-vault db+session, HMAC Redis names, HMAC audit sid)          │
                     └────────────────────────────────────────────────────────────┘
          ▲                         ▲                              ▲
 navigator-auth                ai-parrot                     ai-parrot-server
  IdentityCipher/Store          security/credentials_utils    handlers/credentials, studio/byok,
  VaultView (metadata only)     security/vault_utils          handlers/agent, models/_encrypted_field
  targets: user_vault,          auth/broker                   services/vault_token_sync
           identity             targets: credentials, byok    integrations → needs_reconnect
                                                              target: users_bots
          ▲                                                        ▲
          └──────────────── navigator-frontend-next ───────────────┘
            /profile Secrets UI · vault API client · login notice · integration status
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `navigator_session/vault/crypto.py` | modifies (breaking) | `encrypt_for_*`/`decrypt_for_*` removed from public API; serializer kept |
| `navigator_session/vault/config.py` | extends | `KeyRing`, alg-id mapping, `VAULT_NAMING_KEY_ID`; `VaultConfig` validates it |
| `navigator_session/vault/session_vault.py` | modifies | Context-bound seal/open, HMAC Redis names, HMAC audit sid, metadata, `:` allowed |
| `navigator_session/vault/key_rotation.py` | modifies | Registry-driven, all targets, v2 only |
| `navigator_session/storages/redis.py` | uses | Session ids only as HKDF/HMAC input; no change |
| `navigator_auth/identity/crypto.py` (`IdentityCipher`) | modifies (breaking) | `encrypt`/`decrypt` take identity context |
| `navigator_auth/identity/store.py` (`IdentityStore`) | modifies | Builds contexts; re-seals when `provider_user_id` changes |
| `navigator_auth/handlers/vault.py` (`VaultView`) | modifies (breaking HTTP) | Metadata only; typed errors |
| `navigator_auth/vault/integration.py` | modifies | Maps kernel errors; loading stays non-blocking |
| `navigator_auth/vault/sql/` | extends | Migration: `user_vault_audit.session_id` semantics → HMAC (column comment / length) |
| `parrot/security/credentials_utils.py`, `vault_utils.py` | modifies | Context arguments; targets for `user_credentials` |
| `parrot/auth/broker.py`, `handlers/studio/byok.py` | modifies | BYOK context; target for `user_llm_keys` |
| `parrot/handlers/credentials.py`, `handlers/agent.py` | modifies | Pass contexts |
| `parrot/handlers/models/_encrypted_field.py`, `users_bots.py` | modifies | `_ctx` envelope replaced by AAD; target for `users_bots` |
| `parrot/services/vault_token_sync.py` | uses | Deterministic scheme preserved; F4 fixed by kernel change |
| `parrot/handlers/integrations.py` | extends | `status` incl. `needs_reconnect` |
| `navigator-frontend-next/src/lib/api/http.ts` | modifies | Forced re-login reason, no redirect loop |
| `navigator-frontend-next/src/lib/api/integrations.ts` | extends | `IntegrationDescriptor.status` |
| `navigator-frontend-next/src/routes/profile/` | extends | New `/profile/secrets` route + "Manage secrets" link on `/profile` |

### Data Models

```python
from typing import Literal, Optional, Union
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field

ContextValue = Union[str, int, UUID, None]

class VaultContext(BaseModel):
    """Identity a ciphertext is bound to (becomes AEAD associated data)."""
    purpose: str                      # e.g. "user-vault", "identity"
    layer: Literal["db", "session"]
    fields: tuple[tuple[str, ContextValue], ...]   # ordered, fixed per target

class EnvelopeHeader(BaseModel):
    format_version: int = 0xA2
    alg_id: Literal[1, 2]
    key_id: int = Field(ge=1, le=65535)
    nonce: bytes                      # 12 bytes

class VaultSecretMetadata(BaseModel):
    """What the HTTP API and UI may see about a secret."""
    key: str
    updated_at: datetime
    key_version: int

class MigrationTargetReport(BaseModel):
    target: str
    total: int
    migrated: int
    already_v2: int
    failed: int
    quarantined: int
    failed_refs: list[str]            # row identities only, never values

class MigrationReport(BaseModel):
    started_at: datetime
    finished_at: Optional[datetime]
    dry_run: bool
    targets: list[MigrationTargetReport]
    verified: bool
```

```typescript
// navigator-frontend-next
export type IntegrationStatus = "connected" | "disconnected" | "needs_reconnect";
export interface VaultSecretMetadata { key: string; updated_at: string; key_version: number; }
```

### New Public Interfaces

```python
# navigator_session/vault/keyring.py
class KeyRing:
    @classmethod
    def from_env(cls) -> "KeyRing": ...
    @property
    def active_key_id(self) -> int: ...
    @property
    def write_alg_id(self) -> int: ...
    def has_key(self, key_id: int) -> bool: ...
    def naming_hmac(self, value: str) -> str: ...           # hex, used for Redis names / audit sid

# navigator_session/vault/envelope.py
class VaultCryptoError(Exception): ...
class VaultIntegrityError(VaultCryptoError): ...           # tag mismatch (tamper / wrong context)
class UnknownKeyVersionError(VaultCryptoError, KeyError): ...
class UnsupportedFormatError(VaultCryptoError): ...        # not v2 (incl. legacy v1) / bad alg

def seal(plaintext: bytes, context: VaultContext, keyring: KeyRing,
         *, session_uuid: Optional[str] = None) -> bytes: ...
def open_sealed(blob: bytes, context: VaultContext, keyring: KeyRing,
                *, session_uuid: Optional[str] = None) -> bytes: ...
def seal_value(value: Any, context: VaultContext, keyring: KeyRing, **kw) -> bytes: ...   # serialize + seal
def open_value(blob: bytes, context: VaultContext, keyring: KeyRing, **kw) -> Any: ...

# navigator_session/vault/registry.py
class TargetRow(Protocol):
    ref: str                                    # printable row identity, no secrets
    values: dict[str, Optional[bytes]]          # encrypted field -> blob

class ProtectedTarget(Protocol):
    name: str                                   # "auth.user_vault_secrets", "docdb:user_credentials", ...
    encrypted_fields: tuple[str, ...]
    def context_for(self, row: TargetRow, field: str) -> VaultContext: ...
    async def iter_batches(self, batch_size: int) -> AsyncIterator[list[TargetRow]]: ...
    async def write(self, row: TargetRow, blobs: dict[str, Optional[bytes]],
                    key_version: int) -> None: ...
    async def quarantine(self, row: TargetRow, reason: str, run_id: str) -> None: ...
    async def export_raw(self, sink: "BackupSink") -> int: ...      # rows/documents exported as-is
    async def restore_raw(self, source: "BackupSource") -> int: ...  # rollback from export

def discover_targets(**resources: Any) -> list[ProtectedTarget]: ...  # entry points

# navigator_session/vault/key_rotation.py
async def rotate_master_key(targets: list[ProtectedTarget], old_key_id: int,
                            new_key_id: int, keyring: KeyRing,
                            batch_size: int = 100) -> dict[str, dict]: ...

# navigator_session/vault/migrate/  (CLI entry point: navigator-vault)
#   navigator-vault migrate --dry-run
#   navigator-vault migrate --run --backup-dir DIR [--quarantine] [--batch-size N] [--target NAME ...]
#   navigator-vault verify
#   navigator-vault restore --backup-dir DIR [--target NAME ...]   (rollback)
#   navigator-vault purge-redis [--sessions]            (SCAN-based, runbook step)
async def migrate_v1_to_v2(targets: list[ProtectedTarget], keyring: KeyRing, *,
                           dry_run: bool, quarantine: bool, backup_dir: Optional[Path],
                           batch_size: int = 100) -> MigrationReport: ...
async def restore_backup(targets: list[ProtectedTarget], backup_dir: Path) -> MigrationReport: ...
async def verify_v2(targets: list[ProtectedTarget], keyring: KeyRing) -> MigrationReport: ...

# SessionVault (signatures unchanged except):
class SessionVault:
    async def list_metadata(self) -> list[VaultSecretMetadata]: ...

# navigator_auth/identity/crypto.py
class IdentityCipher:
    def encrypt(self, value: Any, *, user_id: int, auth_provider: str,
                provider_user_id: Optional[str], field: str) -> bytes: ...
    def decrypt(self, blob: bytes, *, user_id: int, auth_provider: str,
                provider_user_id: Optional[str], field: str) -> Any: ...

# parrot/security/credentials_utils.py
def encrypt_credential(credential: dict, context: VaultContext, keyring: KeyRing) -> str: ...
def decrypt_credential(encrypted: str, context: VaultContext, keyring: KeyRing) -> dict: ...
```

**HTTP contract (navigator-auth):**

| Method & path | Response (2xx) | Errors |
|---|---|---|
| `GET /api/v1/user/vault` | `{"secrets": [VaultSecretMetadata, ...]}` | `503 {"error": "vault_unavailable"}` |
| `GET /api/v1/user/vault/{key}` | `VaultSecretMetadata` (**no `value`**) | `404`, `409 {"error": "vault_integrity_error"}`, `503` |
| `POST /api/v1/user/vault` | `201 {"key", "updated_at", "key_version", "message"}` (superset of current body) | `400` validation, `503` |
| `DELETE /api/v1/user/vault/{key}` | `200` (unchanged) | `404`, `503` |

**HTTP contract (ai-parrot):** `GET /api/v1/agents/integrations/{agentId}` descriptors gain
`status: "connected" | "disconnected" | "needs_reconnect"`; `connected` stays for backward
compatibility (`true` only when `status == "connected"`).

### Deployment Runbook (single maintenance window)

The maintenance window date is scheduled by ops (out of scope). The spec requires full
downtime of vault readers/writers; the expected duration is measured in the Module 14
rehearsal and recorded in the runbook.

1. Stop every writer/reader: navigator-auth apps, ai-parrot servers/workers, Telegram/CLI
   resolvers.
2. Install the new package versions in the migration environment (all targets discoverable).
3. `navigator-vault migrate --dry-run` → review report (must show `failed == 0`, or failures
   explicitly accepted for quarantine).
4. `navigator-vault migrate --run --backup-dir /secure/path [--quarantine]`. Before touching a
   target, the CLI exports every row/document of that target **as stored** (v1 ciphertext,
   never plaintext) to `backup-dir/<run_id>/<target>.jsonl` plus a manifest with counts and
   SHA-256 per file; the run aborts if the export fails or the directory is not writable/empty.
5. `navigator-vault verify` (must be `verified`).
6. `navigator-vault purge-redis --sessions` (removes `vault:*` and `session:*` → forced re-login).
7. Deploy navigator-session 1.0.0, navigator-auth 0.28.0, ai-parrot, frontend together.
8. Start services; smoke test: login (notice shown), `/profile/secrets` CRUD, one
   identity-backed call, one BYOK call, one integration, one `VaultTokenSync` round trip.
9. Rollback = stop services → `navigator-vault restore --backup-dir /secure/path/<run_id>`
   (restores v1 blobs, including quarantined items, and removes `*_quarantine` copies) →
   redeploy previous versions (v2 data is unreadable by old code by design).

**Quarantine semantics (`--quarantine`):**

| Engine | Action | Visibility |
|---|---|---|
| PostgreSQL targets | `deleted_at = NOW()` (soft-delete) + audit row `operation='quarantine'` with reason and `run_id`; identity rows: `enabled = false` + token columns kept as-is | Row disappears from runtime reads; user re-creates / re-links |
| DocumentDB targets | Copy to `<collection>_quarantine` (e.g. `user_credentials_quarantine`) with `quarantined_at`, `reason`, `run_id`, original `_id`; then delete from the original collection | Document disappears from runtime reads; recoverable by ops or `restore` |

---

## 3. Module Breakdown

> Repos: **NS** = `../navigator-session`, **NA** = `navigator-auth`,
> **AP** = `../ai-parrot/packages/ai-parrot`, **APS** = `../ai-parrot/packages/ai-parrot-server`,
> **FE** = `../navigator/navigator-frontend-next`.

### Module 1: KeyRing & key schedule (NS)
- **Path**: `navigator_session/vault/keyring.py`, `navigator_session/vault/config.py`
- **Responsibility**: Load/validate master key ring, active key id, write algorithm and naming
  key id; HKDF sub-key derivation with v2 labels; `naming_hmac`. Raw master keys never leave
  the object.
- **Depends on**: existing `config.py` (`load_master_keys`, `VaultConfig`)

### Module 2: Envelope v2, canonical AAD & errors (NS)
- **Path**: `navigator_session/vault/envelope.py`, `navigator_session/vault/context.py`,
  `navigator_session/vault/crypto.py` (serializer only remains), `navigator_session/vault/__init__.py`
- **Responsibility**: `VaultContext`, canonical AAD encoding, header pack/parse, `seal` /
  `open_sealed` / `seal_value` / `open_value`, typed errors; remove `encrypt_for_*` /
  `decrypt_for_*` from the public API.
- **Depends on**: Module 1

### Module 3: Context registry & PostgreSQL target base (NS)
- **Path**: `navigator_session/vault/registry.py`, `navigator_session/vault/targets/postgres.py`,
  `navigator_session/vault/targets/user_vault.py`, `pyproject.toml` (entry-point group)
- **Responsibility**: `ProtectedTarget`/`TargetRow` protocols, entry-point discovery, reusable
  asyncpg target base (keyset pagination by PK, per-batch transactions), `user_vault` target.
- **Depends on**: Module 2

### Module 4: SessionVault v2 (NS)
- **Path**: `navigator_session/vault/session_vault.py`
- **Responsibility**: Use `KeyRing` + contexts for DB and session layers; Redis names
  `vault:v2:{naming_hmac(session_uuid)}:{naming_hmac(key)}`; audit stores
  `naming_hmac(session_uuid)`; allow `:` in key names (forbid empty, >255 chars, control
  chars); `list_metadata()` (loads `updated_at`, `key_version`); integrity failures on load
  skip the entry and audit `integrity_fail`.
- **Depends on**: Modules 2, 3

### Module 5: Registry-driven key rotation (NS)
- **Path**: `navigator_session/vault/key_rotation.py`
- **Responsibility**: Rotate every discovered target from `old_key_id` to `new_key_id` using
  each target's contexts; keep per-batch transactions, error-offset semantics and stats per
  target.
- **Depends on**: Module 3

### Module 6: Offline migrator CLI (NS)
- **Path**: `navigator_session/vault/migrate/legacy_v1.py`, `migrate/runner.py`,
  `migrate/cli.py`, `pyproject.toml` (`navigator-vault` script)
- **Path (additional)**: `migrate/backup.py` (JSONL sink/source, manifest, SHA-256)
- **Responsibility**: v1 decrypt (isolated, not exported), dry-run/run/verify/restore,
  mandatory `--backup-dir` export before each target is migrated, quarantine delegated to each
  target (§2 Quarantine semantics), resumable (rows already v2 are skipped; an existing
  manifest for the same `run_id` is reused), `MigrationReport` JSON output, SCAN-based
  `purge-redis`. Targets may provide a `legacy_unwrap` hook (used by Module 11). PostgreSQL
  quarantine/export/restore implemented in the Module 3 target base.
- **Depends on**: Modules 2, 3

### Module 7: Identity Vault contexts & targets (NA)
- **Path**: `navigator_auth/identity/crypto.py`, `navigator_auth/identity/store.py`,
  `navigator_auth/identity/targets.py`, `pyproject.toml` (entry point, `navigator-session>=1.0.0`)
- **Responsibility**: `IdentityCipher` with identity contexts; `IdentityStore` passes context
  per field and re-seals all token fields when `provider_user_id` changes; `identity` target
  for rotation/migration.
- **Depends on**: Modules 2, 3

### Module 8: Session Vault HTTP API v2 (NA)
- **Path**: `navigator_auth/handlers/vault.py`, `navigator_auth/vault/integration.py`,
  `navigator_auth/vault/sql/002_vault_audit_sid_hmac.sql`, `navigator_auth/vault/migrations.py`
- **Responsibility**: Metadata-only GET responses, typed error mapping (`409`/`503`), audit
  column migration, non-blocking vault loading preserved.
- **Depends on**: Module 4

### Module 9: ai-parrot credentials & BYOK (AP + APS)
- **Path**: AP `parrot/security/credentials_utils.py`, `parrot/security/vault_utils.py`,
  `parrot/auth/broker.py`, `parrot/vault_targets.py`; APS `parrot/handlers/credentials.py`,
  `parrot/handlers/credentials_utils.py`, `parrot/handlers/studio/byok.py`,
  `parrot/handlers/agent.py`
- **Responsibility**: Context-bound credential helpers; DocumentDB targets
  `user_credentials` (`user_id`, `name`) and `user_llm_keys` (`user_id`, `provider`) including
  `export_raw`/`restore_raw` and quarantine by move to `<collection>_quarantine`; all five
  call sites pass contexts; renames of `name`/`provider` re-seal.
- **Depends on**: Modules 2, 3

### Module 10: Integration status & VaultTokenSync (APS)
- **Path**: `parrot/handlers/integrations.py`, `parrot/services/vault_token_sync.py`
- **Responsibility**: Map `VaultIntegrityError` / `UnknownKeyVersionError` to
  `needs_reconnect`; add `status` to descriptors; confirm `VaultTokenSync` round-trips
  `{provider}:{field}` keys with the deterministic session scheme (F4 regression test).
- **Depends on**: Modules 4, 9

### Module 11: users_bots encrypted fields (APS)
- **Path**: `parrot/handlers/models/_encrypted_field.py`, `parrot/handlers/models/users_bots.py`,
  `parrot/vault_targets.py` (APS)
- **Responsibility**: Replace `_ctx` envelope with AAD context `(user_id, chatbot_id, field)`;
  `users_bots` target whose `legacy_unwrap` verifies the v1 `_ctx` envelope before re-sealing
  the inner value.
- **Depends on**: Modules 2, 3, 6

### Module 12: Frontend vault API client & Secrets UI (FE)
- **Path**: `src/lib/api/vault.ts`, `src/routes/profile/secrets/+page.svelte`,
  `src/lib/components/profile/UserSecrets*.svelte`, `src/routes/profile/+page.svelte` (link),
  tests alongside
- **Responsibility**: Typed client for the §2 HTTP contract; dedicated route
  `/profile/secrets` under the same `AuthGuard` as `/profile`, reachable via a
  "Manage secrets" link on the profile page (next to the tabs) and by direct URL; list (name,
  updated, key version), create/update with write-only masked value (never pre-filled), row
  refreshed from the POST metadata response, delete with confirmation, inline validation,
  `vault_unavailable` / `vault_integrity_error` banners.
- **Depends on**: HTTP contract (§2) — can start before Module 8 lands (mocked client)

### Module 13: Frontend forced re-login & integration status (FE)
- **Path**: `src/lib/api/http.ts`, `src/routes/login/`, `src/lib/api/integrations.ts`,
  integrations panel components
- **Responsibility**: 401 → single redirect to `/login?reason=session_expired` (no loop, notice
  shown once). Notice text: *"Your session has ended because of a security update. Please
  sign in again."* `IntegrationDescriptor.status` with a "Reconnect" action for
  `needs_reconnect`.
- **Depends on**: HTTP contracts (§2) — can start before Module 10 lands

### Module 14: Runbook, docs & cross-repo verification (NS + NA)
- **Path**: NS `docs/vault/` (format, key schedule, migration runbook), NA `docs/`,
  CHANGELOGs in NS/NA/AP/APS, NS `tests/integration/test_vault_migration_e2e.py`
- **Responsibility**: Operator runbook (§2), threat-model update in
  `navigator_session/vault/__init__.py`, end-to-end migration rehearsal over all targets with
  seeded v1 data.
- **Depends on**: Modules 1–13

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_keyring_loads_ring_and_active_key` | M1 | Valid env → ids, write alg; invalid key length / missing active key raise |
| `test_keyring_subkeys_domain_separated` | M1 | DB, session and naming keys differ for same master key; differ from v1 derivations |
| `test_naming_key_stable_across_active_rotation` | M1 | Changing `VAULT_ACTIVE_KEY_ID` does not change `naming_hmac` |
| `test_session_key_requires_master_key` | M1 | Same `session_uuid`, different master key → different session key |
| `test_seal_open_roundtrip_both_algs` | M2 | AES-GCM and ChaCha20 round-trip; `alg_id` recorded |
| `test_open_with_changed_backend_env` | M2 | Blob sealed with AES opens after `VAULT_CIPHER_BACKEND=chacha20` |
| `test_open_rejects_wrong_context` | M2 | Different user_id / key / field / purpose / layer → `VaultIntegrityError` |
| `test_open_rejects_header_tamper` | M2 | Flipped `key_id` or `alg_id` byte → integrity or unknown-key error, never plaintext |
| `test_open_rejects_v1_blob` | M2 | Legacy v1 ciphertext → `UnsupportedFormatError` |
| `test_aad_null_vs_empty_distinct` | M2 | `None` and `""` context values produce different AAD |
| `test_aad_no_concatenation_ambiguity` | M2 | `("a:b","c")` vs `("a","b:c")` → different AAD |
| `test_unknown_key_version` | M2 | Removed key id → `UnknownKeyVersionError` |
| `test_short_blob_rejected` | M2 | < 32 bytes → `UnsupportedFormatError` |
| `test_registry_discovers_entry_points` | M3 | Targets from installed entry points are returned; bad target logged and skipped |
| `test_postgres_target_keyset_pagination` | M3 | All rows visited once with concurrent updates excluded |
| `test_session_vault_redis_names_hmac` | M4 | Redis keys contain neither session_uuid nor key name |
| `test_session_vault_audit_sid_hmac` | M4 | Audit insert receives HMAC, not raw session id |
| `test_session_vault_allows_colon_keys` | M4 | `jira:access_token` set/get works; control chars rejected |
| `test_session_vault_cross_user_swap_detected` | M4 | Row blob copied to another user → entry skipped + `integrity_fail` audit |
| `test_session_vault_list_metadata` | M4 | Returns key, updated_at, key_version; no values |
| `test_rotation_all_targets` | M5 | Mixed targets rotated; stats per target; failed rows stay on old key |
| `test_migrate_dry_run_no_writes` | M6 | Report counts, zero writes |
| `test_migrate_resumable` | M6 | Interrupted run resumes; v2 rows counted as `already_v2` |
| `test_migrate_failure_blocks_without_quarantine` | M6 | Undecryptable row → non-zero exit, not verified |
| `test_migrate_quarantine_postgres` | M3/M6 | `--quarantine` soft-deletes the row and writes `operation='quarantine'` audit with `run_id` |
| `test_migrate_run_requires_backup_dir` | M6 | `--run` without `--backup-dir`, or with a non-writable/non-empty dir → exit non-zero, zero writes |
| `test_backup_export_before_migration` | M6 | Each target's JSONL + manifest (counts, SHA-256) exists before its first write; export failure aborts that target |
| `test_backup_contains_no_plaintext` | M6 | Exported records hold stored blobs only; known plaintext never appears in files |
| `test_restore_roundtrip` | M6 | migrate → restore → all rows byte-identical to pre-migration, quarantined items back in place |
| `test_legacy_v1_not_exported` | M6 | `legacy_v1` not importable from `navigator_session.vault` public API |
| `test_identity_field_swap_detected` | M7 | access_token blob moved to refresh_token → integrity error |
| `test_identity_relink_reseals` | M7 | `provider_user_id` change re-seals every token field |
| `test_vault_view_get_key_returns_metadata_only` | M8 | Response has no `value` field |
| `test_vault_view_integrity_error_409` / `_unavailable_503` | M8 | Typed error bodies |
| `test_vault_view_post_returns_metadata` | M8 | `201` body has `key`, `updated_at`, `key_version`, `message`; no `value` |
| `test_credentials_context_bound` | M9 | `user_credentials` doc moved to another user/name → decrypt fails |
| `test_byok_context_bound` | M9 | `user_llm_keys` provider swap → decrypt fails |
| `test_docdb_quarantine_moves_document` | M9 | Quarantined doc copied to `<collection>_quarantine` with `quarantined_at`, `reason`, `run_id`, original `_id`, then removed from source |
| `test_docdb_restore_removes_quarantine_copy` | M9 | `restore_raw` puts the original back and deletes the quarantine copy |
| `test_integrations_needs_reconnect` | M10 | Integrity error on stored token → `status == "needs_reconnect"`, `connected == false` |
| `test_vault_token_sync_roundtrip` | M10 | Deterministic session scheme stores and reads `{provider}:{field}` (F4) |
| `test_users_bots_field_swap_detected` | M11 | `mcp_config` ↔ `tools_config` swap → integrity error |
| `test_users_bots_legacy_unwrap_checks_ctx` | M11 | v1 blob with mismatching `_ctx` → migration failure, not re-sealed |
| `vault.test.ts` | M12 | Client parses metadata; never sends/reads `value` on GET |
| `UserSecrets` component tests | M12 | Value input masked, never pre-filled; row updated from POST metadata; delete confirmation; error banners |
| `/profile/secrets` route tests | M12 | Route guarded by `AuthGuard` (unauthenticated → `/login`); "Manage secrets" link on `/profile` navigates to it |
| `http.test.ts` (re-login) | M13 | Burst of 401s → one redirect with `reason=session_expired` |
| login notice test | M13 | `reason=session_expired` renders the exact security-update notice once; absent otherwise |
| `integrations` status tests | M13 | `needs_reconnect` renders Reconnect action |

### Integration Tests
| Test | Description |
|---|---|
| `test_vault_migration_e2e` (NS) | Seed v1 data in all PostgreSQL targets + DocumentDB fixtures → dry-run → run → verify → runtime opens every row with v2; v1 rejected |
| `test_rotation_after_migration` (NS) | Migrate, add `VAULT_MASTER_KEY_v2`, rotate, open all rows; Redis naming unchanged |
| `test_login_loads_vault_v2` (NA) | Login → vault loaded → `/api/v1/user/vault` metadata; Redis dump contains no session id/key names |
| `test_redis_dump_not_decryptable` (NS) | Using only Redis contents + session cookie, decryption fails (no master key) |
| `test_cross_user_substitution_db` (NA) | SQL UPDATE copying `ciphertext_db` between users → secret skipped on login, audit written, login succeeds |
| `test_parrot_mcp_restore_with_v2_credentials` (APS) | `handlers/agent.py` MCP restore decrypts context-bound `user_credentials` |
| Frontend e2e (FE, Playwright/Vitest browser) | Secrets page CRUD against mocked API; forced re-login notice |

### Test Data / Fixtures
```python
@pytest.fixture
def master_key_env(monkeypatch):
    """Two-version key ring with v1 active; lowest id (1) is the naming key."""
    ...

@pytest.fixture
def keyring(master_key_env) -> "KeyRing": ...

@pytest.fixture
def v1_seed_rows():
    """Legacy blobs produced with the pre-1.0 encrypt_for_db for every target (frozen bytes)."""
    ...

@pytest.fixture
def fake_docdb():
    """In-memory DocumentDB double implementing read/read_one/update_one used by parrot targets."""
    ...

@pytest.fixture
def fake_redis():
    """Async Redis double recording key names for HMAC assertions."""
    ...
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] No production code path in NS/NA/AP/APS calls AEAD `encrypt`/`decrypt` with
      `associated_data=None` (grep check in CI for `encrypt(nonce, .*, None)` patterns).
- [ ] `encrypt_for_db`, `decrypt_for_db`, `encrypt_for_session`, `decrypt_for_session` are no
      longer importable from `navigator_session.vault`; no references remain in NA/AP/APS.
- [ ] Every ciphertext written by the new code starts with `0xA2`, carries `alg_id` and
      `key_id`, and opens only with its exact registered context.
- [ ] Moving a ciphertext across users, rows or fields fails with `VaultIntegrityError` for all
      six inventory stores (unit tests per store).
- [ ] With Redis contents plus a valid session cookie but without master keys, no vault value
      can be decrypted (integration test).
- [ ] Redis key names and `auth.user_vault_audit.session_id` contain no raw session ids or
      secret names.
- [ ] Changing `VAULT_CIPHER_BACKEND` does not break reading existing v2 data.
- [ ] Master key rotation re-seals all targets and does not change Redis naming (unless the
      naming key id is removed — documented).
- [ ] `navigator-vault migrate --dry-run/--run/verify/restore` works over all targets; migration
      rehearsal on seeded v1 data ends `verified: true`; runtime rejects v1 blobs.
- [ ] `migrate --run` refuses to start without a valid `--backup-dir`, exports every target
      (stored blobs only, manifest with SHA-256) before writing, and `restore` returns all
      targets to their exact pre-migration bytes.
- [ ] Quarantine: PostgreSQL rows soft-deleted + audited; DocumentDB documents moved to
      `<collection>_quarantine` with `quarantined_at`, `reason`, `run_id`.
- [ ] Rehearsal (Module 14) records migration + verify duration in the runbook.
- [ ] `GET /api/v1/user/vault/{key}` responses never include `value`; `POST` returns
      `key`, `updated_at`, `key_version`, `message`.
- [ ] `VaultTokenSync` persists and reads `{provider}:{field}` tokens (F4 fixed).
- [ ] Vault failures still never block login (existing integration tests remain green).
- [ ] Frontend: `/profile/secrets` (linked from `/profile`) CRUD with write-only values; forced
      re-login shows *"Your session has ended because of a security update. Please sign in
      again."* once without redirect loops; integrations show `needs_reconnect` with a
      Reconnect action.
- [ ] Unit and integration tests pass in each repo:
      NS `pytest tests/ -v`, NA `pytest tests/ -v`, AP/APS `pytest` for touched packages,
      FE `pnpm test` (vitest).
- [ ] No plaintext, ciphertext, derived keys or raw session ids in logs (log-capture tests on
      seal/open, migration and rotation paths).
- [ ] Runbook, format and key-schedule docs published (`navigator-session/docs/vault/`);
      CHANGELOGs mark the breaking changes; versions bumped as in the header.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- Keep the kernel dependency-light: `cryptography`, `orjson`, `pydantic`; asyncpg/redis only in
  target/CLI modules; **no DocumentDB/asyncdb dependency in navigator-session** — DocumentDB
  targets live in ai-parrot and are discovered via entry points.
- Async-first for targets, migration and rotation; seal/open stay synchronous (CPU-bound, tiny).
- Pydantic models for contexts, reports and configuration; Google-style docstrings; strict type
  hints.
- Reuse the acquire/release compatibility pattern already in `session_vault.py` for pools that
  expose `acquire()` both as context manager and awaitable.
- Keyset pagination (`WHERE pk > $last ORDER BY pk LIMIT n`) for targets instead of `OFFSET`,
  avoiding the skip bug fixed in `key_rotation.py`.
- Loggers: `navigator.vault` (NS/NA), module loggers in ai-parrot; log target names, row refs,
  key ids, counts — never values.
- Constant-time comparisons (`hmac.compare_digest`) wherever HMACs are compared.

### Known Risks / Gotchas
- **Coordinated breaking release** — old code cannot read v2 and new code rejects v1. Mitigation:
  single maintenance window, backups, rehearsal (Module 14), rollback = restore + redeploy.
- **Naming key removal** — if the naming key id (lowest id or `VAULT_NAMING_KEY_ID`) is removed
  from the ring, Redis names change and live caches are orphaned; `SessionVault.get()` has no DB
  fallback. Mitigation: `VaultConfig` refuses to start if the naming key id is missing; runbook
  says removing it requires `purge-redis`.
- **`provider_user_id` nullable / re-link** in `auth.user_identities` — context must encode
  `NULL` distinctly and upserts must re-seal all token fields in the same transaction.
- **DocumentDB renames** (`name` in `user_credentials`, `provider` in `user_llm_keys`) — any
  rename path must re-seal; audit call sites in `credentials.py` update handlers.
- **`_encrypted_field` v1 envelopes** — the migrator must verify the embedded `_ctx` before
  trusting it, otherwise an already-swapped v1 blob would be legitimized as v2.
- **Soft-deleted vault rows** are migrated like active rows (keeps restore possible and avoids
  leaving v1 data at rest).
- **Deterministic persistent sessions** (`telegram-persistent:`, `cli-persistent:`) keep
  working because derivation is deterministic in `(master key, session_uuid)`; their Redis
  entries are also removed by `purge-redis` and repopulate from DB on next load.
- **Format byte collision** — a v1 blob whose key id high byte is `0xA2` (key id ≥ 41472) would
  parse as v2 header; impossible in practice (ids are small) and still fails authentication.
- **Backup directory is sensitive** — it holds v1 ciphertext (not plaintext) that remains
  decryptable with the current master keys. Mitigation: CLI creates files `0600` in a `0700`
  directory, refuses world-readable targets, runbook requires secure storage and deletion after
  the rollback period.
- **Backup vs concurrent writers** — exports are only consistent because all services are
  stopped (runbook step 1); the CLI warns if it detects vault writes (audit rows newer than the
  export start) during the run.
- **ai-parrot FEAT-266/267** (`vault_token_sync.py`) are done and merged into ai-parrot `dev`
  (verified 2026-09-15); Module 10 builds on that code, which still exhibits F4.
- **Frontend redirect storms** — many parallel requests may get 401 simultaneously; the
  redirect must be guarded (single flight).

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| `cryptography` | `>=41.0` (existing) | `AESGCM`, `ChaCha20Poly1305`, `HKDF`, HMAC |
| `orjson` | existing | Value serialization |
| `pydantic` | `>=2` (existing) | Context, header, report models |
| `redis` (asyncio) | existing | Session cache + `purge-redis` via `SCAN` |
| `asyncpg` | existing | PostgreSQL targets, migrator |
| `navigator-session` | `>=1.0.0` | Required by navigator-auth and ai-parrot after this feature |
| `asyncdb` / `DocumentDb` (ai-parrot) | existing | DocumentDB targets (ai-parrot only) |

---

## 7. Open Questions

Resolved while writing this spec (from brainstorm Open Questions):

- [x] Naming key stability → lowest key id in the ring, overridable with `VAULT_NAMING_KEY_ID`;
      startup fails if it is missing (§2 Key schedule, §6).
- [x] Soft-deleted rows → migrated like active rows (§6).
- [x] `VaultTokenSync` `:` keys → confirmed bug F4; fixed by allowing `:` once Redis names are
      HMAC'd (Module 4, Module 10).
- [x] Session key granularity → per `(key_id, alg_id, session_uuid)` HKDF, cached per vault
      instance (§2).
- [x] ai-parrot inventory → `user_credentials`, `user_llm_keys` (DocumentDB), `users_bots`
      (PostgreSQL) (§1 inventory).
- [x] SDD tracking → this spec and all tasks live in navigator-auth.

Resolved in spec review (2026-09-15):

- [x] Quarantine semantics → PostgreSQL: soft-delete + audit; DocumentDB: move to
      `<collection>_quarantine` with metadata (§2 Quarantine semantics).
- [x] Frontend placement → dedicated route `/profile/secrets`, linked from `/profile`
      ("Manage secrets") and reachable by direct URL (Module 12).
- [x] Forced re-login notice → *"Your session has ended because of a security update. Please
      sign in again."* (Module 13).
- [x] `POST /api/v1/user/vault` → `201 {key, updated_at, key_version, message}`, a superset of
      the current body (§2 HTTP contract).
- [x] ai-parrot FEAT-266/267 → done and merged into ai-parrot `dev`; not blocking (§6).
- [x] Backups → the CLI performs a mandatory raw export (`--backup-dir`) and provides
      `restore`; independent of ops tooling (§2 Runbook).
- [x] Maintenance window → scheduled by ops, out of scope; duration measured in the Module 14
      rehearsal.

No open questions remain.

---

## Worktree Strategy

- **Default isolation unit:** `mixed` — per-repo worktrees; sequential inside the core,
  parallel across downstream repos.
- **Worktree naming:** in each repo that a task touches,
  `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening` on branch
  `feat-FEAT-099-vault-crypto-hardening` (from `dev` or the repo's integration branch). SDD state
  (`sdd/tasks/.index.json`) is updated only in navigator-auth.
- **Sequential (navigator-session worktree):** M1 → M2 → M3 → {M4, M5, M6}. M4/M5/M6 touch
  different files and may run in parallel after M3, but share `pyproject.toml` / `__init__.py`
  hunks — keep them sequential unless run by separate workers that rebase.
- **Parallel after M2 + M3 are merged (API frozen):**
  - navigator-auth worktree: M7 → M8 (M8 also needs M4).
  - ai-parrot worktree: M9 → M11 (needs M6 for `legacy_unwrap`) → M10 (needs M4).
- **Parallel from the start (contract-first):** navigator-frontend-next worktree: M12, M13
  against the §2 HTTP contracts with mocked clients.
- **Last, sequential:** M14 (needs everything; runs the cross-repo rehearsal).
- **Cross-feature dependencies:** none blocking. navigator-auth FEAT-092…098 are done and
  merged into `dev`; ai-parrot FEAT-266/267 are done and merged into ai-parrot `dev`. The package
  dependency `navigator-auth → navigator-session>=1.0.0` requires the NS worktree to be
  installed editable (`[tool.uv.sources] navigator-session = { path = "../navigator-session" }`
  already present in navigator-auth) while developing.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-09-15 | Jesus Lara | Initial draft from `vault-crypto-hardening.brainstorm.md` (Option A) |
| 0.2 | 2026-09-15 | Jesus Lara | Resolved all open questions: quarantine per engine, CLI backup/restore, `/profile/secrets` route + link, re-login notice, POST metadata body, FEAT-266/267 merged, window owned by ops |
