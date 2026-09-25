
User Vault
==========

navigator-auth stores per-user secrets (``auth.user_vault_secrets``) and linked
identity tokens (``auth.user_identities``) encrypted with the vault
implemented in **navigator-session** (``navigator_session.vault``). This page
covers what is specific to navigator-auth; the format and the operational
procedures live with the implementation.

Reference documents (navigator-session >= 1.0.0):

* ``docs/vault/format.md`` — envelope v2 layout, the AEAD associated data, and
  the HKDF key schedule.
* ``docs/vault/targets.md`` — how to register a protected store so that
  ``navigator-vault`` can migrate, verify and rotate it.
* ``docs/vault/migration-runbook.md`` — the v1 → v2 migration, step by step.

Configuration
-------------

The vault reads its environment directly (see ``format.md`` for the full list):

==============================  ==========================================
``VAULT_MASTER_KEY_v{N}``       Master key for version *N*, 32 bytes, base64
``VAULT_ACTIVE_KEY_ID``         Version used for new ciphertext
``VAULT_CIPHER_BACKEND``        ``aesgcm`` (default) or ``chacha20``
``VAULT_NAMING_KEY_ID``         Version used to derive Redis key names
==============================  ==========================================

``setup_vault_keyring(app)`` builds the key ring at startup and stores it on the
aiohttp application, so handlers and the identity store share one ring.

Protected stores
----------------

navigator-auth registers its stores through the
``navigator_session.vault_targets`` entry-point group
(``navigator_auth.identity.targets:factory``), which is what makes them visible
to ``navigator-vault list-targets``.

Schema migrations
-----------------

* ``navigator_auth/vault/sql/002_vault_crypto_hardening.sql``
* ``navigator_auth/identity/sql/003_identity_key_version_integer.sql``

Both are applied automatically at startup and are safe to re-run.

HTTP contract
-------------

``GET /api/v1/user/vault/{key}`` returns **metadata only** — never the secret
value. Secrets are write-only over the API; a client that needs the value uses
the server-side helpers instead.
