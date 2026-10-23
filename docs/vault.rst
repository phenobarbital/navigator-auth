
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

External provider credential capture (FEAT-103)
-----------------------------------------------

``AzureAuth`` (and, through the generic ``ExternalAuth`` mechanism, any backend
that opts in) keeps the credential it negotiates at login instead of discarding
it. The pieces are routed by sensitivity:

* The provider **refresh token** (and the ``id_token`` / access token) is
  ciphered into ``auth.user_identities`` through
  ``IdentityStore.save_linked_identity``. The provider's refresh token is
  **never** placed in the session and **never** returned in an HTTP response.
* The session receives only non-secret companions next to the existing
  ``auth_method`` / ``auth_token``:

  ====================================  ====================================================
  ``id_token``                          Provider OIDC ``id_token``.
  ``external_expires_at``               ISO-8601 expiry of the provider access token.
  ``external_issued_at``                ISO-8601 ``iat`` of the provider access token, when
                                        it is a JWT. Present only when knowable.
  ``has_refresh_token``                 Boolean marker — a refresh token is vaulted. Never
                                        the token itself.
  ``external_provider_user_id``         Verified external account the login is bound to.
  ====================================  ====================================================

.. warning::

   ``session["refresh_token"]`` / the ``refresh_token`` field of a login
   response is **Navigator's own** refresh token (indexed in Redis as
   ``auth:refresh_token:<tok>`` for 90 days). It is a different credential that
   merely shares a name with the provider's. The provider's refresh token is
   never in the session.

Getting a live provider token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An Entra access token for Microsoft Graph lived 419 seconds (7 minutes) in a
measured session, while a Navigator session lasts ``SESSION_TIMEOUT`` (100 hours
by default): the session can outlive the provider token by roughly 850x. A
consumer that reads ``session["auth_token"]`` directly therefore gets a dead
token for almost the whole session. Call
``ExternalAuth.get_live_provider_token(request, user_id)`` instead:

* It is **on demand** — there is deliberately no middleware refreshing on
  every request.
* It checks the session's local user, ``auth_method`` and
  ``external_provider_user_id``, reads the exact vaulted credential for that
  account, and refreshes it (persisting the rotated credential and updating
  ``session["auth_token"]`` / ``external_expires_at``) when it expires within
  ``IDENTITY_REFRESH_LEEWAY`` seconds.
* It **never falls back to another linked account**: a session bound to
  account A is never served account B's credential.
* It returns ``None`` when the binding is missing or mismatched (a session from
  before this feature requires a re-login), no credential is stored, or a
  required refresh cannot complete. For Azure the refresh requests the stored
  grant's own scopes; a refresh that explicitly drops granted permissions is not
  published.
* The ``check_credentials`` JSON response masks ``auth_token`` and ``id_token``.

A login is not always a newly issued token
-----------------------------------------

Logging out of Navigator ends the **Navigator** session only; the provider's
own SSO session survives. The next authorization-code round-trip is therefore
silent at the IdP, and Entra answers it with the access token it already holds
for that session — same ``iat``, same ``exp``, with ``expires_in`` reporting
only the **remaining** lifetime. A brand-new session could start out holding a
credential seconds from expiry (``issue:3fd80396c685``).

Two consequences to keep in mind:

* ``expires_in`` from a provider is time left, **not** the token's issued
  lifetime. Only ``exp - iat`` is the lifetime.
* Backends run the captured grant through
  ``ExternalAuth.ensure_fresh_login_grant`` before publishing it, which applies
  the same ``IDENTITY_REFRESH_LEEWAY`` check ``get_live_provider_token`` uses
  later and refreshes an already-aged grant first. It never fails a login: when
  the refresh is impossible, the provider's credential is published as received
  and the warning says so.

``external_issued_at`` makes the reuse visible without decoding the token.
Where a genuinely newly-issued credential is required — or to measure token
lifetime across logins — set ``AZURE_LOGIN_PROMPT=login`` so Entra
re-authenticates instead of serving its cache; it is off by default because it
costs a credential prompt on every login.

Azure settings: see ``AZURE_FLOW_TTL``, ``AZURE_SESSION_TIMEOUT`` and
``AZURE_LOGIN_PROMPT`` in :doc:`settings`.
