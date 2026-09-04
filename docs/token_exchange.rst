Token Exchange
================

``TokenExchangeAuth`` lets a client that already holds a valid bearer token
from Azure, Google or GitHub (a mobile app, a desktop tool, a partner
front-end that ran the provider login itself) exchange it for a Navigator
session **without** replaying the browser redirect flow.

The exchanged session is opened through the exact same code path as a
Basic login: user mapping, ``BasicUser`` identity, ``remember()``, the
internal JWT + refresh token, Basic success callbacks and ``last_login``
update. The only differences are how the user is authenticated and that the
session lifetime is capped at the external token's own lifetime.

Request
-------

.. code-block:: text

   POST /api/v1/login
   X-Auth-Method: TokenExchangeAuth
   Content-Type: application/json

   {
     "provider": "azure",
     "token": "<provider access token>",
     "token_type": "Bearer",
     "id_token": "<provider id_token, optional depending on provider>"
   }

- ``provider`` — one of the values configured in ``TOKEN_EXCHANGE_PROVIDERS``
  (default ``azure``, ``google``, ``github``); it must also be a loaded,
  configured backend.
- ``token`` — the provider's access token. For Google, a JWT-shaped ``token``
  with no separate ``id_token`` is treated as an id_token-only exchange.
- ``id_token`` — optional. Azure and Google use it (when present) for a
  fully signature-verified audience check; GitHub ignores it (it has none).

Response
--------

On success the response body is **identical in shape** to a Basic login,
plus two additional fields:

.. code-block:: json

   {
     "token": "<internal JWT>",
     "username": "user@example.com",
     "auth_method": "basic",
     "auth_origin": "azure",
     "external_expires_at": "2026-09-04T18:00:00+00:00",
     "...": "the usual Basic login fields (refresh_token, expires_in, ...)"
   }

Both the top-level response/session and the ``AUTH_SESSION_OBJECT`` carry
``auth_method: "basic"`` and ``auth_origin: "<provider>"``; the internal JWT
mirrors ``auth_method``, ``auth_origin`` and ``external_expires_at`` as
claims.

Errors:

- ``400`` — malformed payload (missing ``provider``/``token``), an
  unsupported provider, or a provider that isn't a loaded backend.
- ``401`` — the token is invalid, expired, minted for a different
  application, the account's e-mail isn't verified, or no matching
  ``auth.users`` row exists. The response body never reveals which of these
  occurred beyond a generic "Invalid Credentials" — the specific reason is
  only logged server-side.

Audience-bound verification
----------------------------

Every provider verifies that the token was minted **for this deployment**,
not just that it is a live token:

- **Azure** — prefers the ``id_token`` (JWKS-verified signature, ``aud`` ==
  ``AZURE_ADFS_CLIENT_ID``, ``iss`` matches the configured tenant). Without
  an ``id_token``, the access token must still carry ``aud`` in
  ``{AZURE_ADFS_CLIENT_ID, "https://graph.microsoft.com",
  "00000003-0000-0000-c000-000000000000"}`` **and** ``appid``/``azp`` equal
  to ``AZURE_ADFS_CLIENT_ID``. This access-token-only path is weaker (Graph
  tokens are not meant for third-party signature validation), so a
  signature-verification failure is tolerated once ``appid``/``aud`` match
  and the subsequent Graph ``/me`` call succeeds.
- **Google** — the ``id_token`` (or a JWT-shaped ``token``) is verified
  against Google's published JWKS, requiring ``aud == GOOGLE_CLIENT_ID`` and
  a verified e-mail. An opaque access token is checked via Google's
  ``tokeninfo`` endpoint, requiring ``aud`` or ``azp == GOOGLE_CLIENT_ID``.
- **GitHub** — the token is checked against GitHub's "check a token" REST
  endpoint, authenticated with *this application's own* client
  credentials — this both validates the token and confirms it belongs to
  this OAuth app. Only a verified primary e-mail is accepted.

User resolution — never auto-provisioned
-----------------------------------------

The exchanged token must map to an **existing** ``auth.users`` row:

1. The stable ``(provider, provider_user_id)`` link, if a previous exchange
   or identity-link flow already recorded one, wins.
2. Otherwise the provider's verified e-mail is looked up directly.
3. If neither resolves a user, the exchange fails with ``401`` — a new user
   is **never** created, regardless of the ``AUTH_MISSING_ACCOUNT`` setting.

Session lifetime cap
---------------------

The internal JWT and session never outlive the external token:

- When the provider reports an expiry, the cap is
  ``min(SESSION_TIMEOUT, external_token_expires_at - now)``.
- When it doesn't (e.g. a classic GitHub OAuth token, which never expires),
  the cap falls back to ``TOKEN_EXCHANGE_MAX_TTL`` (defaults to
  ``SESSION_TIMEOUT``).
- If the resulting cap is under 60 seconds, the exchange fails with ``401``
  (the external token is treated as effectively expired).
- The Redis session TTL and the session cookie's ``Max-Age`` are aligned
  with this same cap, not the platform's default session timeout.

Credential storage
-------------------

The verified provider credential (access token, refresh token when present,
and ``id_token``) is written to the **Identity Vault**
(``auth.user_identities``), ciphered with the same Session Vault master
keys used elsewhere — never to the Redis session. A vault write failure is
logged but never fails the login.

Retrieve it through the existing Identity Vault credential endpoint:

.. code-block:: text

   GET /api/v1/user/identities/{provider}/credential

A re-exchange that doesn't carry a new refresh token keeps the previously
vaulted one instead of clobbering it with ``null``.

Configuration
-------------

See :doc:`settings` for ``TOKEN_EXCHANGE_MAX_TTL`` and
``TOKEN_EXCHANGE_PROVIDERS``.
