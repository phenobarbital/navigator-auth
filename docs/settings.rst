Settings
=========

Token Exchange (FEAT-096)
--------------------------

Settings for the ``TokenExchangeAuth`` backend (see :doc:`token_exchange`).

``TOKEN_EXCHANGE_MAX_TTL``
   Integer, seconds. Fallback session/JWT lifetime used when the external
   provider token reports no expiry (e.g. classic GitHub OAuth tokens).
   Defaults to the same value as the platform's ``SESSION_TIMEOUT``.

``TOKEN_EXCHANGE_PROVIDERS``
   Comma-separated list of provider slugs eligible for token exchange.
   Defaults to ``azure,google,github``. Each entry must also correspond to
   a loaded, configured authentication backend (matched by its
   ``_service_name``) or exchange requests for it are rejected with
   ``400``.

SAML 2.0 (FEAT-097)
---------------------

Settings for the abstract SAML SP/IdP roles (see :doc:`../documentation/saml`).
Every key below is resolved under a subclass's own ``config_prefix`` first
(default ``SAML`` for the SP role, ``SAML_IDP`` for the IdP role), falling
back to the ``SAML_*`` name shown.

**Shared (both roles)**

``SAML_XMLSEC_BINARY``
   Path to the ``xmlsec1`` binary. Auto-detected via ``PATH`` when unset;
   startup fails fast with a clear message if neither resolves.

``SAML_CLOCK_SKEW``
   Integer, seconds. Tolerance on assertion/response time conditions.
   Default ``60``.

``SAML_FLOW_TTL``
   Integer, seconds. Redis TTL for request/logout/pending-SSO flow
   records. Default ``600``.

``SAML_EXECUTOR_WORKERS``
   Integer. Size of the bounded executor every blocking ``pysaml2``/
   ``xmlsec1`` call runs through. Default ``4``.

**SP role** (``SAMLAuth``)

``SAML_METADATA``
   Path or URL to the IdP's metadata XML. No default; see
   :doc:`../documentation/saml` for the ``SAML_PATH`` fallback chain.

``SAML_PATH``
   Legacy cert/settings directory (kept for the ``python3-saml``
   migration fallback and for ``SAML_SP_KEY_FILE``/``SAML_SP_CERT_FILE``
   discovery conventions).

``SAML_SETTINGS``
   Optional JSON. Legacy ``python3-saml`` settings, translated via
   ``translate_legacy_settings``; unknown keys fail startup naming them.

``SAML_MAPPING``
   SAML attribute → user field mapping (existing key, unchanged shape).

``SAML_SP_KEY_FILE`` / ``SAML_SP_CERT_FILE``
   Optional SP key pair (``AuthnRequest`` signing, assertion decryption).

``SAML_BINDING``
   ``redirect`` (default) or ``post``. ``AuthnRequest`` binding.

``SAML_ALLOW_UNSOLICITED``
   Boolean. Accept IdP-initiated (unsolicited) responses. Default
   ``true``.

``SAML_WANT_ASSERTIONS_SIGNED`` / ``SAML_WANT_RESPONSE_SIGNED``
   Boolean. Signature requirements on the inbound assertion/response.
   Defaults ``true`` / ``false``.

``SAML_METADATA_RELOAD``
   Integer, seconds. IdP metadata reload interval; ``0`` disables.
   Default ``3600``.

**IdP role** (``SAMLIdentityProvider``)

``SAML_IDP_KEY_FILE`` / ``SAML_IDP_CERT_FILE`` / ``SAML_IDP_KEY_PASSPHRASE``
   Signing key pair. Required for the IdP role; startup fails without
   both file paths.

``SAML_IDP_ENTITY_ID``
   Override the IdP's own entity ID. Default
   ``{domain}/auth/saml-idp/metadata``.

``SAML_IDP_SERVICE_PROVIDERS``
   JSON list of registered SP entries (``sp_id``, ``entity_id``,
   ``acs_url``, and the other ``ServiceProviderConfig`` fields). Default
   ``[]``.

``SAML_IDP_SETTINGS``
   Optional JSON ``pysaml2`` overrides for the IdP role.

``SAML_IDP_REQUIRE_AUTH_METHODS``
   JSON list. If set, only sessions whose ``auth_method`` is listed may
   receive assertions. Default ``[]`` (no restriction).

Backend-Based Password Recovery (FEAT-098)
--------------------------------------------

Settings for the three-step recovery flow (see :doc:`password_recovery`).

``AUTH_RECOVERY_SECRET``
   HMAC key used to sign both the stage-1 (recovery) and stage-2
   (confirmation) tokens. Falls back to ``SECRET_KEY`` (``AUTH_SECRET_KEY``)
   when unset.

``AUTH_RECOVERY_TTL``
   Integer, seconds. Stage-1 (recovery token) lifetime. Default ``3600``
   (1 hour).

``AUTH_RECOVERY_CONFIRM_TTL``
   Integer, seconds. Stage-2 (confirmation token) lifetime. Default ``900``
   (15 minutes).

``AUTH_RECOVERY_CALLBACK``
   Dotted path to the notification callable (sync or async). No default —
   without it, step 1 logs a warning and no notification is sent (the HTTP
   response is unaffected). See the callback contract in
   :doc:`password_recovery`.

``AUTH_RECOVERY_URL_TEMPLATE``
   URL template the recovery link is built from, e.g.
   ``https://app.example/reset?token={token}``. No default — without it,
   step 1 logs an error and ``NotificationPayload.url`` is an empty string;
   the response is unaffected.

``AUTH_RECOVERY_RATE_EMAIL``
   ``"<count>/<window>"``. Per-address limit on step 1. Default ``"3/hour"``.

``AUTH_RECOVERY_RATE_IP``
   ``"<count>/<window>"``. Per-IP limit on step 1. Default ``"10/hour"``.

``AUTH_RECOVERY_PWD_MIN_LENGTH``
   Integer. Minimum length enforced at step 3. Default ``8``.

``AUTH_RECOVERY_PWD_REQUIRE_LETTER``
   Boolean. Require at least one letter. Default ``True``.

``AUTH_RECOVERY_PWD_REQUIRE_DIGIT``
   Boolean. Require at least one digit. Default ``True``.

``FORGOT_PASSWORD_CALLBACK``
   **Deprecated.** The legacy callback setting from the pre-FEAT-098
   ``handlers/recovery.py``. Honoured for one release — used as a fallback
   when ``AUTH_RECOVERY_CALLBACK`` is unset, with a ``DeprecationWarning``.
   See the migration note in :doc:`password_recovery`.
