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
