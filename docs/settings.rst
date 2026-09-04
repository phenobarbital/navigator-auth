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
