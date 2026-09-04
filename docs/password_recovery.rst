Backend-Based Password Recovery
=================================

A three-step, HMAC-signed self-service password recovery flow that splits
*"you proved you opened the mailbox"* (stage 1) from *"you are authorized to
write a password"* (stage 2). It replaces the non-functional draft that used
to live in ``handlers/recovery.py``.

**navigator-auth never sends e-mail.** Step 1 hands a mail-ready payload to
a configured callback and the HTTP response never carries the token.

Endpoints
---------

.. list-table::
   :header-rows: 1

   * - Verb
     - Path
     - Purpose
   * - ``POST``
     - ``/api/v1/password-recovery``
     - Step 1 — request a recovery link
   * - ``GET``
     - ``/api/v1/password-recovery/{token}``
     - Step 2 — validate the link, mint a confirmation token
   * - ``POST``
     - ``/api/v1/password-recovery/confirm``
     - Step 3 — set the new password

Legacy aliases (compatibility, same handler): ``POST /api/v1/forgot-password``
→ step 1, ``POST /api/v1/reset-password`` → step 3.

Step 1 — request
^^^^^^^^^^^^^^^^^

.. code-block:: text

   POST /api/v1/password-recovery
   Content-Type: application/json

   {"email": "user@example.com"}

Always responds ``200`` with the **same** body, whether or not the address
is registered, whether the request was rate-limited, or whether the
notification callback raised:

.. code-block:: json

   {"message": "If that email address is registered, recovery instructions have been sent."}

The token is never present in this response, in any Redis value (Redis is
keyed by ``sha256(token)``), or in a log line at any level. See
`Enumeration resistance`_.

Step 2 — validate
^^^^^^^^^^^^^^^^^^

.. code-block:: text

   GET /api/v1/password-recovery/{token}

``200`` on success:

.. code-block:: json

   {"token": "<confirmation token>", "expires_in": 900, "username": "user"}

``400`` — the recovery link is missing, expired, or its signature does not
verify (a single generic message; the reasons are not distinguished for the
caller). Calling this endpoint repeatedly with the same recovery token is
safe: each call rotates a fresh confirmation token, but the stage-1 token
itself is **not** consumed, so refreshing the page or a mail-scanner
prefetch never burns the reset.

Step 3 — confirm
^^^^^^^^^^^^^^^^^

.. code-block:: text

   POST /api/v1/password-recovery/confirm
   Content-Type: application/json

   {"password": "...", "confirm_password": "...", "token": "<confirmation token>"}

``202`` on success:

.. code-block:: json

   {"action": "Password was changed successfully", "status": "OK"}

The response never carries a session token or refresh token — there is no
auto-login after a self-service reset.

Errors:

- ``400`` — passwords don't match, the confirmation token is missing,
  invalid, expired, or already used.
- ``422`` — the new password fails the configured policy:

  .. code-block:: json

     {"violations": [{"rule": "min_length", "message": "..."}]}

  A ``422`` does **not** consume either token — the caller can retry
  immediately with a stronger password using the same confirmation token.

A successful step 3:

- Hashes and writes the new password (the same hasher Basic login uses).
- Sets ``is_new = False`` (self-service reset — **not** the same as a
  superuser-driven reset, which sets ``is_new = True``).
- Deletes both the stage-1 and stage-2 Redis records, so neither can be
  replayed.
- Revokes the user's live Redis session and every outstanding JWT ``jti`` —
  a token issued before the reset stops authenticating.

Enumeration resistance
-----------------------

Known and unknown addresses are indistinguishable by status, body, **and**
latency: a real address triggers a database lookup and a Redis write; an
unknown one may not, so elapsed time alone could otherwise reveal whether
an account exists. Step 1 measures its own elapsed time and pads to a fixed
floor (~250ms) before responding, on both paths.

Rate-limit rejection also returns the identical generic ``200`` body rather
than a distinct status — a ``429`` would itself tell an attacker the
address or IP is being tracked.

The callback contract
-----------------------

navigator-auth never sends e-mail. Configure ``AUTH_RECOVERY_CALLBACK`` with
the dotted path to a sync or async callable that accepts one positional
argument, a ``NotificationPayload``:

.. code-block:: python

   @dataclass(frozen=True)
   class NotificationPayload:
       email: str            # the address the caller requested recovery for
       display_name: str     # empty string when found=False
       username: str         # empty string when found=False
       token: str            # raw stage-1 token — never appears anywhere else
       url: str               # AUTH_RECOVERY_URL_TEMPLATE.format(token=token)
       expires_at: datetime
       found: bool            # False => no matching account

- ``found=False`` means no account matched the requested address (or the
  match was ambiguous — see below); the callback decides whether to send
  anything (e.g. a "no account" notice) or stay silent. ``token``/``url``
  are empty strings in this case — there is no real token to send.
- A raising callback is caught, logged, and **never** changes the HTTP
  response — the caller still receives the generic ``200``.
- If ``AUTH_RECOVERY_URL_TEMPLATE`` is unset (or malformed), the error is
  logged and ``url`` is an empty string; the response is unaffected.
- ``NotificationPayload.__repr__`` redacts ``token``/``url`` — do not rely
  on a raw ``print()``/``repr()`` for debugging; log the other fields
  instead.

E-mail lookup matches ``email`` first, then falls back to ``alt_email``.
``User.email`` has no unique constraint: if more than one active user
matches, the lookup refuses to guess — it logs a warning and takes the
``found=False`` path, exactly as for an unknown address.

Every **active** user may recover, including federated-only accounts with
no local password.

Migrating from ``FORGOT_PASSWORD_CALLBACK``
----------------------------------------------

``FORGOT_PASSWORD_CALLBACK`` (the old ``handlers/recovery.py`` setting) is
deprecated for one release. When set and ``AUTH_RECOVERY_CALLBACK`` is not,
it is used as a fallback and a ``DeprecationWarning`` is emitted. The new
callback's payload (``NotificationPayload``) is richer than the old
``(request, user, token)`` positional call — update the callback signature
when you migrate.

Configuration
-------------

See :doc:`settings` for every ``AUTH_RECOVERY_*`` key and its default.
