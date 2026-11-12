Two-factor authentication for BasicAuth
=======================================

FEAT-106 adds a second factor to ``BasicAuth`` (username + password): **TOTP**
(Google-Authenticator-compatible) and **e-mail one-time codes**, enforced per
tenant. No new runtime dependency is needed: TOTP comes from ``cryptography``.

.. contents::
   :local:
   :depth: 2

How it works
------------

The second-factor decision runs inside ``BasicAuth.authenticate()``. A provider
only verifies a factor; it cannot create a session itself. When a password login
owes a factor, login returns a ``401`` challenge envelope and no session or token.
``TokenExchangeAuth`` is never challenged. A passkey sign-in satisfies tenant
enforcement without an OTP; external-IdP enforcement is out of scope because the
identity provider owns that policy.

The global switch is ``AUTH_BASIC_2FA_ENABLED``. At its default ``False`` value,
the BasicAuth login path is unchanged. When enabled, missing MFA tables, Redis or
Postgres failures, or an unset ``AUTH_OTP_SECRET`` make every BasicAuth login fail
closed with ``mfa_unavailable``. Startup still succeeds, and availability heals
without a restart: the first MFA decision after ``AUTH_MFA_RETRY_INTERVAL`` seconds
rebuilds the services (one rebuild at a time). A missing ``AUTH_OTP_SECRET`` or
``authdb`` pool is a permanent misconfiguration and is never retried.

Settings
--------

======================================== ================== ===============================================
Setting                                  Default            Meaning
======================================== ================== ===============================================
``AUTH_BASIC_2FA_ENABLED``               ``False``          Global BasicAuth MFA kill switch.
``AUTH_OTP_SECRET``                      unset              Required HMAC key when enabled; no ``SECRET_KEY`` fallback.
``AUTH_OTP_CHALLENGE_TTL``               ``300``            Challenge lifetime in seconds.
``AUTH_OTP_MAX_ATTEMPTS``                ``5``              Attempts per challenge; the fifth failed attempt burns it.
``AUTH_OTP_CODE_LENGTH``                 ``6``              Number of digits in an e-mail OTP.
``AUTH_OTP_RATE_USER``                   ``10/hour``        Strict user limiter; a Redis error fails closed.
``AUTH_OTP_RATE_IP``                     ``30/hour``        Strict IP limiter; a Redis error fails closed.
``AUTH_OTP_EMAIL_CALLBACK``              unset              Dotted callback path receiving ``OtpNotificationPayload``.
``AUTH_TOTP_ISSUER``                     ``Navigator``      Issuer label displayed by authenticator applications.
``AUTH_MFA_BACKUP_CODE_COUNT``           ``10``             Backup codes issued per set.
``AUTH_MFA_BACKUP_CODE_LENGTH``          ``8``              Characters in each backup code.
``AUTH_MFA_NOTIFY_CALLBACK``             unset              Dotted callback path receiving ``MfaSecurityNotice``.
``AUTH_MFA_RETRY_INTERVAL``              ``15``             Seconds between rebuilds of unavailable MFA services.
``AUTH_MFA_LOCK_TIMEOUT``                ``5.0``            Seconds to wait for the per-user lock; a timeout is ``mfa_unavailable``.
======================================== ================== ===============================================

Unlike password recovery, both OTP rate limiters refuse the request if Redis is
unavailable. Set a high-entropy ``AUTH_OTP_SECRET`` before enabling MFA; it is the
key for challenge and OTP integrity and is deliberately not derived from another
application secret.

Login flow and responses
------------------------

For a password login that needs a factor, ``POST /api/v1/login`` responds:

.. code-block:: json

   {
     "mfa_required": true,
     "challenge": "<opaque challenge>",
     "providers": ["email"],
     "preferred": "email",
     "expires_in": 300
   }

Submit the factor to ``POST /auth/mfa/verify`` using ``challenge``, ``provider``,
``code``, and optionally ``remember_device`` (and ``device_label``):

.. code-block:: text

   POST /api/v1/login
   Content-Type: application/json

   {"username": "user", "password": "password"}

   POST /auth/mfa/verify
   Content-Type: application/json

   {"challenge": "<opaque challenge>", "provider": "email", "code": "123456"}

``strong_factor_required`` and ``no_factor_available`` are ``403`` refusals;
``mfa_unavailable`` is a ``503`` refusal. Refusals use
``{"error": "<code>", "message": "..."}``. Successful MFA sessions have
``mfa=True`` and AMR values ``pwd`` plus ``otp`` (e-mail), ``totp``, or
``backup``. A trusted-device login uses ``["pwd", "trusted_device"]``. ABAC can
require a fresh factor by inspecting ``amr`` and rejecting ``trusted_device``.

OAuth2 login form
-----------------

The same ``SecondFactorGate`` that guards BasicAuth also guards ``POST /oauth2/login``.
When a factor is owed, the server renders ``oauth/mfa.html`` with
``Cache-Control: no-store`` and sets no session cookie. The user submits the factor to
``POST /oauth2/login/mfa`` (route ``nav_oauth2_login_mfa``), which verifies it and
redirects to ``/oauth2/authorize`` preserving PKCE, ``state``, ``nonce``, ``scope`` and
``prompt``. The trusted-device cookie works on this form too. When 2FA is on and
BasicAuth's MFA slot is missing or unavailable, the OAuth2 login answers ``503`` and
creates no session; when 2FA is off, the login is unchanged.

OAuth2 tokens and ABAC
----------------------

An access token minted after an MFA-verified OAuth2 login carries ``mfa`` and ``amr``.
A ``refresh`` rotation copies both from the parent token, token introspection
(``introspect``) echoes ``amr`` and ``mfa``, and ``userinfo`` echoes ``amr``. A token
minted without a factor carries no such claim. For bearer requests, ABAC reads
assurance from the validated presented token and never from the shared session, so a
password-only token cannot borrow the assurance of another session of the same user.

OAuth credential invalidation uses a per-user generation stored in
``oauth_user_generation``. A password reset or recovery completion advances it; older
authorization codes, device carriers, access tokens and refresh tokens then fail
everywhere. If the generation cannot be read, the request fails closed.

E-mail delivery callback
------------------------

navigator-auth never sends e-mail. Configure ``AUTH_OTP_EMAIL_CALLBACK`` with a
dotted path to a sync or async callable accepting ``OtpNotificationPayload``:

.. code-block:: python

   OtpNotificationPayload(
       email="user@example.com",
       display_name="Example User",
       username="user",
       code="123456",
       expires_at=<datetime>,
       found=True,
   )

The code is the only location where a live e-mail code exists. Never log it or
call ``model_dump()`` on this payload; its repr redacts the code. Callback errors
are contained and logged at WARNING, and the HTTP response remains identical so
delivery cannot become an enumeration oracle. Operationally, a broken callback
means e-mail-state users in an enforced tenant cannot complete their login.

Security notifications (``AUTH_MFA_NOTIFY_CALLBACK``)
------------------------------------------------------

``AUTH_MFA_NOTIFY_CALLBACK`` is an optional dotted callback path. Its sync or
async callable receives ``MfaSecurityNotice`` with ``email``, ``display_name``,
``username``, ``event``, ``occurred_at``, and ``actor`` after a TOTP disenrolment,
an administrator disenrolment, or removal of a user's last passkey. When unset,
the event is logged at INFO. Callback failures are contained and logged at WARNING.

Per-user state: none → email → totp
-----------------------------------

===================================== ================= =======================================
Policy and factor state               Result            Notes
===================================== ================= =======================================
OFF or OPTIONAL, not enrolled         ``none``          No BasicAuth challenge.
ENFORCED, no strong factor             ``email``         A usable e-mail address is the floor; no enrolment is needed.
Confirmed TOTP                         ``totp``          TOTP is offered instead of e-mail.
===================================== ================= =======================================

A confirmed TOTP or any registered passkey is a strong factor and closes the
e-mail path. Deleting an ordinary user's last passkey without TOTP reopens the
e-mail state, writes an audit event, revokes trusted devices, and sends a security
notice. Backup codes are ten 8-character codes, shown once on initial TOTP
confirmation, consumed once each, and regenerated only with password
re-authentication **and** fresh proof of a strong factor (a current TOTP code, an
unused backup code, or a fresh passkey session); without the proof
``POST /auth/mfa/backup-codes`` answers ``403`` ``strong_factor_proof_required``. A user who has no usable factor (for example no usable address,
or a passkey-only user without backup codes) receives ``no_factor_available``;
passkey holders should sign in with their passkey.

Enrolling and replacing TOTP
----------------------------

``POST /auth/mfa/totp/enroll`` requires a current session and a fresh password.
Replacing an existing strong factor additionally requires a current TOTP code, an
unused backup code, or a passkey-sign-in session younger than
``AUTH_OTP_CHALLENGE_TTL``. An e-mail code and a trusted-device cookie never prove
replacement. The pending seed lasts five minutes and is bound to the user, session,
and security version; it does not replace the active seed until confirmation.

``POST /auth/mfa/totp/confirm`` consumes the pending enrollment once, marks its
TOTP step used, revokes trusted devices, and invalidates outstanding challenges.
It returns the initial backup-code set only once. Render the ``otpauth://`` URI as
a QR code in the client; navigator-auth does not depend on ``pyotp`` or ``qrcode``.

Per-tenant policy
-----------------

Policy is data in ``auth.tenant_mfa_policy``: ``org_id``, ``mode``
(``off|optional|enforced``), and ``remember_days``. It is read on every login.
Membership is read from ``auth.organization_users`` for the authenticated user,
never from ``X-Org-Id`` or ``X-Client-Id``. Deployments must provide that table,
as they do ``auth.vw_users``. No membership yields no policy (OFF), not a global
default.

For a user belonging to several organizations, the strictest mode wins and the
smallest ``remember_days`` among non-OFF organizations wins.

Changing a policy (the transactional recipe)
--------------------------------------------

Use ``navigator_auth.mfa.policy.apply_tenant_policy(...)`` rather than a direct
``UPDATE``:

.. code-block:: python

   from navigator_auth.mfa.policy import apply_tenant_policy
   from navigator_auth.mfa.types import MfaMode

   await apply_tenant_policy(
       db_pool=db_pool,
       security=security,
       trusted_devices=trusted_devices,
       org_id=42,
       mode=MfaMode.ENFORCED,
       remember_days=30,
       actor="security-admin@example.com",
       actor_user_id=7,
   )

Hardening (a stricter mode or fewer ``remember_days``) bumps the security version
of every member, revokes the tenant's trusted devices, and writes an
``auth.user_mfa_audit`` row in one transaction. Relaxing only audits. The context
digest detects raw SQL edits, but only this recipe revokes the affected devices.

Pre-flight before enforcing
---------------------------

Run ``python -m scripts.preflight_mfa --org-id N`` before selecting
``enforced``. B1 (an active member with no usable e-mail address) and B2 (an
active superuser without a strong factor) both block activation. Exit statuses are
``0`` (safe), ``1`` (blocked), and ``2`` (operational error). The check cannot
identify an address that is wrong because address verification is not part of this
feature; login continues to enforce both rules after activation.

Administrative disenrolment and separation of duties
----------------------------------------------------

``DELETE /auth/mfa/{user_id}`` requires ``mfa:disenroll`` from
``abac/default_policies/mfa_admin_access.yaml`` and requires the actor to own all
of the target's organizations. The pack grants the action to ``security_admin``;
your deployment must create that group. The operation disables TOTP, invalidates
backup codes, revokes trusted devices, writes a durable audit row, and notifies the
user. It does not otherwise alter the account.

.. warning::

   Adding ``mfa:*`` or ``"*"`` to ``admin_full_access.yaml`` defeats this
   separation of duties. Without the MFA policy pack, nobody can disenrol a user:
   the service fails closed. ``UserManager`` can still edit ``email``; a principal
   with both user CRUD and ``mfa:disenroll`` can take over an account. This is an
   accepted limitation tracked for FEAT-107.

Remember this device
--------------------

Remember-device is offered only after a strong factor and only when
``remember_days > 0``. It skips OTP, never the password. The ``nav_mfa_device``
cookie is ``HttpOnly``, ``Secure``, and ``SameSite=Lax``; it rotates on each use,
replay revokes its family, and the expiry window is never extended. Its login
session has ``amr=["pwd", "trusted_device"]``.

Password changes, recovery completion, TOTP enrolment or disenrolment,
administrator disenrolment, tenant hardening, and passkey removal invalidate
trusted devices. A global-logout revocation hook exists, but there is no
"logout everywhere" endpoint yet; logging out of one session does not revoke
devices.

Credential changes
~~~~~~~~~~~~~~~~~~

A credential change, its security-version bump, the trusted-device revocation and the
audit row happen in one transaction. When 2FA is on and MFA is unavailable, the change
is refused with ``503`` ``mfa_unavailable``; if the stored password hash changed
underneath the request, it answers ``409`` ``credentials_changed``. An administrator
``password_reset`` now also ends the target user's sessions and tokens. Recovery
completion records its single-use confirmation in ``recovery_confirm_consumptions`` in
the same transaction, and a failure to revoke sessions and tokens rolls the password
change back (``503``, password unchanged). Self-service ``password_change`` still does
not revoke the user's other sessions.

Recovering an enforced superuser
--------------------------------

An enforced superuser without a strong factor receives
``strong_factor_required``. There is no e-mail fallback or trusted-device
exception, including after promotion or factor loss; removing the last strong
factor is refused. Recovery needs a backup code while TOTP remains registered,
another registered passkey, or the audited operator procedure: temporarily remove
the privileged role, recover and re-enrol, then restore the role only after the
strong-factor check passes. There is no password-only or e-mail-only grace
session.

Challenges, attempts and invalidation
-------------------------------------

Each challenge accepts five attempts. Attempts one through four preserve it, the
fifth failure burns it, and a correct code consumes it. ``POST
/auth/mfa/challenge`` resends an e-mail OTP only for a live challenge; it rotates
the code while retaining the original expiry and attempt budget. Password
change/reset, recovery completion, factor changes, passkey registration or removal,
and policy hardening invalidate outstanding challenges. Redis or Postgres failure
refuses verification.

Protected seed storage
----------------------

TOTP seeds are sealed by the vault kernel in their own table, ``auth.user_mfa_secrets``,
whose identity columns ``(user_id, provider, key)`` are the seed's associated data, so a
copied seed cannot be opened. Migration ``002_mfa_secrets.sql`` moves existing ``mfa:``
rows out of ``auth.user_vault_secrets``. Master-key rotation re-seals them through the
``mfa`` target of the ``navigator_session.vault_targets`` entry point
(``mfa = "navigator_auth.mfa.targets:factory"``). Entry points are read from installed
metadata, so reinstall the package (``uv pip install -e .``) for ``navigator-vault`` to
discover the target. The session-vault HTTP API rejects ``mfa:`` keys and hides them
from listings; the session-vault loader never decrypts them. Verification can read
a seed without a session, but any vault error refuses the login.

Accepted bounds
---------------

Redis and database readiness
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MFA requires Redis 6.2 or newer: the atomic consumption Lua script calls
``GETDEL``, and email-code replacement uses ``SET KEEPTTL``. Startup reads
``INFO server`` to validate the version without creating keys. Unreadable server
information, an older Redis, or missing database relations, columns or usable
indexes leaves MFA unavailable. Operators must permit this read-only readiness
check. Database readiness checks index ownership, validity and required uniqueness.

Callback and transaction behavior
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Synchronous delivery callbacks run in a worker thread so SMTP or other blocking
I/O does not block the event loop. Async callbacks and returned awaitables run on
the event loop. Cancelling or timing out a synchronous callback cannot interrupt
the thread: the delivery may finish later. Callbacks should set their own I/O
timeouts and tolerate abandoned requests. Async cancellation is propagated.

The gate commits database changes before issuing a session, including trusted
device rotation or creation. A matching session advisory lock retains per-user
serialization until issuance finishes. If explicit unlock fails, the underlying
database connection is terminated before it returns to the pool. Commit failure
therefore prevents session issuance; an already-consumed challenge stays consumed.
Self-disenrollment invalidates unused backup codes in the same transaction.

The per-user budget deliberately combines attempts across challenges. An attacker
who knows a password can exhaust the victim's verification allowance and temporarily
deny access; per-IP limiting reduces distributed pressure but does not eliminate
that tradeoff. Management routes share ``mgmt:<user_id>`` across password and factor
proofs, while enrollment confirmation retains its separate attempt budget.

Authentication bounds
~~~~~~~~~~~~~~~~~~~~~

* A shared mailbox weakens both the e-mail factor and password recovery. This is
  why a superuser cannot remain on the e-mail floor.
* E-mail addresses are not verified. Whether the e-mail floor is adequate depends
  on the tenant's address hygiene.
* A passkey satisfies MFA enforcement only while
  ``PASSKEY_USER_VERIFICATION="required"`` (the default). Lowering it to
  ``"preferred"`` can make passkeys single-factor; see :doc:`passkey`.
* SMS OTP, external-IdP enforcement, a tenant-policy HTTP API, and e-mail
  verification are non-goals.
