Passkey (WebAuthn) Authentication
=================================

``PasskeyAuth`` adds passwordless sign-in with passkeys (WebAuthn / FIDO2)
to Navigator Auth. Enrollment is done by an already signed-in user; sign-in
goes through the existing ``POST /api/v1/login`` endpoint, and the session is
opened by the same code path as a Basic login (``BasicAuth.open_session``), so
the response body, JWT, refresh token, ``jti`` revocation and success
callbacks are identical.

Overview
--------

- Credentials are bound to a **relying party** (RP): one entry per tenant
  site, matched against the request ``Origin`` exactly. A credential enrolled
  for one RP is never accepted for another.
- Ceremony challenges are single-use and stored in Redis with a short TTL.
- The WebAuthn ``user.id`` is a random 32-byte handle per ``(user, RP)``; it
  never contains the user id or any personal data.
- A passkey login is flagged ``auth_method="passkey"``, ``mfa`` (true when the
  authenticator verified the user) and ``amr`` (``["hwk", "user"]``, or
  ``["hwk"]`` without user verification).
- Disabled accounts (``is_active`` false) are rejected with ``403``.

Installation
------------

.. code-block:: bash

   pip install "navigator-auth[passkey]"

The extra installs ``webauthn>=2.0,<3`` (py_webauthn). Redis **6.2 or newer**
is required (challenges are consumed with ``GETDEL``). The ``webauthn``
package is imported lazily: installations without the extra keep working as
long as ``PasskeyAuth`` is not enabled.

Enable the backend next to the ones you already use:

.. code-block:: python

   AUTHENTICATION_BACKENDS = (
       "navigator_auth.backends.BasicAuth",
       "navigator_auth.backends.PasskeyAuth",
   )

``PasskeyAuth`` refuses to start (``ConfigError``) when
``PASSKEY_RELYING_PARTIES`` is empty or when ``webauthn`` is not installed.
Its tables (``user_credentials`` and ``user_passkey_handles`` in
``AUTH_DB_SCHEMA``) are created idempotently on startup.

Configuration
-------------

=============================== ========================= ==========================================
Setting                         Default                   Description
=============================== ========================= ==========================================
``PASSKEY_RELYING_PARTIES``     ``[]``                    JSON list of allowed relying parties
``PASSKEY_CHALLENGE_TTL``       ``300``                   Seconds a challenge stays valid
``PASSKEY_USER_VERIFICATION``   ``"required"``            ``"required"`` or ``"preferred"``
``PASSKEY_TENANT_ATTRIBUTE``    ``None``                  Optional user attribute compared to ``org_id``
``PASSKEY_DECOY_CREDENTIALS``   ``1``                     Decoy credential ids for unknown usernames
=============================== ========================= ==========================================

With ``PASSKEY_USER_VERIFICATION="required"`` an assertion without user
verification is rejected. An invalid ``PASSKEY_RELYING_PARTIES`` value is
logged and treated as empty (which then stops ``PasskeyAuth`` at startup).

Relying parties (per tenant)
----------------------------

.. code-block:: bash

   PASSKEY_RELYING_PARTIES='[
     {"origin": "https://app.tenant-a.com", "rp_id": "tenant-a.com",
      "rp_name": "Tenant A", "org_id": 5, "client_id": 1},
     {"origin": "https://app.tenant-b.com", "rp_id": "tenant-b.com",
      "rp_name": "Tenant B", "org_id": 7, "client_id": 2}
   ]'

- ``origin`` — the exact origin the browser reports (scheme, host and port).
  It is compared after lower-casing the scheme and host and stripping a
  trailing ``/``. Prefix and wildcard matches do not exist.
- ``rp_id`` — the registrable domain the credential is scoped to.
- ``rp_name`` — display name shown by the authenticator.
- ``org_id`` / ``client_id`` — copied into the session on login so ABAC
  policies are evaluated for the tenant of the site the user signed in on.

The RP is resolved **only** from the ``Origin`` header (``Referer`` is used as
an exact-match fallback when ``Origin`` is absent; the literal ``null`` is
always rejected). ``Host`` and ``X-Forwarded-*`` are never read, so a load
balancer that rewrites them cannot change the result. Make sure the load
balancer forwards the browser's ``Origin`` header unchanged.

Endpoints
---------

======================================================== ================ ==============================================
Method and path                                          Auth             Response
======================================================== ================ ==============================================
``POST /api/v1/auth/passkey/register/options``           Session + CSRF   ``PublicKeyCredentialCreationOptions`` JSON
``POST /api/v1/auth/passkey/register/verify``            Session + CSRF   ``201 {"status": "registered", "id": ...}``
``POST /api/v1/auth/passkey/login/options``              Public           ``{challenge_id, publicKey}``
``POST /api/v1/login`` + ``X-Auth-Method: PasskeyAuth``  Public           Basic login body plus ``auth_method``/``mfa``/``amr``
``GET /api/v1/auth/passkey/credentials``                 Session          list of the caller's passkeys
``PATCH /api/v1/auth/passkey/credentials/{id}``          Session + CSRF   ``200 {"status": "renamed"}``
``DELETE /api/v1/auth/passkey/credentials/{id}``         Session + CSRF   ``204``, or ``409`` for the last login method
======================================================== ================ ==============================================

Every sign-in failure (unknown credential, bad signature, wrong origin,
expired or reused challenge, user-verification missing) returns the same
``401`` so callers cannot tell the cases apart. Deleting the last passkey of a
user who has no password and no linked external identity returns ``409``.
The credential list never exposes the public key, the sign counter or the
user handle.

Client integration
------------------

Enrollment (CSRF)
~~~~~~~~~~~~~~~~~

Enrollment needs an existing session. For **cookie** sessions the CSRF
middleware requires the ``X-CSRF-Token`` header to equal the ``csrf_token``
cookie; Bearer-authenticated requests skip that check.

.. code-block:: javascript

   const csrf = document.cookie.split("; ")
     .find(c => c.startsWith("csrf_token="))?.split("=")[1];
   const headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf};

   const opts = await (await fetch("/api/v1/auth/passkey/register/options", {
     method: "POST", headers, credentials: "same-origin", body: "{}"})).json();
   const cred = await navigator.credentials.create({
     publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(opts)});
   await fetch("/api/v1/auth/passkey/register/verify", {
     method: "POST", headers, credentials: "same-origin",
     body: JSON.stringify({credential: cred.toJSON(), label: "My laptop"})});

Sign-in (username-first and conditional UI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``login/options`` accepts an optional ``username``. With a username the
response lists the user's credentials (or the same number of deterministic
decoy ids for an unknown user, so the response shape does not reveal whether
the account exists). Without a username ``allowCredentials`` is empty, which is
what conditional UI (autofill) uses.

.. code-block:: javascript

   async function passkeySignIn(username, mediation) {
     const started = await (await fetch("/api/v1/auth/passkey/login/options", {
       method: "POST", headers: {"Content-Type": "application/json"},
       credentials: "same-origin",
       body: JSON.stringify(username ? {username} : {})})).json();
     const cred = await navigator.credentials.get({
       publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(started.publicKey),
       ...(mediation ? {mediation} : {})});
     return fetch("/api/v1/login", {
       method: "POST", credentials: "same-origin",
       headers: {"Content-Type": "application/json", "X-Auth-Method": "PasskeyAuth"},
       body: JSON.stringify({challenge_id: started.challenge_id,
                             credential: cred.toJSON()})});
   }

   // conditional UI: <input autocomplete="username webauthn">
   if (await PublicKeyCredential.isConditionalMediationAvailable?.()) {
     passkeySignIn(undefined, "conditional");
   }

The OAuth2 login page (``templates/oauth/login.html``) ships this flow and
continues to ``/oauth2/authorize`` after a successful sign-in.

Session, JWT and ABAC
---------------------

The login response, the session object and the internal JWT carry
``auth_method`` (``"passkey"``), ``mfa`` and ``amr``; the session also carries
the RP's ``org_id``, ``client_id`` and ``passkey_rp_id``. ABAC policies see two
new evaluation-context keys, ``auth_method`` and ``mfa``, so a policy can
require a phishing-resistant login (``auth_method == "passkey"`` or
``mfa == true``).

When ``PASSKEY_TENANT_ATTRIBUTE`` is set (for example ``"org_id"``) and the
user record has that attribute, its value must equal the RP's ``org_id``;
otherwise the login is rejected with the uniform ``401``. A user record
without the attribute skips the check.

Limitations
-----------

- Attestation is requested as ``none`` and is not verified; authenticators are
  not filtered by model.
- Related Origin Requests are not supported: each site needs its own entry.
- A sign-count regression is rejected and logged at warning level (with the
  credential id), but the credential is **not** disabled automatically.
- Decoy credential ids are deterministic per ``(RP, username)``. An attacker
  who can compare the count returned for known and unknown users may infer
  account existence if ``PASSKEY_DECOY_CREDENTIALS`` differs from the typical
  number of enrolled passkeys; keep it at the common value.
