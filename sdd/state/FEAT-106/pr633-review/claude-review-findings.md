# Candidate findings from another reviewer (UNVERIFIED)

These came from a separate automated reviewer. Each is a claim, not a fact. Line numbers refer to the PR tree.

1. `navigator_auth/backends/oauth2/backend.py:1636`: the second factor is only hooked into `BasicAuth.authenticate`. `Oauth2Provider.auth_login` (POST to the OAuth2 login URI) checks only the password via `idp.authenticate_credentials`, then calls `_create_user_session`. That bypasses 2FA for an enforced tenant whenever `Oauth2Provider` is in `AUTHENTICATION_BACKENDS`.
2. `navigator_auth/mfa/totp.py:270`: the TOTP seed is sealed into `auth.user_vault_secrets` with an MFA purpose and fields `(user_id, provider, key)`. navigator_session's rotation target for that table (`UserVaultTarget`) uses purpose `user-vault` with fields `(user_id, key)`, and no MFA target is registered. So `rotate_master_key` and `migrate_v1_to_v2` cannot open these rows. Once the old key is retired, TOTP verify returns 503, and a quarantine run soft-deletes the seeds.
3. `navigator_auth/handlers/mfa.py:101`: verify holds a pooled connection inside `user_lock`, then acquires more connections from the same pool (`user_from_id`, TOTP `_load_seed`, backup consume, `open_session`). password_change, password_reset and recovery do the reverse: they hold a connection, then `security_transition` acquires a second one. Nested acquires can deadlock the pool at about `max_size` concurrent requests.
4. `navigator_auth/mfa/services.py:132`: MFA availability is decided once in `BasicAuth.on_startup` and never retried. A transient DB failure or a startup DDL race leaves `available=False` for the life of the process. Every login then gets 503, and `security_transition` yields None, so password resets skip the version bump and device revocation.
5. `navigator_auth/handlers/recovery/handler.py:299`: the password update inside the `security_transition` body commits on a different connection. If bump, revoke, audit or commit then fails, the password has changed but session revocation (`drop_pair`, `revoke_user`) is skipped. `password_change` and `password_reset` in `session.py` have the same pattern.
6. `navigator_auth/handlers/mfa.py:65`: the IP rate limiter keys on `request.remote`, not the proxy-aware `get_client_ip` in `authorizations/_client_ip.py`. Behind a load balancer every client shares one 30/hour bucket.
7. `navigator_auth/handlers/mfa.py:443`: backup-code regeneration needs a session, the password and an enrolled strong factor, but no fresh proof of that factor. With a stolen session and the password, an attacker can mint new codes without the TOTP device.
8. `navigator_auth/backends/basic.py:382`: each successful password check sends a new email OTP and issues a new challenge, with no rate limit. That includes the `is_authenticated` decorator path, which accepts GET query credentials. The result is mailbox flooding, and the 5-attempt limit resets on every login.
9. `navigator_auth/mfa/limiter.py:31`: an unparseable `AUTH_OTP_RATE_USER`/`AUTH_OTP_RATE_IP` value turns limiting off with only a warning, though the limiter is documented as fail-closed.
10. `navigator_auth/backends/basic.py:413`: the trusted-device token is rotated and committed before the session opens and the new cookie is delivered. If the session fails, or the decorator path never sets a cookie, the old token is later treated as a replay and the whole device family is revoked.
11. `navigator_auth/handlers/users/user.py:40`: admin password changes through UserManager are not wrapped in `security_transition`, so there is no version bump, no device revocation and no audit.
12. `navigator_auth/handlers/mfa.py:395`: `disenroll_totp` evaluates its strong-factor-still-required guard outside the user lock. A concurrent passkey delete can leave an enforced superuser with no strong factor. MfaStorageError from the unguarded calls also gives 500 instead of 503.
13. `navigator_auth/handlers/mfa.py:354`: `confirm_totp` discards the remaining-attempts count and hard-codes `attempts_remaining: 0` while the pending enrollment still exists.
14. `navigator_auth/mfa/services.py:76`: `_evaluate` repeats `totp_confirmed` and `passkey_count` lookups, plus `to_regclass` probes: about 12–14 DB round-trips per login where about 5 would do.
15. `navigator_auth/mfa/notify.py:27`: a synchronous email or notify callback runs inline on the event loop, and on resend it runs inside `user_lock`. Some `MfaChallengeStore` methods also lack docstrings and type hints.

Lower-priority candidates:
- `auth.py:545` `finalize_login` uses `err.message` on arbitrary exceptions.
- `MfaSecurity.current_version` can return NULL on a concurrent first evaluation.
- A resent email states its expiry as now plus the full TTL.
- A missing email callback is silent, with no startup warning.
- Duplicated helpers across modules.
- `ReservedPrefixSessionVault.load_for_session` copies its base class.
