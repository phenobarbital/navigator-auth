---
id: FC-002
query_id: Q010
type: read
intent: "Read the session-binding code around backend.py:700 and the code that mints the access token."
executed_at: 2026-11-11T14:36:00Z
duration_ms: 600
parent_id: null
depth: 0
---

# FC-002 — Session-bind failure is swallowed: the token is still issued, without session claims

## Summary

`_token_session_claims` resolves the owner with `self._idp.user_from_id(user_id)`;
any exception is logged as the reported warning ("cannot bind a session to the
token for user_id=…") and an EMPTY dict is returned. The caller spreads that dict
into `token_data`, so the access token is minted anyway — carrying only
`user_id/client_id/scope/jti`, with no `session_id`/username claims. The same call
runs on the refresh grant (2046), which explains the warning on "Refresh Token".
Downstream, nothing can resolve a session from such a token (see FC-004, FC-008).

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 688-710
  symbol: `Oauth2Provider._token_session_claims`
  excerpt: |
    try:
        user = await self._idp.user_from_id(user_id)
    except Exception as exc:  # pylint: disable=W0703
        self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")
        return {}
    session = await self._create_user_session(request, user)
    if not session:
        return {}

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 1822-1830
  symbol: `Oauth2Provider._handle_authorization_code`
  excerpt: |
    token_data = {
        "user_id": user_id,
        "client_id": client.client_id,
        "scope": scope,
        "jti": jti,
        **await self._token_session_claims(request, user_id),
    }

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2046
  symbol: `Oauth2Provider._handle_refresh_token`
  excerpt: |
    **await self._token_session_claims(request, user_id),

- path: `examples/oauth2_3lo_server.py`
  lines: 131-135
  symbol: `DemoIdentityProvider.user_from_id`
  excerpt: |
    for user in self._users.values():
        if str(user.user_id) == str(uid):
            return user
    raise UserNotFound(f"Invalid Credentials for user_id={uid!r}")

## Notes

The decoded tokens in the report confirm the claim-less shape:
`{'exp','iat','iss','jti','user_id': 35,'client_id','scope','aud'}` — no session id.
The degrade-silently behaviour is intentional and tested (FC-010,
`test_unknown_user_degrades_without_raising`).
