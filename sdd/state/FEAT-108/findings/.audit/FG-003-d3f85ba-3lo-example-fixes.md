---
id: FG-003
query_id: Q032
type: git_log
intent: "History of the 3LO example and its regression tests (d3f85ba)."
executed_at: 2026-11-11T14:41:00Z
duration_ms: 900
parent_id: null
depth: 0
---

# FG-003 — d3f85ba: the 3LO example and the fixes that already landed

## Summary

`examples/oauth2_3lo_server.py` and `tests/test_oauth2_3lo_session_binding.py` have a single commit:
d3f85ba (2026-08-21, author "Claude"). It added the example and fixed the flow: it introduced
`Oauth2Provider._token_session_claims` (bind each issued access token to a session via
`self._idp.user_from_id`, logging the exact warning seen in the report and returning `{}` on failure),
the Resource-Server `Oauth2Provider.authenticate()` (raises 401 when the token has no bound session),
`_get_request_user_id` reading `request["userdata"]`, `aud`-tolerant `decode_token`, and made
`conf.AUTHENTICATION_BACKENDS` read from navconfig (`config.get`, fallback empty). Session binding,
PKCE propagation and the grants-API user lookup are therefore NOT new work — the report's failures are
what happens when `user_from_id` cannot resolve the token's user.

## Citations

- commit: `d3f85ba` — 2026-08-21 10:59 +0000 — Claude
  message: "feat(oauth2): end-to-end 3LO example + fixes to make the flow work"
  files: |
    examples/README.md (+90), examples/oauth2_3lo_server.py (+265), examples/oauth2_server.py,
    examples/static/oauth2_3lo_app.html (+362), examples/static/oauth2_index.html, examples/static/callback.html,
    navigator_auth/auth.py (+84), navigator_auth/backends/idp/__init__.py (+39),
    navigator_auth/backends/oauth2/backend.py (+265), navigator_auth/conf.py (+11),
    templates/oauth/consent.html, templates/oauth/login.html, tests/test_oauth2_3lo_session_binding.py (+168)

- path: `navigator_auth/backends/oauth2/backend.py`
  symbol: `Oauth2Provider._token_session_claims`
  excerpt: |
    try:
        user = await self._idp.user_from_id(user_id)
    except Exception as exc:  # pylint: disable=W0703
        self.logger.warning(
            f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}"
        )
        return {}

- path: `navigator_auth/backends/oauth2/backend.py`
  symbol: `Oauth2Provider.authenticate`
  excerpt: |
    session = await get_session(request, payload, new=False)
    ...
    if not session:
        raise InvalidAuth("Oauth2: the access token is not bound to a valid session.", status=401)

- path: `navigator_auth/conf.py`
  symbol: `AUTHENTICATION_BACKENDS`
  excerpt: |
    AUTHENTICATION_BACKENDS = tuple(
        e.strip()
        for e in config.get("AUTHENTICATION_BACKENDS", fallback="").split(",")
        if e.strip()
    )

## Notes

- Commit message states the design intent: a token whose owner cannot be resolved is left "usable for
  introspection-based resource servers" (no session claims) — so `/api/v1/me`, `/oauth2/userinfo` and the
  grants API degrade (401 / empty profile) by design when binding fails. The example relies on
  `DemoIdentityProvider` (users 1 and 2) being the IdP for BOTH login and `user_from_id`.
- The example sets backends via `os.environ.setdefault("AUTHENTICATION_BACKENDS", ...)`, but conf reads
  it with navconfig `config.get`; if the operator's env file defines it, the example's value is ignored
  (consistent with Azure/ADFS/NoAuth/TrocToken appearing in the log).
- [cross-lane: type=read, intent=confirm which IdP instance Oauth2Provider.auth_login uses to authenticate the resource owner — token user_id=35 is not in DEMO_USERS]
- [cross-lane: type=read, intent=verify navconfig precedence: does config.get prefer env/dev/.env over os.environ set before import?]
