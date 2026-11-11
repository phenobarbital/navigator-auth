---
id: FC-011
query_id: Q019
type: grep
intent: "Read the SPA buttons (List my grants, Call without credentials) to see which endpoints/headers they use."
executed_at: 2026-11-11T14:43:30Z
duration_ms: 300
parent_id: null
depth: 0
---

# FC-011 — SPA calls: bearer on me/userinfo/grants; the anonymous call omits cookies

## Summary

`examples/static/oauth2_3lo_app.html` calls `/api/v1/me` with and without the
bearer, `/oauth2/userinfo` and `GET /api/v1/oauth2/grants` with the bearer, and
`DELETE /api/v1/oauth2/grants/<client_id>` for revoke. `callApi` uses
`credentials: 'omit'`, so the "without credentials (expect 401)" call carries no
cookie and no header — the anonymous 200 is produced server-side (FC-004 allow_hosts
exemption + FC-007 NoAuth), not by a leaked browser session.

## Citations

- path: `examples/static/oauth2_3lo_app.html`
  lines: 261-270
  symbol: `callApi`
  excerpt: |
    async function callApi(url, withToken) {
        const headers = {};
        if (withToken) {
            headers.Authorization = `${token.token_type} ${token.access_token}`;
        }
        // credentials:'omit' -> the browser session cookie ... is NOT sent
        const res = await fetch(url, { headers, credentials: 'omit' });

- path: `examples/static/oauth2_3lo_app.html`
  lines: 318-322
  symbol: `button handlers`
  excerpt: |
    $('call-me').onclick = () => callApi(cfg.protected_endpoint, true);
    $('call-me-anon').onclick = () => callApi(cfg.protected_endpoint, false);
    $('call-userinfo').onclick = () => callApi(cfg.userinfo_endpoint, true);
    $('list-grants').onclick = () => callApi('/api/v1/oauth2/grants', true);

- path: `examples/static/oauth2_3lo_app.html`
  lines: 144, 159
  symbol: `buttons`
  excerpt: |
    <button id="call-me-anon" class="secondary">Call it without credentials (expect 401)</button>
    <button id="list-grants" class="secondary" disabled>List my grants</button>
