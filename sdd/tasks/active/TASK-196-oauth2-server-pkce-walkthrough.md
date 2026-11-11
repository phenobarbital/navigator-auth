# TASK-196: oauth2_server.py pins its backend and its browser pages do PKCE (S256)

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1 S6 + S7 / G1–G2, §3 Module 2, AC3–AC4. `examples/oauth2_server.py:55` builds
`AuthHandler()` (same settings-override defect as the 3LO example). Its browser walk-through
(`/login` → Authorize → `callback.html` → Get Token) fails with `invalid_grant: code_verifier
required.`: the provider correctly enforces RFC 7636, but `oauth2_index.html` / `callback.html`
never generate, store or send a PKCE pair, and the startup hint prints a `<S256_hash>` placeholder.

---

## Scope

- `examples/oauth2_server.py`: `AuthHandler(backends=["navigator_auth.backends.oauth2.Oauth2Provider"], authz_backends=[])`;
  rewrite the **3LO** startup hint to point at `http://localhost:5000/login` and explain
  `code_challenge = BASE64URL(SHA256(code_verifier))` instead of printing `<S256_hash>`.
- `examples/static/oauth2_index.html`: replace the "without PKCE" note and the static
  `/oauth2/authorize?…` link with a button that generates verifier, S256 challenge and a random
  `state`, stores `{verifier, state}` in `sessionStorage` under `nav_oauth2_index_pkce`, and redirects.
- `examples/static/callback.html`: `exchangeToken()` loads the stored pair, refuses a mismatched
  `state` with a visible message, posts `code_verifier`, clears the store after success.
- Create `tests/test_oauth2_examples_wiring.py` (source/AST and page-content checks).

**NOT in scope**: the Device Grant hint (`:184-200`, its `<S256_hash>` at `:189` stays);
`examples/static/oauth2_3lo_app.html` (reference, untouched — spec Non-Goals);
`examples/README.md` (TASK-207); `examples/oauth2_3lo_server.py` (TASK-195).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `examples/oauth2_server.py` | MODIFY | Pinned `AuthHandler`; 3LO hint points at `/login` |
| `examples/static/oauth2_index.html` | MODIFY | PKCE + `state` authorize button |
| `examples/static/callback.html` | MODIFY | `state` check + `code_verifier` in the exchange |
| `tests/test_oauth2_examples_wiring.py` | CREATE | AST + page-content tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` (2026-11-11). FEAT-106 does not touch these files.

### Verified Imports
```python
import ast                     # stdlib — oauth2_server.py runs at import (app + auth.setup at :52-56), never import it in tests
from pathlib import Path       # stdlib
```

### Existing Signatures to Use
```python
# examples/oauth2_server.py
auth = AuthHandler()                                      # :55  (module level, runs at import)
print("3LO flow (public client + PKCE S256):")            # :173 (3LO hint block :173-182)
    "&state=test_state"                                   # :180
    "&code_challenge=<S256_hash>&code_challenge_method=S256"  # :181 (3LO) AND :189 (device) — edit only :181
# Public client: client_id "nav_public_client", redirect_uri http://localhost:5000/static/callback.html,
# scopes default profile email offline_access (hint at :174-182; client registration :90+).
```
```js
// examples/static/oauth2_3lo_app.html — reference implementation (copy, do not import)
function b64url(bytes) { ... }            // :172-175
function randomString(size = 32) { ... }  // :177-179
async function s256(verifier) { ... }     // :181-184 (crypto.subtle.digest SHA-256)
const load / save / clear (sessionStorage) // :186-188
async function startLogin() { ... }       // :200-214 (verifier = randomString(32), state = randomString(12))
async function exchangeCode(code, state)  // :216-239 (state check, code_verifier in the body)

// examples/static/oauth2_index.html
//   :48-52  <p>This page starts the flow <em>without</em> PKCE ... </p>
//   :53-54  <a href="/oauth2/authorize?client_id=nav_public_client&...&state=xyz123&scope=default+profile"><button>Authorize</button></a>
// examples/static/callback.html
//   :20-24  const params / code / state read from location.search
//   :30-48  async function exchangeToken() { ... } (no code_verifier, no state check)
```

### Does NOT Exist
- No `code_verifier` / `code_challenge` anywhere in `callback.html` or `oauth2_index.html`.
- No shared PKCE JS file under `examples/static/` — inline the helpers in each page (spec §2).
- No `/client-config` route in `oauth2_server.py` (that is the 3LO example) — hard-code the values the hint already prints.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "examples/oauth2_server.py", "action": "MODIFY"},
    {"path": "examples/static/oauth2_index.html", "action": "MODIFY"},
    {"path": "examples/static/callback.html", "action": "MODIFY"},
    {"path": "tests/test_oauth2_examples_wiring.py", "action": "CREATE"}
  ],
  "contract_symbols": []
}
```

---

## Implementation Notes

### Key Constraints
- `crypto.subtle` needs a secure context: `http://localhost` qualifies, a LAN IP does not (TASK-207 documents it).
- The token request stays `application/x-www-form-urlencoded` (the provider answers 415 to JSON).
- The two pages share only the storage key `nav_oauth2_index_pkce`; never put the verifier in the URL.
- Escape nothing new server-side: these are static files served by `add_static`.

---

## Implementation Blueprint

### Steps (in order)
1. Pin the backend in `oauth2_server.py` — *why*: AC3 (same defect as S6).
2. Rewrite the 3LO hint (only the block preceded by `"&state=test_state"`) — *why*: AC4, no placeholder.
3. Replace the index page note + link with the PKCE button and script — *why*: G2.
4. Rewrite `exchangeToken()` in the callback — *why*: the `state` check is the CSRF guard; the verifier is the PKCE proof.
5. Create the tests and run them.

### `examples/oauth2_server.py` (MODIFY) — backend
```python
# occurrences: 1 (verified: grep -c 'auth = AuthHandler()' examples/oauth2_server.py)
# REPLACE `auth = AuthHandler()` (verified: examples/oauth2_server.py:55) WITH:
# ``backends`` pins the provider this example demonstrates (navigator_auth.conf
# star-imports settings.settings last, so local dev settings would otherwise decide the
# list), and ``authz_backends=[]`` stops an inherited allow_hosts from letting requests
# through without a session.
auth = AuthHandler(
    backends=["navigator_auth.backends.oauth2.Oauth2Provider"], authz_backends=[]
)
```

### `examples/oauth2_server.py` (MODIFY) — 3LO hint
```python
# occurrences: 1 (verified: grep -c 'print("3LO flow (public client + PKCE S256):")' examples/oauth2_server.py)
# REPLACE the print(...) call that follows `print("3LO flow (public client + PKCE S256):")`
# (verified: examples/oauth2_server.py:173-182 — the one containing "&state=test_state") WITH:
                print(
                    "  Open http://localhost:5000/login and press Authorize — the page"
                    " generates the PKCE pair (S256) and a random state."
                )
                print(
                    "  Raw form: GET /oauth2/authorize?response_type=code"
                    "&client_id=nav_public_client"
                    "&redirect_uri=http://localhost:5000/static/callback.html"
                    "&scope=default+profile+email+offline_access&state=<random>"
                    "&code_challenge=BASE64URL(SHA256(code_verifier))&code_challenge_method=S256"
                )
```
**Why**: the `:189` occurrence belongs to the device hint and stays (NOT in scope).

### `examples/static/oauth2_index.html` (MODIFY)
```html
<!-- occurrences: 1 (verified: grep -c 'This page starts the flow <em>without</em> PKCE' examples/static/oauth2_index.html) -->
<!-- REPLACE lines :48-54 (the <p>…without PKCE…</p> and the <a href="/oauth2/authorize?…"> link) WITH: -->
        <p>
            The button generates a PKCE pair (S256) and a random <code>state</code>, keeps them in
            <code>sessionStorage</code>, and starts <code>/oauth2/authorize</code>. The callback page checks
            the <code>state</code> and sends the <code>code_verifier</code> to <code>/oauth2/token</code>.
        </p>
        <button type="button" onclick="startAuthorize()">Authorize</button>
        <script>
            const STORE = 'nav_oauth2_index_pkce';
            const CLIENT_ID = 'nav_public_client';
            const REDIRECT_URI = 'http://localhost:5000/static/callback.html';
            const SCOPE = 'default profile email offline_access';
            // FILL IN: b64url, randomString, s256 — copy the bodies from oauth2_3lo_app.html:172-184 verbatim.
            async function startAuthorize() {
                // FILL IN: verifier = randomString(32); state = randomString(12);
                //          sessionStorage.setItem(STORE, JSON.stringify({verifier, state}));
                //          redirect to /oauth2/authorize with response_type=code, client_id, redirect_uri,
                //          scope, state, code_challenge = await s256(verifier), code_challenge_method=S256
                //          — bounded by AC4 (pattern oauth2_3lo_app.html:200-214).
            }
        </script>
```

### `examples/static/callback.html` (MODIFY)
```js
// occurrences: 1 (verified: grep -c 'async function exchangeToken() {' examples/static/callback.html)
// REPLACE the whole function at :30-48 WITH:
        const STORE = 'nav_oauth2_index_pkce';

        async function exchangeToken() {
            let saved = {};
            try { saved = JSON.parse(sessionStorage.getItem(STORE)) || {}; } catch { saved = {}; }
            if (!saved.state || saved.state !== state) {
                document.getElementById('result').innerText =
                    'state mismatch — possible CSRF, the exchange was not attempted.';
                return;
            }
            const formData = new URLSearchParams();
            formData.append('grant_type', 'authorization_code');
            formData.append('code', code);
            formData.append('client_id', 'nav_public_client');
            formData.append('redirect_uri', 'http://localhost:5000/static/callback.html');
            formData.append('code_verifier', saved.verifier);
            // FILL IN: POST to /oauth2/token as before (form-urlencoded); show the JSON; on res.ok
            //          sessionStorage.removeItem(STORE) — bounded by AC4.
        }
```

### `tests/test_oauth2_examples_wiring.py` (CREATE)
```python
"""FEAT-108 M2 — oauth2_server.py backend pinning and the PKCE browser pages."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "examples" / "oauth2_server.py"
INDEX = ROOT / "examples" / "static" / "oauth2_index.html"
CALLBACK = ROOT / "examples" / "static" / "callback.html"


def _auth_handler_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "AuthHandler"
    ]


def test_oauth2_server_pins_backends():
    """AC3 — source check: the module starts a server at import, never import it."""
    calls = _auth_handler_calls(ast.parse(SERVER.read_text()))
    assert len(calls) == 1
    kwargs = {kw.arg: kw.value for kw in calls[0].keywords}
    # FILL IN: assert ast.literal_eval(kwargs["backends"]) == ["navigator_auth.backends.oauth2.Oauth2Provider"]
    #          and ast.literal_eval(kwargs["authz_backends"]) == [] — bounded by AC3.


def test_oauth2_server_3lo_hint_has_no_placeholder():
    """AC4 — the 3LO hint no longer prints <S256_hash>; the device hint may."""
    # FILL IN: the text between 'print("3LO flow' and 'Device Grant flow' contains no
    #          "<S256_hash>" and mentions http://localhost:5000/login — bounded by AC4.


def test_index_page_sends_pkce_challenge():
    html = INDEX.read_text()
    assert "code_challenge_method" in html and "crypto.subtle" in html
    assert "nav_oauth2_index_pkce" in html
    # FILL IN: no static href to /oauth2/authorize? remains — bounded by AC4.


def test_callback_page_sends_verifier_and_checks_state():
    html = CALLBACK.read_text()
    # FILL IN: "code_verifier" posted, saved.state compared to the returned state,
    #          and the same STORE key as the index page — bounded by AC4.
```

### FILL IN checklist
- [ ] Index page helpers + `startAuthorize()`; bounded by AC4.
- [ ] Callback POST + store clear; bounded by AC4.
- [ ] The four test bodies; bounded by AC3/AC4.

---

## Acceptance Criteria

- [ ] AC3: `examples/oauth2_server.py` builds `AuthHandler(backends=["navigator_auth.backends.oauth2.Oauth2Provider"], authz_backends=[])`.
- [ ] AC4: the index page sends `code_challenge` (S256) and a random `state`; the callback refuses a mismatched `state` and sends `code_verifier`; the 3LO hint no longer prints `<S256_hash>`.
- [ ] Manual check (record in the Completion Note): `python examples/oauth2_server.py`, `/login` → Authorize → login → consent → callback → Get Token returns an `access_token`.
- [ ] `ruff check examples/oauth2_server.py tests/test_oauth2_examples_wiring.py` is clean.

---

## Validation Commands

- `pytest tests/test_oauth2_examples_wiring.py -q`

---

## Test Specification

See the CREATE block: `test_oauth2_server_pins_backends`, `test_oauth2_server_3lo_hint_has_no_placeholder`,
`test_index_page_sends_pkce_challenge`, `test_callback_page_sends_verifier_and_checks_state` (spec §4, M2).

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` in the blueprint before editing; a changed
   count means the anchor moved (re-locate it), a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-196 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
