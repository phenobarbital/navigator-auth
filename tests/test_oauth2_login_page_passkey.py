"""FEAT-101 TASK-97 — OAuth2 login page passkey UI.

Static template checks always run. The browser test needs Playwright (not a project
dependency) and is skipped when it is not importable.
"""

from pathlib import Path

import pytest

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "oauth" / "login.html"


def _render() -> str:
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(TEMPLATE.parent.parent)))
    return env.get_template("oauth/login.html").render(
        action_url="/oauth2/login", client_id="c", state="s", upstream_providers=[]
    )


def test_login_page_has_passkey_ui_and_keeps_password_form():
    html = _render()
    assert 'name="username"' in html and 'autocomplete="username webauthn"' in html
    assert 'name="password"' in html and 'action="/oauth2/login"' in html
    assert 'id="passkey-signin"' in html
    assert "/api/v1/auth/passkey/login/options" in html
    assert '"X-Auth-Method": "PasskeyAuth"' in html
    assert "mediation" in html and "isConditionalMediationAvailable" in html
    # pre-session public calls: no CSRF header is sent
    assert "X-CSRF" not in html
    # authorize parameters (incl. PKCE) are carried through
    for name in ("code_challenge", "code_challenge_method", "nonce", "prompt", "state"):
        assert f'"{name}"' in html


def test_login_page_script_is_valid_javascript(tmp_path):
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    html = _render()
    start = html.index("<script>", html.index("passkey-signin"))
    js = html[start + len("<script>") : html.index("</script>", start)]
    path = tmp_path / "login.js"
    path.write_text(js)
    assert subprocess.run([node, "--check", str(path)], capture_output=True).returncode == 0


def test_oauth2_login_page_passkey():
    """Browser check with a CDP virtual authenticator (button is revealed when WebAuthn exists)."""
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as err:  # pylint: disable=W0703
            pytest.skip(f"chromium unavailable: {err}")
        try:
            page = browser.new_page()
            cdp = page.context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            cdp.send(
                "WebAuthn.addVirtualAuthenticator",
                {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": True,
                        "hasUserVerification": True,
                        "isUserVerified": True,
                    }
                },
            )
            page.set_content(_render())
            assert page.is_visible("#passkey-signin")
        finally:
            browser.close()
