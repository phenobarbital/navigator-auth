"""FEAT-108 M2 — oauth2_server.py backend pinning and the PKCE browser pages."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "examples" / "oauth2_server.py"
INDEX = ROOT / "examples" / "static" / "oauth2_index.html"
CALLBACK = ROOT / "examples" / "static" / "callback.html"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _auth_handler_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "AuthHandler"
    ]


def _three_lo_hint_block(source: str) -> str:
    start = source.index('print("3LO flow')
    end = source.index('print("Device Grant flow', start)
    return source[start:end]


def test_oauth2_server_pins_backends():
    """AC3 — source check: the module starts a server at import, never import it."""
    calls = _auth_handler_calls(ast.parse(_read(SERVER)))
    assert len(calls) == 1
    kwargs = {kw.arg: kw.value for kw in calls[0].keywords}
    assert ast.literal_eval(kwargs["backends"]) == [
        "navigator_auth.backends.oauth2.Oauth2Provider"
    ]
    assert ast.literal_eval(kwargs["authz_backends"]) == []


def test_oauth2_server_3lo_hint_has_no_placeholder():
    """AC4 — the 3LO hint no longer prints <S256_hash>; the device hint may."""
    block = _three_lo_hint_block(_read(SERVER))
    assert "<S256_hash>" not in block
    assert "http://localhost:5000/login" in block


def test_index_page_sends_pkce_challenge():
    """AC4 — the index page generates an S256 challenge and a random state."""
    html = _read(INDEX)
    assert "code_challenge_method" in html and "crypto.subtle" in html
    assert "nav_oauth2_index_pkce" in html
    assert 'href="/oauth2/authorize?' not in html


def test_callback_page_sends_verifier_and_checks_state():
    """AC4 — the callback checks state, posts code_verifier, and shares the store key."""
    html = _read(CALLBACK)
    assert "code_verifier" in html
    assert "saved.state !== state" in html
    assert "nav_oauth2_index_pkce" in html
    assert "sessionStorage.removeItem(STORE)" in html
