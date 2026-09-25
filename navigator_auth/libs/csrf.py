"""CSRF token generation/verification — signed double-submit cookie.

Stateless: the token is a random nonce plus an HMAC-SHA256 signature over
``session_id + nonce``, keyed with the server's ``SECRET_KEY``. Binding the
signature to the session id means a token leaked from one session can't be
replayed against another, and no server-side token storage is needed —
``navigator_auth.middlewares.csrf`` verifies purely from the request.

Spec: OWASP CSRF Prevention Cheat Sheet — "Signed Double-Submit Cookie".
"""
import base64
import hashlib
import hmac
import secrets

__all__ = ("generate_csrf_token", "verify_csrf_token")


def _sign(secret: bytes, session_id: str, nonce: str) -> str:
    msg = f"{session_id}.{nonce}".encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_csrf_token(secret: bytes, session_id: str) -> str:
    """Generate a signed CSRF token bound to ``session_id``.

    Format: ``"<nonce>.<signature>"`` (both base64url, no padding).
    """
    nonce = secrets.token_urlsafe(16)
    signature = _sign(secret, session_id, nonce)
    return f"{nonce}.{signature}"


def verify_csrf_token(secret: bytes, session_id: str, token: str) -> bool:
    """Verify a token produced by :func:`generate_csrf_token` for the same session_id."""
    if not token or not session_id:
        return False
    try:
        nonce, signature = token.split(".", 1)
    except ValueError:
        return False
    if not nonce or not signature:
        return False
    expected = _sign(secret, session_id, nonce)
    return hmac.compare_digest(expected, signature)
