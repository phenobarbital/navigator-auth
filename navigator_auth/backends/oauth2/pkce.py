"""PKCE (Proof Key for Code Exchange) utilities — TASK-025.

Implements S256 (SHA-256) as the only supported method.
Plain PKCE is NOT supported by this implementation; RFC 7636 allows
servers to reject ``plain`` — we enforce S256 for all public clients.

Spec: RFC 7636 — https://tools.ietf.org/html/rfc7636
"""

import base64
import hashlib


def _s256(verifier: str) -> str:
    """Compute the S256 code challenge from a verifier string.

    challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """Verify a code_verifier against the stored code_challenge.

    Args:
        code_verifier:   The raw verifier string sent by the client at the
                         token endpoint.
        code_challenge:  The challenge value stored at the authorize endpoint.
        method:          The challenge method; only "S256" is accepted.

    Returns:
        True  if the verifier matches the challenge.
        False otherwise (including if method is not S256).
    """
    if method.upper() != "S256":
        # Reject plain and any unknown method.
        return False

    if not code_verifier or not code_challenge:
        return False

    computed = _s256(code_verifier)
    # Constant-time comparison.
    import hmac as _hmac
    return _hmac.compare_digest(computed, code_challenge)


def generate_challenge(verifier: str) -> str:
    """Helper for tests/examples: generate the S256 challenge from a verifier."""
    return _s256(verifier)
