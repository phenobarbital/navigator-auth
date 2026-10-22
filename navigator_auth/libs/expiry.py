"""Published token-expiry fields (FEAT-103 Module 5).

``IdentityProvider.create_token`` returns an ABSOLUTE epoch (a float) as its
third tuple element (``backends/idp/__init__.py``). Publishing that under
the key ``expires_in`` is wrong: RFC 6749 §4.2.2 defines ``expires_in`` as
"the lifetime in seconds of the access token".

This module holds the single conversion used by every publisher, extending the
repo's existing **B1** decision — *"expires_in is seconds (int)"*,
``backends/oauth2/backend.py`` — from the OAuth2 provider backend to the
legacy login publishers.
"""
import time


def expiry_fields(exp: float) -> dict:
    """Map an absolute epoch ``exp`` onto the published expiry pair.

    Args:
        exp: Absolute expiry as a UNIX epoch, as returned by
            ``IdentityProvider.create_token`` / ``create_ephemeral_token``.

    Returns:
        ``{"expires_in": <int seconds remaining, never < 0>,
           "expires_at": <int absolute epoch>}``

    Example:
        >>> fields = expiry_fields(time.time() + 3600)
        >>> 3595 <= fields["expires_in"] <= 3600
        True
    """
    remaining = int(exp - time.time())
    return {
        "expires_in": max(remaining, 0),
        "expires_at": int(exp),
    }
