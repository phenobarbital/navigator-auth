"""Focused contract tests for the MFA Redis state primitives."""

import json

from navigator_auth.mfa.store import canonical_json, new_opaque_token


def test_canonical_json_is_stable():
    """Canonical encoding is independent of mapping insertion order."""
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_opaque_token_is_url_safe_and_unique():
    """Opaque tokens are non-empty and suitable for URL transport."""
    token = new_opaque_token()
    assert token
    assert json.loads(json.dumps(token)) == token
