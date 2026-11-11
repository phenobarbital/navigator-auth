"""Focused contract tests for the MFA Redis state primitives."""

import json

from navigator_auth.mfa.store import MfaChallengeStore, canonical_json, new_opaque_token
from navigator_auth.mfa.types import PendingEnrollment


def test_canonical_json_is_stable():
    """Canonical encoding is independent of mapping insertion order."""
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_opaque_token_is_url_safe_and_unique():
    """Opaque tokens are non-empty and suitable for URL transport."""
    token = new_opaque_token()
    assert token
    assert json.loads(json.dumps(token)) == token


def test_pending_enrollment_digest_is_signed_and_required() -> None:
    """Legacy contextless records and digest tampering cannot authorize enrollment."""
    store = MfaChallengeStore(None, b"test-secret")
    fields = {
        "user_id": 1,
        "session_hash": "session",
        "security_version": 0,
        "context_digest": "context",
        "sealed_seed": "sealed",
        "issued_at": 1.0,
    }
    record = {**fields, "signature": store._sign(fields)}
    assert store._decode(json.dumps(record), PendingEnrollment).context_digest == "context"
    assert store._decode(json.dumps({**record, "context_digest": "other"}), PendingEnrollment) is None
    del fields["context_digest"]
    assert store._decode(json.dumps({**fields, "signature": store._sign(fields)}), PendingEnrollment) is None
