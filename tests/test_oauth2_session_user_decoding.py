"""Security regression tests for ``Oauth2Provider._decode_session_user``.

The session user blob reaches this decoder from server-side session storage.
It used to be handed straight to ``jsonpickle.decode``, which reconstructs
whatever class the document names and honours ``py/reduce`` — so anything able
to write a session (a compromised session store, a session-fixation bug, a
future client-side session backend) got arbitrary code execution out of it.
See GHAS ``py/unsafe-deserialization``.

Tests:
  test_reduce_gadget_is_not_executed   — the RCE payload decodes to None, runs nothing
  test_jsonpickle_safe_flag_is_not_a_fix — documents why ``safe=True`` was rejected
  test_legacy_jsonpickle_blob_round_trips — real sessions still resolve
  test_plain_json_blob_round_trips     — un-pickled payloads resolve too
  test_malformed_blobs_return_none     — junk never raises, never authenticates
"""

import logging
import os
from pathlib import Path

import jsonpickle
import pytest

from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.models import OauthUser


@pytest.fixture
def decoder():
    """A provider stub exposing only the session-user decoder."""
    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = logging.getLogger("test.oauth2.session")
    return provider


def _reduce_gadget(marker: Path) -> str:
    """A jsonpickle document that runs ``touch <marker>`` when unpickled."""
    return (
        '{"py/reduce": [{"py/function": "os.system"}, '
        '{"py/tuple": ["touch %s"]}]}' % marker
    )


def test_reduce_gadget_is_not_executed(decoder, tmp_path):
    """A py/reduce payload must decode to nothing and execute nothing."""
    marker = tmp_path / "pwned"

    assert decoder._decode_session_user(_reduce_gadget(marker)) is None
    assert not marker.exists(), "session blob achieved code execution"


def test_jsonpickle_safe_flag_is_not_a_fix(tmp_path):
    """``jsonpickle.decode(..., safe=True)`` still runs py/reduce payloads.

    This is why the decoder parses the blob as data instead of reaching for
    the library's own guard rail. If a future jsonpickle release closes this,
    the test fails and the comment in ``_decode_session_user`` can be revisited
    — but the decoder should stay data-only regardless.
    """
    marker = tmp_path / "pwned_safe"
    try:
        jsonpickle.decode(_reduce_gadget(marker), safe=True)
    except Exception:  # pragma: no cover - behaviour differs across versions
        pass
    assert marker.exists(), (
        "jsonpickle safe=True now blocks py/reduce; "
        f"version={jsonpickle.__version__}"
    )


def test_legacy_jsonpickle_blob_round_trips(decoder):
    """Sessions written by earlier releases keep resolving to their owner."""
    encoded = jsonpickle.encode(
        OauthUser(
            user_id=42,
            username="alice",
            given_name="Alice",
            family_name="Smith",
            email="alice@example.com",
        )
    )
    user = decoder._decode_session_user(encoded)

    assert isinstance(user, OauthUser)
    assert user.user_id == 42
    assert user.username == "alice"
    assert user.given_name == "Alice"
    assert user.family_name == "Smith"
    assert user.email == "alice@example.com"


def test_plain_json_blob_round_trips(decoder):
    """A plain JSON object resolves, mapping first_name/last_name aliases."""
    user = decoder._decode_session_user(
        '{"user_id": "7", "username": "bob", "first_name": "Bob",'
        ' "last_name": "Jones", "email": "bob@example.com"}'
    )

    assert user.user_id == 7  # coerced to int
    assert user.given_name == "Bob"
    assert user.family_name == "Jones"


@pytest.mark.parametrize(
    "blob",
    [
        None,
        "",
        "not json",
        "[1, 2]",
        '"just-a-string"',
        '{"username": "no-id"}',
        '{"user_id": "not-an-int"}',
        '{"py/object": "subprocess.Popen", "args": ["true"]}',
        '{"__dict__": "not-a-mapping"}',
    ],
)
def test_malformed_blobs_return_none(decoder, blob):
    """Unusable blobs are rejected quietly — never raise, never authenticate."""
    assert decoder._decode_session_user(blob) is None
