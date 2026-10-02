# ruff: noqa: F811
"""FEAT-101 TASK-90 — the software authenticator passes py_webauthn's real verifiers."""
import os

import pytest

webauthn = pytest.importorskip("webauthn")

from webauthn.helpers.exceptions import InvalidAuthenticationResponse  # noqa: E402

from tests.fixtures.passkey import passkey_rp_config, soft_authenticator  # noqa: F401,E402

ORIGIN, RP_ID = "https://a.test", "a.test"


def _register(auth, challenge):
    cred = auth.make_attestation(RP_ID, ORIGIN, challenge, user_handle=os.urandom(32))
    return webauthn.verify_registration_response(
        credential=cred, expected_challenge=challenge,
        expected_rp_id=RP_ID, expected_origin=ORIGIN,
    )


def test_attestation_roundtrip(soft_authenticator):
    """verify_registration_response accepts make_attestation output."""
    verified = _register(soft_authenticator, os.urandom(32))
    assert verified.credential_id == soft_authenticator.credential_id
    assert verified.sign_count == 0


def test_assertion_roundtrip(soft_authenticator):
    """verify_authentication_response accepts make_assertion output (UV on, count 1)."""
    verified = _register(soft_authenticator, os.urandom(32))
    challenge = os.urandom(32)
    cred = soft_authenticator.make_assertion(RP_ID, ORIGIN, challenge, sign_count=1)
    out = webauthn.verify_authentication_response(
        credential=cred, expected_challenge=challenge, expected_rp_id=RP_ID,
        expected_origin=ORIGIN, credential_public_key=verified.credential_public_key,
        credential_current_sign_count=0, require_user_verification=True,
    )
    assert out.new_sign_count == 1 and out.user_verified is True


def test_assertion_without_uv_rejected_when_required(soft_authenticator):
    """require_user_verification=True rejects uv=False."""
    verified = _register(soft_authenticator, os.urandom(32))
    challenge = os.urandom(32)
    cred = soft_authenticator.make_assertion(RP_ID, ORIGIN, challenge, sign_count=1, uv=False)
    with pytest.raises(InvalidAuthenticationResponse):
        webauthn.verify_authentication_response(
            credential=cred, expected_challenge=challenge, expected_rp_id=RP_ID,
            expected_origin=ORIGIN, credential_public_key=verified.credential_public_key,
            credential_current_sign_count=0, require_user_verification=True,
        )


def test_rp_config_fixture(passkey_rp_config):
    import navigator_auth.conf as conf

    assert conf.PASSKEY_RELYING_PARTIES[1]["org_id"] == 7
