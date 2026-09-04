"""Tests for FEAT-097 Module 3: AbstractSAMLBackend SP-initiated and
unsolicited login, ACS, metadata (TASK-056).
"""
from unittest.mock import AsyncMock

import pytest

#: The committed SAML fixtures (idp-metadata.xml/sp-metadata.xml entity IDs)
#: are baked in with "https"; the `sp_backend`/`force_https_scheme` fixture
#: (conftest.py) forces `get_domain()` to agree regardless of this
#: environment's own `PREFERRED_AUTH_SCHEME` (this sandbox's `env/dev/.env`
#: sets "http") — every URL built here must match.
SCHEME = "https"


def _mock_validate_user_info(backend, token="tok-123"):
    backend.validate_user_info = AsyncMock(
        return_value={"token": token, "refresh_token": None, "type": "Bearer", "expires_in": 3600}
    )


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_authenticate_sets_flow(sp_backend, redis_stub):
    from aiohttp.test_utils import make_mocked_request

    request = make_mocked_request(
        "GET", f"{SCHEME}://sp.example.com/api/v1/auth/saml/", headers={"Host": "sp.example.com"}
    )
    resp = await sp_backend.authenticate(request)
    assert resp.status == 302
    assert any(k.startswith("saml_req_") for k in redis_stub.keys())


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_solicited_ok(sp_backend, signed_response, post_request, redis_stub):
    _mock_validate_user_info(sp_backend)
    relay = "relay-solicited"
    await redis_stub.set(
        sp_backend.core.req_key(relay),
        {"request_id": "req-1", "internal_redirect": None, "acs_url": "x", "oauth2_flow": None},
        ttl=600,
    )
    saml_response = signed_response(in_response_to="req-1")
    request = post_request({"SAMLResponse": saml_response, "RelayState": relay})
    resp = await sp_backend.auth_callback(request)
    assert resp.status == 302
    assert "error=" not in resp.headers.get("Location", "")


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_in_response_to_mismatch(sp_backend, signed_response, post_request, redis_stub):
    relay = "relay-mismatch"
    await redis_stub.set(
        sp_backend.core.req_key(relay),
        {"request_id": "req-expected", "internal_redirect": None, "acs_url": "x", "oauth2_flow": None},
        ttl=600,
    )
    saml_response = signed_response(in_response_to="req-actually-different")
    request = post_request({"SAMLResponse": saml_response, "RelayState": relay})
    resp = await sp_backend.auth_callback(request)
    assert resp.status == 302
    assert "error=SAML_INVALID_RESPONSE" in resp.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_stale_request(sp_backend, signed_response, post_request):
    # InResponseTo present but no flow record stored (never requested / expired).
    saml_response = signed_response(in_response_to="req-none-stored")
    request = post_request({"SAMLResponse": saml_response, "RelayState": "no-such-relay"})
    resp = await sp_backend.auth_callback(request)
    assert resp.status == 302
    assert "error=SAML_STALE_REQUEST" in resp.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_unsolicited_ok_then_replay(sp_backend, signed_response, post_request):
    _mock_validate_user_info(sp_backend)
    saml_response = signed_response(in_response_to=None)
    first = await sp_backend.auth_callback(
        post_request({"SAMLResponse": saml_response, "RelayState": ""})
    )
    assert "error=" not in first.headers.get("Location", "")
    second = await sp_backend.auth_callback(
        post_request({"SAMLResponse": saml_response, "RelayState": ""})
    )
    assert "error=SAML_REPLAY" in second.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_unsolicited_disabled(sp_backend, signed_response, post_request, monkeypatch):
    monkeypatch.setattr("navigator_auth.backends.saml.sp.SAML_ALLOW_UNSOLICITED", False)
    saml_response = signed_response(in_response_to=None)
    request = post_request({"SAMLResponse": saml_response, "RelayState": ""})
    resp = await sp_backend.auth_callback(request)
    assert "error=SAML_FORBIDDEN" in resp.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_bad_signature(sp_backend, signed_response, post_request, redis_stub):
    relay = "relay-tampered"
    await redis_stub.set(
        sp_backend.core.req_key(relay),
        {"request_id": "req-tampered", "internal_redirect": None, "acs_url": "x", "oauth2_flow": None},
        ttl=600,
    )
    saml_response = signed_response(in_response_to="req-tampered")
    import base64

    xml = base64.b64decode(saml_response).decode("utf-8")
    tampered = xml.replace("auser", "attacker")
    tampered_b64 = base64.b64encode(tampered.encode("utf-8")).decode("utf-8")
    request = post_request({"SAMLResponse": tampered_b64, "RelayState": relay})
    resp = await sp_backend.auth_callback(request)
    assert resp.status == 302
    assert "error=" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_sp_callback_get_405(sp_backend):
    from aiohttp.test_utils import make_mocked_request

    request = make_mocked_request(
        "GET", f"{SCHEME}://sp.example.com/auth/saml/callback/", headers={"Host": "sp.example.com"}
    )
    resp = await sp_backend.auth_callback(request)
    assert resp.status == 405


@pytest.mark.asyncio
async def test_sp_dispatch_reads_post_relaystate(sp_backend, post_request):
    request = post_request({"SAMLResponse": "irrelevant", "RelayState": "abc"})
    assert await sp_backend.get_callback_state(request) == "abc"


@pytest.mark.asyncio
async def test_sp_metadata_valid(sp_backend):
    from aiohttp.test_utils import make_mocked_request

    request = make_mocked_request(
        "GET", f"{SCHEME}://sp.example.com/auth/saml/metadata", headers={"Host": "sp.example.com"}
    )
    resp = await sp_backend.metadata(request)
    assert resp.status == 200
    assert "EntityDescriptor" in resp.text
    assert f"{SCHEME}://sp.example.com/auth/saml/callback/" in resp.text


@pytest.mark.asyncio
async def test_sp_check_credentials_true(sp_backend):
    assert await sp_backend.check_credentials(None) is True


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_authorize_hook_denies(sp_backend, signed_response, post_request):
    sp_backend.authorize = AsyncMock(return_value=False)
    saml_response = signed_response(in_response_to=None)
    request = post_request({"SAMLResponse": saml_response, "RelayState": ""})
    resp = await sp_backend.auth_callback(request)
    assert "error=SAML_FORBIDDEN" in resp.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_sp_acs_relaystate_offhost(sp_backend, signed_response, post_request, redis_stub):
    """An off-host `internal_redirect` in the flow record is dropped
    (validate_redirect_host); login still succeeds, falling back to the
    default finish-redirect."""
    _mock_validate_user_info(sp_backend)
    relay = "relay-offhost"
    await redis_stub.set(
        sp_backend.core.req_key(relay),
        {
            "request_id": "req-offhost",
            "internal_redirect": "https://evil.test/steal",
            "acs_url": "x",
            "oauth2_flow": None,
        },
        ttl=600,
    )
    saml_response = signed_response(in_response_to="req-offhost")
    request = post_request({"SAMLResponse": saml_response, "RelayState": relay})
    resp = await sp_backend.auth_callback(request)
    assert resp.status == 302
    assert "evil.test" not in resp.headers["Location"]
