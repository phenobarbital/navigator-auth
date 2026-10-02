# ruff: noqa: F811
"""FEAT-101 TASK-97 — R5: a BasicAuth.open_session session is readable by the OAuth2 provider."""

import logging

import jsonpickle
import pytest
from navigator_session import AUTH_SESSION_OBJECT

from tests.fixtures.passkey import passkey_app  # noqa: F401

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]


async def test_passkey_session_decodes_for_oauth2(passkey_app):
    """The ``user`` blob that ``remember()`` writes (via ``open_session``) resolves in
    ``Oauth2Provider._decode_session_user`` to the same user — so the authorize hop works
    after a passkey login without any OAuth2 change."""
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    backend = passkey_app.backend
    user = await backend._idp.user_from_id(passkey_app.user_id)
    # Same construction as BasicAuth.open_session()
    userdata = backend.get_userdata(user=user)
    username = user[backend.username_attribute]
    usr = await backend.create_user(userdata[AUTH_SESSION_OBJECT])
    usr.id = user[backend.userid_attribute]
    usr.set(backend.username_attribute, username)
    blob = jsonpickle.encode(usr)  # what SessionData.save_encoded_data stores under "user"

    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = logging.getLogger("test.oauth2.passkey")
    resolved = provider._decode_session_user(blob)
    assert resolved is not None, "R5: the remember() envelope is not readable by OAuth2"
    assert resolved.user_id == passkey_app.user_id
    assert resolved.username == passkey_app.username
