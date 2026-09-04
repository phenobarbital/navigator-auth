"""Unit tests for FEAT-096 TASK-051: GithubAuth.verify_external_token +
real check_credentials.

Mocks `GithubAuth.post`/`get` (GitHub's "check a token" endpoint, `/user`,
`/user/emails`) — no real network calls.
"""
from unittest.mock import AsyncMock

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.github import GithubAuth
from navigator_auth.exceptions import AuthException, InvalidAuth

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture
def backend():
    be = GithubAuth(user_model=object)
    return be


def _check_response(
    *,
    user_id=123,
    login="octocat",
    email="octocat@example.com",
    scopes=None,
    expires_at=None,
) -> dict:
    return {
        "user": {"id": user_id, "login": login, "email": email},
        "scopes": scopes or ["read:user", "user:email"],
        "expires_at": expires_at,
    }


# ---------------------------------------------------------------------------
# _check_app_token / verify_external_token — happy paths
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_app_token_ok_classic(backend):
    """Classic OAuth token: 200, no `expires_at` in the response."""
    backend.post = AsyncMock(return_value=_check_response())
    userinfo, normalized = await backend.verify_external_token("classic-token")
    assert userinfo["id"] == 123
    assert normalized.provider_user_id == "123"
    assert normalized.expires_at is None
    assert normalized.scopes == ["read:user", "user:email"]
    backend.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_app_token_ok_github_app(backend):
    """GitHub App user-to-server token: 200, `expires_at` present."""
    backend.post = AsyncMock(
        return_value=_check_response(expires_at="2030-01-01T00:00:00Z")
    )
    userinfo, normalized = await backend.verify_external_token("app-token")
    assert normalized.expires_at is not None
    assert normalized.expires_at.year == 2030


# ---------------------------------------------------------------------------
# _check_app_token — failure modes
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_foreign_token_404(backend):
    backend.post = AsyncMock(
        side_effect=AuthException("{'message': 'Not Found', 'documentation_url': 'x'}")
    )
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("foreign-token")
    assert "wrong_audience" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_bad_client_credentials_401(backend):
    backend.post = AsyncMock(
        side_effect=AuthException("{'message': 'Bad credentials', 'documentation_url': 'x'}")
    )
    with pytest.raises(AuthException) as exc:
        await backend.verify_external_token("any-token")
    assert exc.value.status == 500


# ---------------------------------------------------------------------------
# E-mail verification tightening
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_requires_verified_primary_email(backend):
    """user.email empty -> get_github_email(verified_only=True); none
    found -> InvalidAuth('email_unverified')."""
    backend.post = AsyncMock(return_value=_check_response(email=None))
    backend.get_github_email = AsyncMock(return_value=None)
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("token-no-public-email")
    assert "email_unverified" in str(exc.value)
    backend.get_github_email.assert_awaited_once_with("token-no-public-email", verified_only=True)


@pytest.mark.asyncio
async def test_missing_email_falls_back_to_verified_primary(backend):
    backend.post = AsyncMock(return_value=_check_response(email=None))
    backend.get_github_email = AsyncMock(return_value="verified@example.com")
    userinfo, normalized = await backend.verify_external_token("token-no-public-email")
    assert userinfo["email"] == "verified@example.com"
    assert normalized.provider_user_id == "123"


@pytest.mark.asyncio
async def test_get_github_email_verified_only_does_not_fallback_to_first(backend):
    """Regression for the tightened fallback: with verified_only=True, a
    non-primary/unverified-only email list yields None (unlike the
    login-callback path's default behaviour)."""
    backend.get = AsyncMock(
        return_value=[{"email": "unverified@example.com", "primary": False, "verified": False}]
    )
    email = await backend.get_github_email("token", verified_only=True)
    assert email is None
    # Unchanged default behaviour (login-callback path): falls back to first.
    email = await backend.get_github_email("token", verified_only=False)
    assert email == "unverified@example.com"


# ---------------------------------------------------------------------------
# check_credentials no longer returns True unconditionally
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_check_credentials_rejects_foreign_token(backend):
    backend.post = AsyncMock(
        side_effect=AuthException("{'message': 'Not Found', 'documentation_url': 'x'}")
    )
    request = make_mocked_request(
        "GET", "/auth/github/check_credentials",
        headers={"Authorization": "Bearer foreign-token"},
    )
    response = await backend.check_credentials(request)
    assert response is not True
    assert response.status == 401


@pytest.mark.asyncio
async def test_check_credentials_no_longer_stub_true(backend):
    backend.post = AsyncMock(side_effect=RuntimeError("network down"))
    request = make_mocked_request(
        "GET", "/auth/github/check_credentials",
        headers={"Authorization": "Bearer some-token"},
    )
    response = await backend.check_credentials(request)
    assert response is not True
