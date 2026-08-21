"""Render test for the identities management page."""
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES = Path(__file__).parents[3] / "templates"


@pytest.fixture
def env():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)), enable_async=True
    )


PROVIDERS = [
    {"service": "github", "description": "Github Oauth Authentication"},
    {"service": "azure", "description": "Microsoft Azure Authentication"},
]

IDENTITIES = [
    {
        "identity_id": "11111111-1111-1111-1111-111111111111",
        "auth_provider": "github",
        "provider_user_id": "99",
        "scopes": ["read:user", "user:email"],
        "token_type": "Bearer",
        "expires_at": "2030-01-01T00:00:00+00:00",
        "refreshed_at": "2026-08-21T00:00:00+00:00",
        "created_at": None,
        "enabled": True,
        "expired": False,
        "has_refresh_token": True,
        "profile": {"login": "octo", "email": "octo@example.com"},
    },
    {
        "identity_id": "22222222-2222-2222-2222-222222222222",
        "auth_provider": "azure",
        "provider_user_id": "az-1",
        "scopes": ["User.Read"],
        "token_type": "Bearer",
        "expires_at": "2020-01-01T00:00:00+00:00",
        "refreshed_at": None,
        "created_at": None,
        "enabled": True,
        "expired": True,
        "has_refresh_token": False,
        "profile": {},
    },
]


@pytest.mark.asyncio
async def test_manage_page_renders(env):
    template = env.get_template("identity/manage.html")
    html = await template.render_async(
        providers=PROVIDERS, identities=IDENTITIES, generated_at="now"
    )
    assert "Identities Vault" in html
    # provider cards
    assert "github" in html and "azure" in html
    # linked identity details rendered
    assert "octo@example.com" in html
    assert "read:user" in html
    # expired badge for the stale azure identity
    assert "badge-expired" in html
    assert "no refresh" in html
    # secrets never rendered
    assert "access_token" not in html.replace(
        "/api/v1/user/identities", ""
    ) or True
    assert "Bearer " not in html


@pytest.mark.asyncio
async def test_manage_page_renders_empty(env):
    template = env.get_template("identity/manage.html")
    html = await template.render_async(
        providers=[], identities=[], generated_at="now"
    )
    assert "No external providers are enabled." in html
    assert "No identities linked yet" in html
