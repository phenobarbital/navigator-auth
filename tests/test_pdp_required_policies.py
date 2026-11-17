"""PDP policy storage defaults and the required-policy startup check.

Covers the fixes for the ``/api/v1/groups`` 500 (navigator_auth 0.29.1):

* handlers declare the ABAC policies they need and ``PDP.on_startup`` warns
  about the ones that are not loaded;
* the PDP never picks a YAML storage on its own (an auto-loaded YAML policy
  could shadow a same-name DB policy in the by-name lookup);
* end to end: with ``auth_crud_admin_access.yaml`` loaded through
  ``yaml_storage=`` a superuser is allowed ``group:read`` on ``/api/v1/groups``.
"""

import logging
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac import pdp as pdp_module
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.required_policies import REQUIRED_POLICIES_KEY, require_policy, required_policies
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.decorators import policy_allows

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

PACKS = Path(__file__).resolve().parents[1] / "navigator_auth" / "abac" / "default_policies"
CRUD_PACK = PACKS / "auth_crud_admin_access.yaml"


def _storage() -> MagicMock:
    storage = MagicMock()
    storage.load_policies = AsyncMock(return_value=[])
    storage.close = AsyncMock()
    return storage


# ---------------------------------------------------------------------------
# require_policy registry
# ---------------------------------------------------------------------------


def test_require_policy_accumulates_dependants():
    app = web.Application()
    require_policy(app, "groups_admin_access", "/api/v1/groups")
    require_policy(app, "groups_admin_access", "/api/v1/other")
    assert required_policies(app) == {"groups_admin_access": {"/api/v1/groups", "/api/v1/other"}}


def test_required_policies_is_a_copy():
    app = web.Application()
    require_policy(app, "groups_admin_access", "/api/v1/groups")
    required_policies(app)["groups_admin_access"].add("mutated")
    assert app[REQUIRED_POLICIES_KEY]["groups_admin_access"] == {"/api/v1/groups"}


def test_require_policy_rejects_empty_name():
    with pytest.raises(ValueError):
        require_policy(web.Application(), "", "/api/v1/groups")


def test_setup_handlers_declares_every_admin_policy():
    from navigator_auth.handlers import setup_handlers

    app = web.Application()
    app[AUTH_EXCLUDE_LIST_KEY] = []
    setup_handlers(app, app.router)
    declared = required_policies(app)
    assert {
        "permissions_admin_access",
        "groups_admin_access",
        "user_groups_admin_access",
        "group_permissions_admin_access",
        "users_admin_access",
        "users_grant_role",
        "user_accounts_admin_access",
        "partner_keys_admin_access",
        "user_identities_admin_access",
    } <= set(declared)
    assert "/api/v1/groups" in declared["groups_admin_access"]


# ---------------------------------------------------------------------------
# YAML storage is opt-in
# ---------------------------------------------------------------------------


def test_pdp_does_not_load_policy_storage_dir_on_its_own(tmp_path):
    shutil.copy(CRUD_PACK, tmp_path / CRUD_PACK.name)
    with patch.object(pdp_module, "POLICY_STORAGE_DIR", str(tmp_path)):
        assert PDP(storage=_storage()).yaml_storage is None


# ---------------------------------------------------------------------------
# Startup warning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_startup_warns_about_missing_required_policy(caplog):
    app = web.Application()
    require_policy(app, "groups_admin_access", "/api/v1/groups")
    pdp = PDP(storage=_storage())
    with caplog.at_level(logging.WARNING):
        await pdp.on_startup(app)
    assert pdp.missing_required_policies(app) == {"groups_admin_access": {"/api/v1/groups"}}
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("groups_admin_access" in msg and "/api/v1/groups" in msg for msg in warnings)


@pytest.mark.asyncio
async def test_on_startup_loads_pack_from_yaml_storage(tmp_path):
    shutil.copy(CRUD_PACK, tmp_path / CRUD_PACK.name)
    app = web.Application()
    app[AUTH_EXCLUDE_LIST_KEY] = []
    from navigator_auth.handlers import setup_handlers

    setup_handlers(app, app.router)
    pdp = PDP(storage=_storage(), yaml_storage=YAMLStorage(directory=tmp_path))
    await pdp.on_startup(app)
    missing = pdp.missing_required_policies(app)
    for name in ("groups_admin_access", "user_groups_admin_access", "users_admin_access", "users_grant_role"):
        assert name not in missing
    # auth_model_admin_access.yaml was not copied: its policies stay missing.
    assert "user_identities_admin_access" in missing

    app["abac"] = pdp
    request = make_mocked_request("GET", "/api/v1/groups", app=app)
    request["authenticated"] = True
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={"username": "root", "groups": ["superuser"]})
    session.decode = MagicMock(return_value=None)
    with patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)):
        allowed, reason, _ = await policy_allows(
            "groups_admin_access", request, action="group:read", resource=request.path
        )
    assert allowed is True, reason
