"""Tests for the ``check_access(policy)`` decorator.

Covers the three supported handler shapes (bare function, class method and
class decorator), the allow/deny decisions taken from a named ABAC Policy,
and the fail-closed behaviour when the policy (or ABAC itself) is missing.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_auth.decorators import check_access
from navigator_auth.abac.policies import Policy, PolicyEffect

# navigator-auth stores its state on the app/request under plain string keys
# (``app['abac']``, ``request['authenticated']``, ...), which aiohttp only
# warns about; this project turns warnings into errors.
pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)


editors_policy = Policy(
    'post_articles',
    description="Allowing post actions to Editors",
    effect=PolicyEffect.ALLOW,
    actions=['article:create', 'article:update'],
    groups=['editors', 'superusers'],
    priority=2
)

public_policy = Policy(
    'view_articles',
    description="Allowing view to anyone",
    effect=PolicyEffect.ALLOW,
    actions=['article:view'],
    priority=1
)

admin_policy = Policy(
    'admin_articles',
    description="Allowing admin actions to Superusers",
    effect=PolicyEffect.ALLOW,
    actions=['article:admin'],
    groups=['superusers'],
    priority=3
)


class FakePDP:
    """Minimal PDP stub exposing the ``policies`` collection."""

    def __init__(self, policies):
        self._evaluator = None
        self._policies = policies

    @property
    def policies(self):
        return self._policies


def _make_request(
    method: str = "GET",
    authenticated: bool = True,
    pdp=None,
    path: str = "/articles",
):
    """Build a real (mocked-transport) aiohttp Request on a real Application."""
    app = web.Application()
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request(method, path, app=app)
    request["authenticated"] = authenticated
    return request


def _session(groups: list, username: str = "editor@example.com"):
    userinfo = {"username": username, "groups": groups, "email": username}
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value=userinfo)
    session.decode = MagicMock(return_value=None)
    return session


def _patch_session(session):
    return patch(
        "navigator_auth.decorators.get_session",
        new=AsyncMock(return_value=session),
    )


@pytest.fixture
def pdp():
    return FakePDP([editors_policy, public_policy, admin_policy])


# --------------------------------------------------------------------------
# Function-based handlers
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_function_handler_allowed(pdp):
    """A user in an allowed group passes the named policy."""

    @check_access('post_articles')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["editors"])):
        response = await handler(request)

    assert response.status == 200
    assert request["policy_response"].rule == 'post_articles'


@pytest.mark.asyncio
async def test_function_handler_denied(pdp):
    """A user outside the policy groups gets a 403."""

    @check_access('post_articles')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["viewers"])):
        with pytest.raises(web.HTTPForbidden):
            await handler(request)


@pytest.mark.asyncio
async def test_policy_without_groups_allows_everyone(pdp):
    """A policy with no group/subject restriction allows any user."""

    @check_access('view_articles')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(pdp=pdp)
    with _patch_session(_session(["anyone"])):
        response = await handler(request)

    assert response.status == 200


@pytest.mark.asyncio
async def test_unauthenticated_request_is_unauthorized(pdp):
    """An unauthenticated request never reaches policy evaluation."""

    @check_access('view_articles')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(pdp=pdp, authenticated=False)
    with pytest.raises(web.HTTPUnauthorized):
        await handler(request)


@pytest.mark.asyncio
async def test_options_method_bypasses_check(pdp):
    """OPTIONS (CORS preflight) is not evaluated, as in sibling decorators."""

    @check_access('admin_articles')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="OPTIONS", pdp=pdp, authenticated=False)
    response = await handler(request)
    assert response.status == 200


@pytest.mark.asyncio
async def test_unknown_policy_fails_closed(pdp):
    """A policy name not declared on the ABAC denies access."""

    @check_access('does_not_exist')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(pdp=pdp)
    with _patch_session(_session(["superusers"])):
        with pytest.raises(web.HTTPForbidden):
            await handler(request)


@pytest.mark.asyncio
async def test_missing_abac_fails_closed():
    """With no PDP registered on the Application, access is denied."""

    @check_access('view_articles')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request()
    with _patch_session(_session(["superusers"])):
        with pytest.raises(web.HTTPForbidden):
            await handler(request)


# --------------------------------------------------------------------------
# Several policies
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_any_policy_allows(pdp):
    """With a list of policies, any of them allowing grants access."""

    @check_access(['admin_articles', 'post_articles'])
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["editors"])):
        response = await handler(request)
    assert response.status == 200


@pytest.mark.asyncio
async def test_require_all_policies(pdp):
    """``require_all`` demands every policy to allow access."""

    @check_access(['admin_articles', 'post_articles'], require_all=True)
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["editors"])):
        with pytest.raises(web.HTTPForbidden):
            await handler(request)

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["superusers"])):
        response = await handler(request)
    assert response.status == 200


@pytest.mark.asyncio
async def test_action_not_covered_by_policy(pdp):
    """An action outside the policy actions is denied."""

    @check_access('post_articles', action='article:delete')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["editors"])):
        with pytest.raises(web.HTTPForbidden):
            await handler(request)


@pytest.mark.asyncio
async def test_action_covered_by_policy(pdp):
    """An action declared on the policy is allowed."""

    @check_access('post_articles', action='article:create')
    async def handler(request):
        return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    with _patch_session(_session(["editors"])):
        response = await handler(request)
    assert response.status == 200


# --------------------------------------------------------------------------
# Class-based views and class methods
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_decorating_a_view_method(pdp):
    """Decorating a single method of a view: request comes from self."""

    class ArticleView(web.View):
        @check_access('post_articles')
        async def post(self):
            return web.Response(text="ok")

    request = _make_request(method="POST", pdp=pdp)
    view = ArticleView(request)
    with _patch_session(_session(["editors"])):
        response = await view.post()
    assert response.status == 200

    view = ArticleView(_make_request(method="POST", pdp=pdp))
    with _patch_session(_session(["viewers"])):
        with pytest.raises(web.HTTPForbidden):
            await view.post()


@pytest.mark.asyncio
async def test_decorating_a_whole_view_class(pdp):
    """Decorating the class protects every HTTP method of the view."""

    @check_access('admin_articles')
    class AdminView(web.View):
        async def get(self):
            return web.Response(text="get")

        async def delete(self):
            return web.Response(text="delete")

    view = AdminView(_make_request(pdp=pdp))
    with _patch_session(_session(["superusers"])):
        response = await view.get()
    assert response.status == 200

    view = AdminView(_make_request(method="DELETE", pdp=pdp))
    with _patch_session(_session(["editors"])):
        with pytest.raises(web.HTTPForbidden):
            await view.delete()


@pytest.mark.asyncio
async def test_decorating_a_plain_class(pdp):
    """A non-view class gets its public coroutine methods protected."""

    @check_access('admin_articles')
    class Service:
        def __init__(self, request):
            self.request = request

        async def run(self):
            return "done"

        async def _private(self):
            return "private"

    service = Service(_make_request(pdp=pdp))
    with _patch_session(_session(["superusers"])):
        assert await service.run() == "done"

    service = Service(_make_request(pdp=pdp))
    with _patch_session(_session(["editors"])):
        with pytest.raises(web.HTTPForbidden):
            await service.run()
    # private methods are left untouched
    with _patch_session(_session(["editors"])):
        assert await service._private() == "private"
