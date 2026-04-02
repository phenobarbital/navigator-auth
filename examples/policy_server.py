"""
Policy-Based Access Control (PBAC) Example Server.

Demonstrates how to set up an aiohttp server with:
- Guardian (PEP) + PDP infrastructure
- PolicyEvaluator with default policy packs
- Custom ResourcePolicy definitions
- REST /check endpoint for external policy decisions
- Decorated views with @groups_protected and @requires_permission
- Classic ABAC policies (URI, Object, File-based)
- Simple login form with BasicAuth authentication

Run:
    python examples/policy_server.py

Then test with:
    # Open browser to http://localhost:5000/ (redirects to login if not authenticated)

    # Check endpoint (no auth required for the REST decision API)
    curl -X POST http://localhost:5000/api/v1/abac/check \
        -H "Content-Type: application/json" \
        -d '{"user":"alice@acme.com","resource":"tool:jira_create","action":"tool:execute","groups":["engineering"]}'

    # Tools listing (requires auth in real setup)
    curl http://localhost:5000/api/v1/tools/

Environment variables for audit logging:
    AUDIT_BACKEND=log       Use Python logger (default for this example)
    AUDIT_BACKEND=influx    Use InfluxDB (requires INFLUX_* env vars)
    AUDIT_BACKEND=mongo     Use MongoDB (requires AUDIT_DSN)
    AUDIT_BACKEND=pg        Use PostgreSQL (requires AUDIT_DSN)
"""
import os
from pathlib import Path

# Default to file-based audit logging for the example server
os.environ.setdefault("AUDIT_BACKEND", "log")

import aiohttp
from aiohttp import web
from navigator.views import BaseView
from navigator_auth import AuthHandler
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.guardian import Guardian
from navigator_auth.abac.decorators import groups_protected, requires_permission
from navigator_auth.abac.storages.pg import pgStorage
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.abac.policies import Policy, PolicyEffect, ObjectPolicy
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.resources import ResourceType, ActionType
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyLoader
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.conf import default_dsn


# ---------------------------------------------------------------------------
# 1. Custom ResourcePolicy definitions (programmatic)
# ---------------------------------------------------------------------------

# Data-science team can search and insert vectors during business hours
data_science_vectors = ResourcePolicy(
    name="data_science_vectors",
    description="Data-science team can search/insert vectors during business hours",
    effect=PolicyEffect.ALLOW,
    resources=["vector:*"],
    actions=["vector:search", "vector:insert"],
    subjects={"groups": ["data_science", "ml_engineers"]},
    environment={"is_business_hours": True},
    priority=25,
)

# QA team can only list and execute specific testing tools
qa_testing_tools = ResourcePolicy(
    name="qa_testing_tools",
    description="QA team can execute testing and CI tools",
    effect=PolicyEffect.ALLOW,
    resources=["tool:selenium_*", "tool:cypress_*", "tool:pytest_*", "tool:postman_*"],
    actions=["tool:execute", "tool:list"],
    subjects={"groups": ["qa", "quality_assurance"]},
    priority=20,
)

# Deny vector deletion to everyone except admins (enforcing)
deny_vector_delete = ResourcePolicy(
    name="deny_vector_delete_non_admin",
    description="Only admins can delete vectors",
    effect=PolicyEffect.DENY,
    resources=["vector:*"],
    actions=["vector:delete"],
    subjects={
        "groups": ["*"],
        "exclude_groups": ["admin", "superuser"],
    },
    priority=90,
    enforcing=True,
)

# Allow all authenticated users to chat with agents (read-only)
agent_chat_all = ResourcePolicy(
    name="agent_chat_all_users",
    description="Any authenticated user can chat with AI agents",
    effect=PolicyEffect.ALLOW,
    resources=["agent:*"],
    actions=["agent:chat", "agent:query"],
    subjects={"groups": ["*"]},
    priority=10,
)

# Restrict agent configuration to platform team
agent_configure_platform = ResourcePolicy(
    name="agent_configure_platform",
    description="Only platform team can configure agents",
    effect=PolicyEffect.ALLOW,
    resources=["agent:*"],
    actions=["agent:configure"],
    subjects={"groups": ["platform", "superuser"]},
    priority=40,
)


# ---------------------------------------------------------------------------
# 2. Classic ABAC policies (URI and Object-based)
# ---------------------------------------------------------------------------

# Grant access to the public dashboard for all users
public_dashboard = Policy(
    name="public_dashboard",
    effect=PolicyEffect.ALLOW,
    description="Public dashboard accessible to everyone",
    resource=["urn:uri:/dashboard/"],
    priority=5,
)

# Restrict admin panel to superusers and admins
admin_panel = Policy(
    name="admin_panel_access",
    effect=PolicyEffect.ALLOW,
    description="Admin panel restricted to superuser and admin groups",
    resource=["urn:uri:/admin.*$"],
    groups=["superuser", "admin"],
    priority=50,
    enforcing=True,
)

# Time-restricted access: analytics only during business hours (Mon-Fri, 8-18)
analytics_business_hours = Policy(
    name="analytics_business_hours",
    effect=PolicyEffect.ALLOW,
    description="Analytics endpoints available only during business hours",
    resource=["urn:uri:/api/v1/analytics.*$"],
    groups=["analytics", "data_science", "superuser"],
    environment={
        "hour": list(range(8, 19)),
        "day_of_week": list(range(0, 5)),  # Mon-Fri
    },
    priority=20,
)

# Object policy: only senior engineers can approve deployments
deployment_approval = ObjectPolicy(
    name="deployment_approval",
    effect=PolicyEffect.ALLOW,
    description="Only senior engineers and leads can approve deployments",
    actions=["deployment:approve"],
    resource=["urn:navigator:deployment::*"],
    groups=["senior_engineers", "tech_leads", "superuser"],
    priority=60,
)

# Object policy: specific user can manage production configs
prod_config_manager = ObjectPolicy(
    name="prod_config_manager",
    effect=PolicyEffect.ALLOW,
    description="Platform lead manages production configurations",
    actions=["config:edit", "config:deploy"],
    resource=["urn:navigator:config::production"],
    context={"username": "platform-lead@acme.com"},
    priority=55,
)


# ---------------------------------------------------------------------------
# 3. Login Form & Auth Helpers
# ---------------------------------------------------------------------------

LOGIN_HTML = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login — PBAC Example</title>
  <style>
    body {{ font-family: sans-serif; display: flex; justify-content: center;
           align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }}
    .card {{ background: #fff; padding: 2rem; border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,.12); width: 320px; }}
    h2 {{ margin-top: 0; }}
    label {{ display: block; margin-top: 1rem; font-size: .9rem; }}
    input {{ width: 100%%; padding: .5rem; margin-top: .25rem;
            box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }}
    button {{ margin-top: 1.5rem; width: 100%%; padding: .6rem;
             background: #1a73e8; color: #fff; border: none;
             border-radius: 4px; cursor: pointer; font-size: 1rem; }}
    button:hover {{ background: #1558b0; }}
    .error {{ color: #d32f2f; margin-top: 1rem; font-size: .85rem; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Login</h2>
    {error}
    <form method="post" action="/login">
      <label>Username
        <input name="username" type="text" required autofocus>
      </label>
      <label>Password
        <input name="password" type="password" required>
      </label>
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>
"""

INDEX_HTML = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PBAC Example Server</title>
  <style>
    body {{ font-family: sans-serif; max-width: 700px; margin: 2rem auto;
           padding: 0 1rem; }}
    h1 {{ color: #1a73e8; }}
    ul {{ line-height: 1.8; }}
    a {{ color: #1a73e8; }}
    .logout {{ margin-top: 2rem; }}
  </style>
</head>
<body>
  <h1>PBAC Example Server</h1>
  <p>Authenticated as <strong>{username}</strong></p>
  <h3>Endpoints</h3>
  <ul>
    <li><a href="/dashboard/">GET /dashboard/</a> — Public dashboard</li>
    <li><a href="/admin/">GET /admin/</a> — Admin panel (superuser/admin)</li>
    <li><a href="/api/v1/tools/">GET /api/v1/tools/</a> — Tools listing</li>
    <li><a href="/api/v1/analytics/">GET /api/v1/analytics/</a> — Analytics (business hours)</li>
    <li><a href="/api/v1/deployments/">GET /api/v1/deployments/</a> — Deployments</li>
    <li><a href="/api/v1/agents/">GET /api/v1/agents/</a> — AI Agent chat</li>
    <li>POST /api/v1/abac/check — REST policy decision endpoint</li>
  </ul>
  <div class="logout"><a href="/logout">Logout</a></div>
</body>
</html>
"""

# Cookie name for storing the bearer token
AUTH_COOKIE = "bearer_token"


def _get_token_from_request(request: web.Request) -> str | None:
    """Extract bearer token from cookie."""
    return request.cookies.get(AUTH_COOKIE)


@web.middleware
async def cookie_to_bearer_middleware(request: web.Request, handler):
    """Copy the bearer token from cookie into the Authorization header.

    This allows browser-based navigation (cookie auth) to work with the
    auth middleware that expects an Authorization header.

    Note: request.clone() drops _match_info, so we restore it after cloning.
    """
    if "Authorization" not in request.headers:
        token = request.cookies.get(AUTH_COOKIE)
        if token:
            match_info = request._match_info
            request = request.clone(
                headers={**request.headers, "Authorization": f"Bearer {token}"}
            )
            request._match_info = match_info
    return await handler(request)


# ---------------------------------------------------------------------------
# 4. Example Views
# ---------------------------------------------------------------------------

class DashboardView(BaseView):
    """Public dashboard - accessible to all authenticated users."""

    async def get(self):
        guardian = self.request.app['security']
        result = await guardian.authorize(request=self.request)
        return self.json_response({
            "view": "dashboard",
            "message": "Welcome to the public dashboard",
            "policy": result.rule if result else "none",
        })


@groups_protected(groups=["superuser", "admin"])
class AdminView(BaseView):
    """Admin panel - restricted to superuser and admin groups."""

    async def get(self):
        return self.json_response({
            "view": "admin",
            "message": "Admin panel access granted",
        })

    async def post(self):
        return self.json_response({
            "view": "admin",
            "message": "Admin action executed",
        })


class ToolsView(BaseView):
    """Tools listing - demonstrates resource filtering."""

    async def get(self):
        """List tools the current user can execute."""
        guardian = self.request.app['security']

        # Simulate a list of available tools
        all_tools = [
            "jira_create", "jira_search", "github_pr",
            "github_actions", "confluence_page", "jenkins_build",
            "selenium_run", "cypress_test", "pytest_suite",
            "sonarqube_scan", "postman_collection",
        ]

        # Use the PolicyEvaluator to filter tools by permission
        evaluator = getattr(self.request.app.get('abac'), '_evaluator', None)
        if evaluator:
            from navigator_auth.abac.context import EvalContext

            session, user = await guardian.get_user(self.request)
            try:
                from navigator_auth.conf import AUTH_SESSION_OBJECT
                userinfo = session[AUTH_SESSION_OBJECT]
            except (KeyError, TypeError):
                userinfo = {"username": "anonymous", "groups": []}

            ctx = EvalContext.__new__(EvalContext)
            ctx.userinfo = userinfo

            filtered = evaluator.filter_resources(
                ctx=ctx,
                resource_type=ResourceType.TOOL,
                resource_names=all_tools,
                action=ActionType.TOOL_EXECUTE.value,
            )
            return self.json_response({
                "allowed_tools": filtered.allowed,
                "denied_tools": filtered.denied,
                "policies_applied": filtered.policies_applied,
            })

        return self.json_response({"tools": all_tools, "note": "no evaluator"})


class AnalyticsView(BaseView):
    """Analytics - time-restricted access."""

    async def get(self):
        guardian = self.request.app['security']
        result = await guardian.authorize(request=self.request)
        env = Environment()
        return self.json_response({
            "view": "analytics",
            "business_hours": env.is_business_hours,
            "day_segment": env.day_segment.name,
            "policy": result.rule if result else "none",
        })


class DeploymentView(BaseView):
    """Deployment management - object-level permissions."""

    async def get(self):
        """List deployments."""
        return self.json_response({
            "deployments": [
                {"id": "deploy-001", "env": "staging", "status": "pending"},
                {"id": "deploy-002", "env": "production", "status": "pending"},
            ]
        })

    async def post(self):
        """Approve a deployment - requires deployment:approve action."""
        guardian = self.request.app['security']
        result = await guardian.is_allowed(
            request=self.request,
            action="deployment:approve",
            resource=["urn:navigator:deployment::deploy-002"],
        )
        if result.effect:
            return self.json_response({
                "message": "Deployment approved",
                "policy": result.rule,
            })
        return self.json_response(
            {"error": "Not authorized to approve deployments"},
            status=403
        )


class AgentView(BaseView):
    """AI Agent interaction - tiered access."""

    async def get(self):
        """Chat with an agent (allowed for all authenticated users)."""
        evaluator = getattr(self.request.app.get('abac'), '_evaluator', None)
        if evaluator:
            from navigator_auth.abac.context import EvalContext

            ctx = EvalContext.__new__(EvalContext)
            ctx.userinfo = {"username": "demo", "groups": ["engineering"]}

            result = evaluator.check_access(
                ctx=ctx,
                resource_type=ResourceType.AGENT,
                resource_name="support_bot",
                action=ActionType.AGENT_CHAT.value,
            )
            return self.json_response({
                "agent": "support_bot",
                "allowed": result.allowed,
                "policy": result.matched_policy,
                "cached": result.cached,
                "eval_time_ms": round(result.evaluation_time_ms, 3),
            })

        return self.json_response({"agent": "support_bot", "status": "no evaluator"})


# ---------------------------------------------------------------------------
# 4. Application setup
# ---------------------------------------------------------------------------

async def index(request):
    """Index page — redirects to /login if no valid token cookie."""
    token = _get_token_from_request(request)
    if not token:
        return web.Response(status=302, headers={"Location": "/login"})

    # Decode the JWT locally to extract the username
    try:
        auth_handler = request.app["auth"]
        _, payload = auth_handler._idp.decode_token(token)
        if not payload:
            return web.Response(status=302, headers={"Location": "/login"})
        username = payload.get("username", payload.get("sub", "authenticated"))
    except Exception:
        return web.Response(status=302, headers={"Location": "/login"})

    body = INDEX_HTML.format(username=username)
    return web.Response(text=body, content_type="text/html")


async def login_page(request):
    """GET /login — render the login form."""
    # If already has a token, redirect to index
    if _get_token_from_request(request):
        return web.Response(status=302, headers={"Location": "/"})
    body = LOGIN_HTML.format(error="")
    return web.Response(text=body, content_type="text/html")


async def login_submit(request):
    """POST /login — authenticate via the API and store token in a cookie."""
    form = await request.post()
    username = form.get("username", "")
    password = form.get("password", "")

    if not username or not password:
        body = LOGIN_HTML.format(
            error='<p class="error">Username and password are required.</p>'
        )
        return web.Response(text=body, content_type="text/html")

    # Call the auth API using BasicAuth
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://localhost:5000/api/v1/login",
                json={"username": username, "password": password},
                headers={
                    "x-auth-method": "BasicAuth",
                    "Accept": "application/json",
                },
            ) as resp:
                data = await resp.json()
                if resp.status != 200 or "token" not in data:
                    msg = data.get("message", data.get("error", "Login failed"))
                    body = LOGIN_HTML.format(
                        error=f'<p class="error">{msg}</p>'
                    )
                    return web.Response(text=body, content_type="text/html")

                token = data["token"]
    except Exception as exc:
        body = LOGIN_HTML.format(
            error=f'<p class="error">Auth service error: {exc}</p>'
        )
        return web.Response(text=body, content_type="text/html")

    # Set token cookie and redirect to index
    response = web.Response(status=302, headers={"Location": "/"})
    response.set_cookie(
        AUTH_COOKIE, token, httponly=True, samesite="Lax", path="/"
    )
    return response


async def logout(request):
    """GET /logout — clear the token cookie and redirect to login."""
    response = web.Response(status=302, headers={"Location": "/login"})
    response.del_cookie(AUTH_COOKIE, path="/")
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[cookie_to_bearer_middleware])

    # --- Auth system ---
    auth = AuthHandler()
    auth.setup(app)

    # Exclude pages that don't require authentication
    auth.add_exclude_list("/")
    auth.add_exclude_list("/login")
    auth.add_exclude_list("/logout")

    # --- Policy storage ---
    storage = pgStorage(dsn=default_dsn)

    # Optionally load YAML policies from the default policy packs
    default_policies_dir = (
        Path(__file__).resolve().parent.parent
        / "navigator_auth" / "abac" / "default_policies"
    )
    yaml_storage = None
    if default_policies_dir.is_dir():
        yaml_storage = YAMLStorage(directory=str(default_policies_dir))

    # --- PDP (Policy Decision Point) ---
    pdp = PDP(storage=storage, yaml_storage=yaml_storage)

    # Add classic ABAC policies
    for policy in [
        public_dashboard,
        admin_panel,
        analytics_business_hours,
        deployment_approval,
        prod_config_manager,
    ]:
        pdp.add_policy(policy)

    # --- PolicyEvaluator (high-performance resource-based evaluation) ---
    evaluator = PolicyEvaluator(
        default_effect=PolicyEffect.DENY,
        cache_size=1024,
        cache_ttl_seconds=300,
    )

    # Load default policy packs into the evaluator
    if default_policies_dir.is_dir():
        evaluator.load_from_directory(default_policies_dir)

    # Load custom ResourcePolicies
    evaluator.load_policies([
        data_science_vectors,
        qa_testing_tools,
        deny_vector_delete,
        agent_chat_all,
        agent_configure_platform,
    ])

    # Attach evaluator to PDP so the /check endpoint can use it
    pdp._evaluator = evaluator

    # Wire up PDP (registers Guardian, middleware, REST endpoints)
    pdp.setup(app)

    # --- Routes ---
    app.router.add_get("/", index)
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_submit)
    app.router.add_get("/logout", logout)
    app.router.add_view("/dashboard/", DashboardView)
    app.router.add_view("/admin/", AdminView)
    app.router.add_view("/api/v1/tools/", ToolsView)
    app.router.add_view("/api/v1/analytics/", AnalyticsView)
    app.router.add_view("/api/v1/deployments/", DeploymentView)
    app.router.add_view("/api/v1/agents/", AgentView)

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n  PBAC Example Server")
    print("  ===================")
    print("  http://localhost:5000/          (redirects to login)")
    print("  http://localhost:5000/login     (login form)")
    print("  http://localhost:5000/api/v1/abac/check  (POST)\n")
    try:
        web.run_app(app, host="localhost", port=5000, handle_signals=True)
    except KeyboardInterrupt:
        print("\nShutting down.")
