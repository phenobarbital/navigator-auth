import uuid

class Policy:
    pass

## Add policies into an Ordered Tuple, when load, based on priority.

Policy(
    uid=str(uuid.uuid4()),
    description="Allow everyone to log-in between 3 am and 23:59 am",
    resources=[{"url": "api/v1/login"}, {"url": "/login"}],
    effect="Allow",
    action=["get", "login"],
    actors=[],
    priority=0,
    context={
        session.logged_time: [gt('03:00'), lt('23:59')]
    }
)

Policy(
    uid=str(uuid.uuid4()),
    description="Allowing non-auth access from Localhost",
    resources=[],
    effect="Allow",
    action=[],
    actors=[],
    priority=1,
    context={
        request.remote: rules.cidr('127.0.0.1/32')
    }
)

def user_in_group(user, group_name):
    return group_name in user.groups

Policy(
    uid=str(uuid.uuid4()),
    description="Allowing Access to Program Users",
    resources=[
        {"url": r"^\/apps\/(.*)\/.*$"},
        {"app": "app.name"}
    ],
    effect="Allow",
    actions=["get", "read", "filter"],
    actors=[
        {"user.department": "app.name"},
        {"user.department": rules.resources.match("url")},
        user_in_group(user, rules.resources.app.name)
    ],
    priority=1
)
