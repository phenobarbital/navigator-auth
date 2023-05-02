from itertools import chain
from aiohttp import web
from navigator.views import BaseView
from navigator_auth import AuthHandler
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.decorators import groups_protected
from navigator_auth.abac.storages.pg import pgStorage
from navigator_auth.abac.policies import Policy, PolicyEffect, FilePolicy, ObjectPolicy
# from navigator_auth.abac.conditions import NOT
from navigator_auth.conf import default_dsn

app = web.Application()

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app) # configure this Auth system into App.

### install PDP:
### Setup Policy Storage:
storage = pgStorage(dsn=default_dsn)

# Create a policy decision point
pdp = PDP(storage=storage)


## first: load all policies declared:
policy = Policy(
    'only_for_jesus',
    effect=PolicyEffect.ALLOW,
    description="This resource will be used only for Jesus between 9 at 24 monday to saturday",
    subject=['jlara@trocglobal.com'],
    resource=["urn:uri:/private/"],
    environment={
        "hour": list(chain(range(9, 24), range(1))),
        "day_of_week": range(1, 6)
    }
)
pdp.add_policy(policy)

walmart_post = Policy(
    'post_on_walmart',
    description="Allowing post actions to Superusers",
    effect=PolicyEffect.ALLOW,
    actions=['walmart:create', 'walmart:update'],
    resource=["uri:/walmart/*"],
    conditions={
        "method": ["POST"],
    },
    groups=['superuser'],
    priority=1
)
pdp.add_policy(walmart_post)

### configure PDP
pdp.setup(app)

if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
