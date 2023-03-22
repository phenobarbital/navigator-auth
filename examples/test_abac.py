from aiohttp import web
from navigator.views import BaseView
from navigator_auth import AuthHandler
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.decorators import groups_protected
from navigator_auth.abac.storages.pg import pgStorage
from navigator_auth.abac.policies import Policy, PolicyEffect
# from navigator_auth.abac.conditions import NOT
from navigator_auth.conf import default_dsn


class ExampleView(BaseView):
    async def get(self):
        guardian = self.request.app['security']
        response = await guardian.authorize(request=self.request)
        print('RESPONSE ', response)
        return self.response('GET METHOD')

    async def post(self):
        guardian = self.request.app['security']
        await guardian.allowed_groups(request=self.request, groups=['superuser'])
        return self.response('POST METHOD')

    async def put(self):
        #guardian = self.request.app['security']
        #await guardian.has_permission(request=self.request, permissions=['add_widget'])
        return self.response('PUT METHOD')

    async def delete(self):
        guardian = self.request.app['security']
        response = await guardian.authorize(request=self.request)
        return self.response('DELETE METHOD')


## TODO: making a decorator for classes and functions.
@groups_protected(groups=['superuser'])
class TestView(BaseView):
    async def get(self):
        guardian = self.request.app['security']
        await guardian.authorize(request=self.request)
        return self.response('GET TEST VIEW')

    async def post(self):
        return self.response('POST  TEST VIEW')

    async def put(self):
        return self.response('PUT  TEST VIEW')

    async def delete(self):
        return self.response('DELETE  TEST VIEW')


class WalmartView(BaseView):
    async def get(self):
        return self.response('GET WALMART VIEW')

    async def post(self):
        return self.response('POST  WALMART VIEW')

    async def put(self):
        return self.response('PUT  WALMART VIEW')

    async def delete(self):
        return self.response('DELETE  WALMART VIEW')

class EpsonView(BaseView):
    async def get(self):
        return self.response('GET Epson VIEW')

    async def post(self):
        return self.response('POST  Epson VIEW')

    async def put(self):
        return self.response('PUT  Epson VIEW')

    async def delete(self):
        return self.response('DELETE  Epson VIEW')

class TmView(BaseView):
    async def get(self):
        return self.response('GET TRENDMICRO VIEW')

## Creating a basic Policy
policy1 = Policy(
    'avoid_example_put',
    effect=PolicyEffect.ALLOW,
    description="Avoid using PUT method except by Jesus Lara",
    resource=["/api/v1/example/"],
    method='PUT',
    context={
        "username": "jlara@trocglobal.com",
    },
    priority=0
)
policy2 = Policy(
    'allow_consultants',
    effect=PolicyEffect.ALLOW,
    description='Allow Access to this resource only to consultants',
    resource=["/epson/"],
    method=['POST', 'PUT'],
    context={
        "title": "Consultant",
    }
)
policy3 = Policy(
    'login_denied_on_wednesdays',
    effect=PolicyEffect.DENY,
    description="All users, except superUsers has denied access on Wednesdays",
    resource=["/epson/"],
    context={
        "dow": [3]
    },
    groups=[

    ]
)
policy4 = Policy(
    'allow_access_epson_to_epson_users',
    effect=PolicyEffect.ALLOW,
    description="All Epson Users has access to this resource",
    resource=["/epson/"],
    groups=[
        'epson', 'superuser'
    ]
)

policy5 = Policy(
    'allow_access_tm_to_tm_users',
    effect=PolicyEffect.ALLOW,
    description="All TM Users has access to this resource",
    resource=["/trendmicro/"],
    context={
        "programs": ['trendmicro']
    },
    groups=[
        'trendmicro', 'superuser'
    ]
)
# pdp.add_policy(policy)
# walmart = Policy(
#     'allow_access_test',
#     description="Allow all users identified with Test to enter",
#     resource=["/api/v1/test/*"],
#     groups=['superuser'],
#     context={
#         "username": "jlara@trocglobal.com",
#     }
# )
# pdp.add_policy(walmart)

app = web.Application()

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app) # configure this Auth system into App.

### install PDP:
### Setup Policy Storage:
storage = pgStorage(dsn=default_dsn)

# Create a policy decision point
pdp = PDP(storage=storage)
## add other external policies:
pdp.add_policy(policy1)
pdp.add_policy(policy2)
pdp.add_policy(policy3)
pdp.add_policy(policy4)
pdp.add_policy(policy5)
pdp.setup(app)


app.router.add_view("/api/v1/example/", ExampleView)
app.router.add_view("/api/v1/test/", TestView)
app.router.add_view("/walmart/", WalmartView)
app.router.add_view("/epson/", EpsonView)
app.router.add_view("/trendmicro/", TmView)

if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
