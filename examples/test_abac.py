from aiohttp import web
from navigator.views import BaseView
from navigator_auth import AuthHandler
from navigator_auth.abac import Policy, PolicyEffect
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.guardian import Guardian
from navigator_auth.abac.decorators import groups_protected

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
        guardian = self.request.app['security']
        await guardian.has_permission(request=self.request, permissions=['add_widget'])
        return self.response('PUT METHOD')

    async def delete(self):
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



## Creating a basic Policy
policy = Policy(
    'avoid_example_delete',
    effect=PolicyEffect.DENY,
    description="Avoid using DELETE method",
    resource=["/api/v1/example/"],
    method='DELETE',
    priority=0
)

# Create a policy decision point
pdp = PDP()
pdp.add_policy(policy)

walmart = Policy(
    'allow_access_test',
    description="Allow all users identified with Test to enter",
    resource=["/api/v1/test/*"],
    groups=['superuser'],
    context={
        "username": "jlara@trocglobal.com",
    }
)
pdp.add_policy(walmart)

app = web.Application()

### Also creates a PEP (Policy Enforcing Point)
app['security'] = Guardian(pdp=pdp)

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app) # configure this Auth system into App.

app.router.add_view("/api/v1/example/", ExampleView)
app.router.add_view("/api/v1/test/", TestView)

if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
