from aiohttp import web
from navigator.views import BaseView
from navigator_auth import AuthHandler
from navigator_auth.abac import Policy, PolicyEffect, PDP, Guardian

class ExampleView(BaseView):
    async def get(self):
        guardian = self.request.app['security']
        response = await guardian.is_allowed(request=self.request)
        return self.response('GET METHOD')

    async def post(self):
        return self.response('POST METHOD')

    async def put(self):
        return self.response('PUT METHOD')

    async def delete(self):
        return self.response('DELETE METHOD')



## Creating a basic Policy
policy = Policy(
    'avoid_example_delete',
    effect=PolicyEffect.DENY,
    description="Avoid using DELETE method",
    resource="/api/v1/example/",
    method='DELETE',
    priority=0
)

# Create policy decision point
pdp = PDP()
pdp.add_policy(policy)


app = web.Application()

app['security'] = Guardian(pdp=pdp)

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app) # configure this Auth system into App.

app.router.add_view("/api/v1/example/", ExampleView)

if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
