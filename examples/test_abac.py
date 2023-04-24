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


class ExampleView(BaseView):
    async def get(self):
        guardian = self.request.app['security']
        list_files = ["text1.txt", "text2.txt", "text3.txt", "text4.txt", "text5.txt"]
        response = await guardian.filter_files(files=list_files, request=self.request)
        # response = await guardian.authorize(request=self.request)
        print('RESPONSE ', response)
        return self.json_response(response)

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
        guardian = self.request.app['security']
        list_dirs = ["walmart", "private", "restricted", "tasks"]
        response = await guardian.filter(
            objects=list_dirs,
            type='dir',
            request=self.request
        )
        print('Directories Granted: ', response.response)
        return self.json_response(response.response)

    async def post(self):
        guardian = self.request.app['security']
        response = await guardian.is_allowed(
            action='walmart.create',
            request=self.request
        )
        if response.effect:
            return self.response('WALMART POST')
        return self.response('WALMART READ ONLY')

    async def put(self):
        return self.response('PUT  WALMART VIEW')

    async def delete(self):
        response = await self.request.app['security'].is_allowed(
            actions='file.delete',
            resource=['dir:restricted'],
            request=self.request
        )
        if response.effect:
            return self.response('CAN DELETE FILES')
        return self.response('DELETE FORBIDDEN')

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
    resource=["uri:/api/v1/example/"],
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
    resource=["uri:/epson/"],
    method=['POST', 'PUT'],
    context={
        "title": "Consultant",
    }
)
policy3 = Policy(
    'login_denied_on_wednesdays',
    effect=PolicyEffect.DENY,
    description="All users, except superUsers has denied access on Wednesdays",
    resource=["uri:/epson/"],
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
    resource=["uri:/epson/"],
    groups=[
        'epson', 'superuser'
    ]
)

policy5 = Policy(
    'allow_access_tm_to_tm_users',
    effect=PolicyEffect.ALLOW,
    description="All TM Users (and superusers) has access to this resource",
    resource=["uri:/trendmicro/"],
    context={
        "programs": ['trendmicro']
    },
    groups=[
        'trendmicro', 'superuser'
    ]
)

policy6 = Policy(
    'only_for_jesus',
    effect=PolicyEffect.ALLOW,
    description="This resource will be used only for Jesus between 9 at 24 monday to saturday",
    subject=['jlara@trocglobal.com'],
    resource=["uri:/private/"],
    environment={
        "hour": list(chain(range(9, 24), range(1))),
        "day_of_week": range(1, 6)
    }
)

policy7 = ObjectPolicy(
    'clone_dashboard',
    effect=PolicyEffect.ALLOW,
    description="Clone dashboards can only by superusers and adv_users",
    actions=['dashboard.clone'],
    resource=["dashboard:*", "dashboard:!12345678"],
    groups=['superuser', 'adv_users'],
    priority=3

)
cloning_jesus = ObjectPolicy(
    'clone_dashboard_jesus',
    effect=PolicyEffect.ALLOW,
    description="This dashboard can be cloned only by Jesus",
    actions=['dashboard.clone'],
    resource=["dashboard:12345678"],
    context={
        "username": "jlara@trocglobal.com"
    },
    priority=2
)



policy8 = Policy(
    name='example grant',
    effect=PolicyEffect.ALLOW,
    resource=['uri:/api/v1/example/'],
    description="Grant Access to this resource to all",
    priority=7
)

# files_policy = FilePolicy(
#     name='files_for_jlara',
#     effect=PolicyEffect.ALLOW,
#     resource=['uri:/api/v1/example/'],
#     description="This policy allows access to specific files only for jlara@trocglobal.com",
#     subject=['jlara@trocglobal.com'],
#     objects={
#         "files": ["text1.txt", "text2.txt"],
#     },
#     context={
#         "dow": [6]
#     },
#     objects_attr="files",
#     priority=8
# )

files_policy = FilePolicy(
    name='files_for_jlara',
    effect=PolicyEffect.ALLOW,
    resource=["file:text1.txt", "file:text2.txt"],
    description="This policy allows access to files only for jlara@trocglobal.com",
    subject=['jlara@trocglobal.com'],
    environment={
        "dow": [6]
    },
    objects_attr="files",
    priority=8
)

files2_policy = FilePolicy(
    name='file_denied_for_jlara',
    effect=PolicyEffect.DENY,
    resource=["file:text5.txt"],
    description="Deny Access to File 5 to jlara@trocglobal.com on sundays",
    subject=['jlara@trocglobal.com'],
    environment={
        "dow": [6]
    },
    priority=9
)

files3_policy = FilePolicy(
    name='file_denied_for_jlara',
    effect=PolicyEffect.DENY,
    resource=["file:text1.txt"],
    description="Deny Access to File 1 to jlara@trocglobal.com",
    subject=['jlara@trocglobal.com'],
    priority=10
)

directory_policy = FilePolicy(
    name='directories_restricted_to_superusers_consultants',
    effect=PolicyEffect.ALLOW,
    resource=["dir:restricted", "dir:private"],
    description="Directories are restricted only to SuperUsers consultants",
    groups=['superuser'],
    context={
        "title": "Consultant"
    },
    priority=11
)

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
pdp.add_policy(policy6)
pdp.add_policy(policy7)
pdp.add_policy(policy8)
pdp.add_policy(files_policy)
pdp.add_policy(files2_policy)
pdp.add_policy(files3_policy)
pdp.add_policy(directory_policy)
pdp.add_policy(cloning_jesus)

walmart = Policy(
    'access_walmart',
    description="Allow Walmart to All",
    resource=["uri:/walmart/*"],
    priority=0
)
pdp.add_policy(walmart)
walmart_post = Policy(
    'post_on_walmart',
    description="Allowing post actions to Superusers",
    effect=PolicyEffect.ALLOW,
    actions=['walmart.create', 'walmart.update'],
    resource=["uri:/walmart/*"],
    groups=['superuser'],
    priority=1
)
pdp.add_policy(walmart_post)


dir_creation = FilePolicy(
    name='walmart_create_file',
    effect=PolicyEffect.ALLOW,
    actions=['file.create', 'file.edit', 'file.delete'],
    resource=["dir:restricted", "dir:private"],
    description="Only Superusers can create, edit or delete files",
    groups=['superuser'],
    priority=11
)
pdp.add_policy(dir_creation)

pdp.setup(app)


app.router.add_view("/api/v1/example/", ExampleView)
app.router.add_view("/api/v1/test/", TestView)
app.router.add_view("/walmart/", WalmartView)
app.router.add_view("/epson/", EpsonView)
app.router.add_view("/trendmicro/", TmView)
app.router.add_view("/private/", TmView)


if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
