import inspect
import pathlib
from aiohttp import web
from aiohttp.abc import AbstractView
from aiohttp_cors import setup as cors_setup, ResourceOptions
from navconfig.logging import logging
from navigator_session import get_session
from navigator.views import BaseView
from navigator_auth.decorators import (
    user_session,
    is_authenticated,
    allowed_groups,
    allowed_programs,
    apikey_required
)
from navigator_auth import AuthHandler

@user_session()
@is_authenticated()
class TestHandler(BaseView):
    async def get(self):
        session = self.request.session
        user = self.request.user
        print('GOT USER ', user, session)
        name = self.request.match_info.get('name', user.first_name)
        text = "Hello, " + name
        return web.Response(text=text)

async def handle(request):
    name = request.match_info.get('name', "Anonymous")
    try:
        session = await get_session(request)
        print('WHICH SESSION > ', session)
        if session:
            name = session.session.get('username', str(session.id))
    except Exception:
        pass
    text = "Hello, " + name
    return web.Response(text=text)

# Middleware to print request details
@web.middleware
async def debug_middleware(request, handler):
    app = request.app
    for route in app.router.routes():
        logging.debug(
            f"Route added: {route.resource}, Path: {route.resource.canonical}"
        )
    logging.debug(
        f"Request received: {request.method} {request.path}"
    )
    match_info = request.match_info
    logging.debug(f"Matched info: {match_info}")
    response = await handler(request)
    return response

app = web.Application()

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app)  # configure this Auth system into App.

app.add_routes([web.get('/', handle),
                web.get('/{name}', handle)])

# Serve static files from the admin/public directory
app.router.add_static(
    '/static/',
    path=pathlib.Path(__file__).parent.parent / 'admin' / 'public',
    name='static'
)

# Route for the admin index page
async def admin_index(request):
    return web.FileResponse(
        pathlib.Path(__file__).parent.parent / 'admin' / 'public' / 'index.html'
    )

app.router.add_get('/admin', admin_index)
app.router.add_get('/admin/', admin_index)

@user_session()
async def usersession(request, session, user):
    print('GOT USER ', user, session)
    name = request.match_info.get('name', user.first_name)
    text = "Hello, " + name
    return web.Response(text=text)


@is_authenticated()
async def url_protected(request):
    session = await get_session(request)
    name = str(session['id'])
    text = "Protected Content for: " + name
    return web.Response(text=text)


@allowed_groups(groups=['superuser'])
async def only_supers(request):
    session = await get_session(request)
    name = str(session['id'])
    text = "Protected Content for: " + name
    return web.Response(text=text)

@allowed_programs(programs=['walmart'])
async def only_walmart(request):
    session = await get_session(request)
    name = str(session['id'])
    text = "Walmart Content for: " + name
    return web.Response(text=text)

@apikey_required()
async def api_required(request):
    userdata = request.get('userdata', {})
    print(userdata)
    if userdata:
        name = str(userdata['id'])
    else:
        name = 'Anonymous'
    text = "Only available with API Key Backend: " + name
    return web.Response(text=text)

app.add_routes([
    web.get('/services/usersession', usersession),
    web.get('/services/protected', url_protected),
    web.get('/services/admin', only_supers),
    web.get('/services/walmart', only_walmart),
    web.get('/services/api_required', api_required)
])

app.router.add_view('/services/base_test', TestHandler)

cors = cors_setup(
    app,
    defaults={
        "*": ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_methods="*",
            allow_headers="*",
            max_age=1600,
        )
    },
)
for route in list(app.router.routes()):
    try:
        if not isinstance(route.resource, web.StaticResource):
            if inspect.isclass(route.handler) and issubclass(
                route.handler, AbstractView
            ):
                cors.add(route, webview=True)
            else:
                cors.add(route)
    except (TypeError, ValueError, RuntimeError) as exc:
        if 'already has OPTIONS handler' in str(exc):
            continue
        print(
            f"Error setting up CORS for route {route}: {exc}"
        )
        continue

if __name__ == '__main__':
    try:
        print(TestHandler, type(TestHandler))
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
