from aiohttp import web
from navconfig.logging import logging
from navigator_session import get_session
from navigator_auth.decorators import (
    user_session,
    is_authenticated,
    allowed_groups,
    allowed_programs,
    apikey_required
)
from navigator_auth import AuthHandler

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

app = web.Application(middlewares=[debug_middleware])

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app)  # configure this Auth system into App.

app.add_routes([web.get('/', handle),
                web.get('/{name}', handle)])


@user_session()
async def usersession(request, session, user):
    print('GOT USER ', user, session)
    name = request.match_info.get('name', "Anonymous")
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
    web.get('/services/api_required', api_required),
])


if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
