#!/usr/bin/env python3

from navigator import Application
from navigator_session import get_session
from aiohttp import web
from app import Main

app = Application(Main)

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

app.add_get('/', handle)
app.add_get('/{name}', handle)

if __name__ == "__main__":
    try:
        app.run()
    except KeyboardInterrupt:
        print("EXIT FROM APP =========")
