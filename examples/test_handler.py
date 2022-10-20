from aiohttp import web

from navigator_auth import AuthHandler


async def handle(request):
    name = request.match_info.get('name', "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)

app = web.Application()

# create a new instance of Auth System
auth = AuthHandler()
auth.setup(app) # configure this Auth system into App.

app.add_routes([web.get('/', handle),
                web.get('/{name}', handle)])

if __name__ == '__main__':
    try:
        web.run_app(
            app, host='localhost', port=5000, handle_signals=True
        )
    except KeyboardInterrupt:
        print('EXIT FROM APP =========')
