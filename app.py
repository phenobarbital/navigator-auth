from aiohttp import web
from navigator_auth import AuthHandler
from navigator.handlers.types import AppHandler
from navconfig.logging import logging


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

class Main(AppHandler):
    enable_static: bool = True

    def configure(self):

        self.app.middlewares.append(
            debug_middleware
        )
        # create a new instance of Auth System
        auth = AuthHandler(secure_cookies=True)
        auth.setup(self.app)  # configure this Auth system into App.
