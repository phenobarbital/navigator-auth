import asyncio
from typing import Any, Union
from collections.abc import Callable
from urllib import parse
from orjson import JSONDecodeError
from aiohttp import web
from aiohttp.abc import AbstractView
from aiohttp.web_exceptions import (
    HTTPMethodNotAllowed,
    HTTPNoContent,
    HTTPNotImplemented
)
import aiohttp_cors
from aiohttp_cors import CorsViewMixin
from navconfig.logging import logging, loglevel
from navigator_auth.libs.json import JSONContent, json_encoder, json_decoder



DEFAULT_JSON_ENCODER = json_encoder
DEFAULT_JSON_DECODER = json_decoder


class BaseHandler(CorsViewMixin):
    _allowed = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", )

    cors_config = {
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            allow_headers="*",
        )
    }

    def __init__(self, *args, **kwargs):
        CorsViewMixin.__init__(self)
        self._loop = asyncio.get_event_loop()
        self._json: Callable = JSONContent()
        self.logger = logging.getLogger('navigator')
        self.logger.setLevel(loglevel)
        self.post_init(self, *args, **kwargs)

    def post_init(self, *args, **kwargs):
        pass

    def log(self, message: str):
        self.logger.info(message)

    # function returns
    def no_content(
        self,
        headers: dict = None,
        content_type: str = "application/json",
    ) -> web.Response:
        if not headers:
            headers = {}
        response = HTTPNoContent(content_type=content_type, headers=headers)
        response.headers["Pragma"] = "no-cache"
        raise response

    def response(
        self,
        response: str = "",
        status: int = 200,
        headers: dict = None,
        content_type: str = "application/json",
        **kwargs,
    ) -> web.Response:
        if not headers: # TODO: set to default headers.
            headers = {}
        args = {"status": status, "content_type": content_type, "headers": headers, **kwargs}
        if isinstance(response, dict):
            args["text"] = self._json.dumps(response)
        else:
            args["body"] = response
        return web.Response(**args)

    def json_response(
            self,
            content: Any,
            reason: str = None,
            headers: dict = None,
            status: int = 200,
        ) -> web.Response:
        """json_response.

        Return a JSON-based Web Response.
        """
        if not headers: # TODO: set to default headers.
            headers = {}
        response_obj = {
            "status": status,
            "dumps": json_encoder,
            "reason": reason
        }
        if headers:
            response_obj["headers"] = headers
        return web.json_response(content, **response_obj)

    def redirect(self, resource: Any) -> web.Response:
        return web.HTTPFound(resource)

    def critical(
        self,
        reason: str = None,
        exception: Exception = None,
        stacktrace: str = None,
        status: int = 500,
        headers: dict = None,
        content_type: str = "application/json",
        **kwargs,
    ) -> web.Response:
        response_obj = {
            "reason": reason if reason else str(exception),
            "stacktrace": stacktrace,
        }
        if headers:
            response_obj["headers"] = headers
        args = {
            "text": self._json.dumps(response_obj),
            "reason": reason,
            "content_type": content_type,
            **kwargs,
        }
        if status == 500:  # bad request
            args = {
                "text": self._json.dumps(response_obj),
                "reason": reason,
                "content_type": content_type
            }
            obj = web.HTTPInternalServerError(**args)
        else:
            obj = web.HTTPServerError(**args)
        raise obj

    def error(
        self,
        reason: Union[dict, str] = None,
        exception: Exception = None,
        headers: dict = None,
        content_type: str = "application/json",
        status: int = 400,
        **kwargs,
    ) -> web.Response:
        response_obj = {
            "reason": reason if reason else str(exception),
            "content_type": content_type,
            **kwargs,
        }
        if headers:
            response_obj["headers"] = headers
        if isinstance(exception, dict):
            response_obj["text"] = self._json.dumps(exception)
        else:
            response_obj["text"] = str(exception)
        # defining the error
        if status == 400:  # bad request
            obj = web.HTTPBadRequest(**response_obj)
        elif status == 401:  # unauthorized
            obj = web.HTTPUnauthorized(**response_obj)
        elif status == 403:  # forbidden
            obj = web.HTTPForbidden(**response_obj)
        elif status == 404:  # not found
            obj = web.HTTPNotFound(**response_obj)
        elif status == 406: # Not acceptable
            obj = web.HTTPNotAcceptable(**response_obj)
        elif status == 412:
            obj = web.HTTPPreconditionFailed(**response_obj)
        elif status == 428:
            obj = web.HTTPPreconditionRequired(**response_obj)
        else:
            obj = web.HTTPBadRequest(**response_obj)
        raise obj

    def not_implemented(
        self,
        response: dict = None,
        headers: dict = None,
        content_type: str = "application/json",
        **kwargs # pylint: disable=W0613
    ) -> web.Response:
        response_obj = {
            "text": self._json.dumps(response),
            "reason": "Method not Implemented",
            "content_type": content_type,
            **kwargs,
        }
        if headers:
            response_obj["headers"] = headers
        response = HTTPNotImplemented(**response_obj)
        raise response

    def not_allowed(
        self,
        request: web.Request = None,
        response: dict = None,
        headers: dict = None,
        allowed: dict = None,
        content_type: str = "application/json",
        **kwargs,
    ) -> web.Response:
        if not request:
            request = self.request
        if not allowed:
            allow = self._allowed
        else:
            allow = allowed
        response_obj = {
            "method": request.method,
            "text": self._json.dumps(response),
            "reason": "Method not Allowed",
            "content_type": content_type,
            "allowed_methods": allow,
            **kwargs,
        }
        if headers:
            response_obj["headers"] = headers
        if allowed:
            response_obj["headers"]["Allow"] = ",".join(allow)
        else:
            response_obj["headers"]["Allow"] = ",".join(allow)
        obj = HTTPMethodNotAllowed(**response_obj)
        raise obj

    def query_parameters(self, request: web.Request) -> dict:
        return {key: val for (key, val) in request.query.items()}

    async def get_json(self, request: web.Request = None) -> Any:
        if not request:
            request = self.request
        return await request.json(loads=DEFAULT_JSON_DECODER)

    async def body(self, request: web.Request) -> str:
        body = None
        try:
            if request.body_exists:
                body = await request.read()
                body = body.decode("ascii")
        except Exception: # pylint: disable=W0703
            pass
        finally:
            return body # pylint: disable=W0150

    async def json_data(self, request: web.Request = None):
        if not request:
            request = self.request
        return await self.get_json(request)

    def match_parameters(self, request: web.Request = None) -> dict:
        params = {}
        if not request:
            request = self.request
        for arg in request.match_info:
            try:
                val = request.match_info.get(arg)
                object.__setattr__(self, arg, val)
                params[arg] = val
            except AttributeError:
                pass
        return params

    match_arguments = match_parameters

    def get_arguments(self, request: web.Request = None) -> dict:
        params = {}
        if not request:
            rq = self.request
        else:
            rq = request
        for arg in rq.match_info:
            try:
                val = rq.match_info.get(arg)
                object.__setattr__(self, arg, val)
                params[arg] = val
            except AttributeError:
                pass
        qry = {}
        try:
            qry = {key: val for (key, val) in rq.rel_url.query.items()}
        except (AttributeError, TypeError, ValueError) as err:
            print(err)
        params = {**params, **qry}
        return params

    get_args = get_arguments

    async def data(self, request: web.Request = None) -> dict:
        # only get post Data
        params = {}
        if not request:
            request = self.request
        try:
            params = await self.get_json(request)
        except JSONDecodeError as err:
            logging.debug(f"Invalid POST DATA: {err!s}")
        # if any, mix with match_info data:
        for arg in request.match_info:
            try:
                val = request.match_info.get(arg)
                # object.__setattr__(self, arg, val)
                params[arg] = val
            except AttributeError:
                pass
        return params


class BaseView(web.View, BaseHandler, AbstractView):

    cors_config = {
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            allow_headers="*",
        )
    }

    def __init__(self, request, *args, **kwargs):
        AbstractView.__init__(self, request)
        BaseHandler.__init__(self, *args, **kwargs)

    async def post_data(self) -> dict:
        params = {}
        if self.request.headers.get("Content-Type") == "application/json":
            try:
                return await self.get_json(self.request)
            except JSONDecodeError as ex:
                logging.exception(f'Empty or Wrong POST Data, {ex}')
                return None
        try:
            params = await self.request.post()
            if not params or len(params) == 0:
                if self.request.body_exists:
                    body = await self.request.read()
                    body = body.decode("ascii")
                    if body:
                        try:
                            params = dict(
                                (k, v if len(v) > 1 else v[0])
                                for k, v in parse.parse_qs(body).items()
                            )
                        except (KeyError, ValueError):
                            pass
        finally:
            return params # pylint: disable=W0150
