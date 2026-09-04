"""
Various kinds of Application Responses.

TODO: add FileResponse or JSONResponse or SSEResponse (server-side).
"""
from typing import Any, NoReturn, Optional
from aiohttp import web
from aiohttp import web_exceptions
from aiohttp.web_exceptions import (
    HTTPNoContent,
)
from .libs.json import json_encoder, json_decoder

DEFAULT_JSON_ENCODER = json_encoder
DEFAULT_JSON_DECODER = json_decoder


def Response(
    content: Any = None,
    text: Optional[str] = "",
    body: Any = None,
    status: int = 200,
    headers: dict = None,
    content_type: str = "text/plain",
    charset: Optional[str] = "utf-8",
) -> web.Response:
    """
    Response.
    Web Response Definition for Navigator
    """
    response = {"content_type": content_type, "charset": charset, "status": status}
    if headers:
        response["headers"] = headers
    if isinstance(content, str) or text is not None:
        response["text"] = content if content else text
    else:
        response["body"] = content if content else body
    return web.Response(**response)


def NoContent(
    headers: dict = None, content_type: str = "application/json"
) -> web.Response:
    response = {
        "content_type": content_type,
    }
    if headers:
        response["headers"] = headers
    response = HTTPNoContent(content_type=content_type)
    response.headers["Pragma"] = "no-cache"
    return response


def HTMLResponse(
    content: Any = None,
    text: Optional[str] = "",
    body: Any = None,
    status: int = 200,
    headers: dict = None,
) -> web.Response:
    """
    Sending response in HTML.
    """
    response = {
        "content": content,
        "text": text,
        "body": body,
        "headers": headers,
        "content_type": "text/html",
        "status": status,
    }
    return Response(**response)


def JSONResponse(
    content: Any,
    status: int = 200,
    headers: Optional[dict] = None,
    reason: Optional[str] = None,
    content_type: str = "application/json",
) -> web.Response:
    """
    JSONResponse.
     Sending responses using JSON.
    """
    response = {
        "content_type": content_type,
        "status": status,
        "dumps": json_encoder,
        "reason": reason,
    }
    if headers:
        response["headers"] = headers

    return web.json_response(content, **response)


def _http_exception_classes() -> dict[int, type[web.HTTPException]]:
    """Map each HTTP status to aiohttp's own exception class for it."""
    mapping: dict[int, type[web.HTTPException]] = {}
    for obj in vars(web_exceptions).values():
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            status = getattr(obj, "status_code", None)
            if isinstance(status, int) and status > 0:
                mapping.setdefault(status, obj)
    return mapping


HTTP_EXCEPTIONS = _http_exception_classes()


def _status_line_reason(message: str) -> Optional[str]:
    """Collapse a message into something usable as an HTTP reason phrase.

    These messages embed user input (a vault key name, a client_uid), and
    aiohttp raises ValueError on CR/LF in a reason -- which would turn an
    intended 404 into an unhandled 500. Whitespace is collapsed and the result
    capped so the status line stays sane.
    """
    reason = " ".join(message.split())
    return reason[:200] or None


def json_error(status: int, message: str) -> NoReturn:
    """Raise an HTTP exception carrying a JSON body.

    The class is looked up from aiohttp's own hierarchy so that callers,
    middleware and tests catching `web.HTTPNotFound` or `web.HTTPClientError`
    still match. Raising an anonymous subclass of the `web.HTTPException` base
    (as this used to) is invisible to every one of those handlers, since it is
    not a subclass of the status-specific classes they catch.
    """
    exc_class = HTTP_EXCEPTIONS.get(status)
    if exc_class is None:
        # A status aiohttp has no class for: keep the old behaviour rather than
        # remap it to something with different semantics.
        exc_class = type(
            "JSONHTTPError", (web.HTTPException,), {"status_code": status}
        )
    raise exc_class(
        reason=_status_line_reason(message),
        text=json_encoder({"error": message}),
        content_type="application/json",
    )
