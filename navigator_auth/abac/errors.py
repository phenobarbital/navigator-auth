from typing import Union, Optional, Any
from aiohttp import web, hdrs
from navconfig.logging import logger
from navigator_auth.libs.json import json_encoder

def default_headers(message: str, exception: BaseException = None) -> dict:
    headers = {
        "X-ABAC-RESPONSE": message,
        hdrs.CONNECTION: "keep-alive",
    }
    if exception:
        headers['X-ERROR'] = str(exception)
    return headers

def auth_error(
    reason: Optional[Union[str, dict]] = None,
    exception: Exception = None,
    status: int = 400,
    headers: dict = None,
    content_type: str = 'application/json',
    **kwargs,
) -> web.HTTPError:
    """auth_error.

    Basic Function to build an HTTP Error object.
    Args:
        reason (dict, optional): message passed as error.
        exception (Exception, optional): exception raised. Defaults to None.
        status (int, optional): current HTTP Status. Defaults to 400.
        headers (dict, optional): dictionary of headers. Defaults to None.
        content_type (str, optional): default mime type. Defaults to 'application/json'.
        kwargs: (dict, optional): any other argument passed to HTTPError.
    Returns:
        web.HTTPError: _description_
    """
    if headers:
        headers = {**default_headers(message=str(reason), exception=exception), **headers}
    else:
        headers = default_headers(message=str(reason), exception=exception)
    # TODO: process the exception object
    response_obj = {
        "status": status
    }
    if exception:
        response_obj["error"] = str(exception)
    args = {
        "content_type": content_type,
        "headers": headers,
        **kwargs
    }
    if isinstance(reason, dict):
        response_obj = {**response_obj, **reason}
        # args["content_type"] = "application/json"
        args["body"] = json_encoder(response_obj)
    else:
        response_obj['reason'] = reason
        args["body"] = json_encoder(response_obj)
    # defining the error
    if status == 400:  # bad request
        obj = web.HTTPBadRequest(**args)
    elif status == 401:  # unauthorized
        obj = web.HTTPUnauthorized(**args)
    elif status == 403:  # forbidden
        obj = web.HTTPForbidden(**args)
    elif status == 404:  # not found
        obj = web.HTTPNotFound(**args)
    elif status == 406: # Not acceptable
        obj = web.HTTPNotAcceptable(**args)
    elif status == 412:
        obj = web.HTTPPreconditionFailed(**args)
    elif status == 428:
        obj = web.HTTPPreconditionRequired(**args)
    else:
        obj = web.HTTPBadRequest(**args)
    return obj

def PreconditionFailed(reason: Union[str, dict], **kwargs) -> web.HTTPError:
    msg = f"Error: Some preconditions failed: {reason}"
    return auth_error(
        reason=msg, **kwargs, status=428
    )

def AccessDenied(reason: Union[str, dict], **kwargs) -> web.HTTPError:
    return auth_error(
        reason=reason, **kwargs, status=403
    )

def Unauthorized(reason: Union[str, dict], **kwargs) -> web.HTTPError:
    logger.error(
        reason
    )
    return auth_error(
        reason=reason, **kwargs, status=401
    )
