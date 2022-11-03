from typing import Any
import time
import importlib
import hashlib
import base64
import secrets
from aiohttp import web
from datamodel.exceptions import ValidationError
from navigator_session import get_session, SESSION_KEY, AUTH_SESSION_OBJECT
from asyncdb.exceptions import (
    DriverError,
    ProviderError,
    NoDataFound,
    StatementError
)
from navigator.libs.cypher import Cipher
from navigator_auth.exceptions import AuthException
from navigator_auth.models import User
from navigator_auth.conf import (
    AUTH_USER_MODEL,
    AUTH_PWD_DIGEST,
    AUTH_PWD_LENGTH,
    AUTH_PWD_ALGORITHM,
    AUTH_PWD_SALT_LENGTH,
    PARTNER_KEY
)
from .base import BaseView, BaseHandler


def set_basic_password(
    password: str,
    token_num: int = 6,
    iterations: int = 80000,
    salt: str = None
):
    if not salt:
        salt = secrets.token_hex(token_num)
    key = hashlib.pbkdf2_hmac(
        AUTH_PWD_DIGEST,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=AUTH_PWD_LENGTH,
    )
    hst = base64.b64encode(key).decode("utf-8").strip()
    return f"{AUTH_PWD_ALGORITHM}${iterations}${salt}${hst}"


def check_password(current_password, password):
    if not password:
        return False
    try:
        algorithm, iterations, salt, _ = current_password.split("$", 3)
    except ValueError as ex:
        raise AuthException(
            'Invalid Password Algorithm: {ex}'
        ) from ex
    assert algorithm == AUTH_PWD_ALGORITHM
    compare_hash = set_basic_password(
        password,
        iterations=int(iterations),
        salt=salt,
        token_num=AUTH_PWD_SALT_LENGTH
    )
    return secrets.compare_digest(current_password, compare_hash)

class UserSession(BaseHandler):

    async def session(self, request):
        session = None
        try:
            session = await get_session(request)
        except (ValueError, RuntimeError) as err:
            return self.critical(
                reason="Error Decoding Session",
                request=self.request,
                exception=err
            )
        if not session:
            headers = {"x-status": "Empty", "x-message": "Invalid or Empty User Session"}
            return self.error(
                reason="Unauthorized",
                headers=headers,
                status=403
            )
        else:
            try:
                _id = session[SESSION_KEY]
            except KeyError:
                headers = {"x-status": "Bad Session", "x-message": "Invalid User Session"}
                return self.error(
                    reason='Invalid Session, missing User Session Key',
                    headers=headers,
                    status=403
                )
            return session


    async def in_session(self, request: web.Request):
        """ Adding (put) information (persistence) to User Session."""
        session = await self.session(request)
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid or Empty Session Data",
                status=406
            )
        for k,value in data.items():
            session[k] = value
        headers = {"x-status": "OK", "x-message": "Session Saved"}
        return self.json_response(
            content=data,
            headers=headers
        )

    async def gen_token(self, request: web.Request):
        """ Generate a RCCRYPT TOKEN from Email account."""
        session = await self.session(request)
        params = self.match_parameters(request)
        try:
            userid = params['userid']
        except KeyError:
            userid = None
        ### TODO: check if user is superuser:
        userinfo = session[AUTH_SESSION_OBJECT]
        if userinfo['superuser'] is False:
            return self.error(
                reason = 'Access Denied',
                status=406
            )
        try:
            db = request.app['authdb']
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=userid)
                data = {
                    "magic": "Navigator",
                    "firstName": user.first_name,
                    "lastName": user.last_name,
                    "email": user.email,
                    "username": user.username,
                    "timestamp": str(time.time())
                }
                cipher = Cipher(PARTNER_KEY, type="RNC")
                rnc = cipher.encode(self._json.dumps(data))
                headers = {"x-status": "OK", "x-message": "Token Generated"}
                response = {
                    "token": rnc.upper()
                }
                return self.json_response(
                    content=response,
                    headers=headers
                )
        except ValidationError as ex:
            self.error(
                reason='User info has errors',
                exception=ex.payload,
                status=412
            )
        except Exception as err: # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User: {err}",
                exception=err
            )

    async def password_change(self, request: web.Request):
        """ Reset User Password. """
        session = await self.session(request)
        params = self.match_parameters(request)
        try:
            userid = params['userid']
        except KeyError:
            userid = None
        try:
            data = await self.get_json(request)
            new_password = data['password']
            old_password = data['old_password']
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid User Data",
                status=406
            )
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
            user_id = userinfo['user_id']
        except KeyError:
            return self.error(
                reason = 'Invalid Session, missing Session ID',
                status=406
            )
        ## validating user Id:
        if userid is not None and userid != user_id:
            return self.error(
                reason="Forbidden: User ID from session and URL doesn't match.",
                status=403
            )
        try:
            db = request.app['authdb']
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                if check_password(user.password, old_password):
                    # valid, can change password
                    user.password = set_basic_password(new_password)
                    await user.update()
                    headers = {"x-status": "OK", "x-message": "Session OK"}
                    response = {
                        "action": "Password Changed",
                        "status": "OK"
                    }
                    return self.json_response(
                        content=response,
                        headers=headers,
                        status=202
                    )
                else:
                    return self.error(
                        reason="Forbidden: Current Password doesn't match.",
                        status=403
                    )
        except ValidationError as ex:
            self.error(
                reason='User info has errors',
                exception=ex.payload,
                status=412
            )
        except Exception as err: # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User: {err}",
                exception=err
            )


    async def password_reset(self, request: web.Request):
        """ Reset User Password. """
        session = await self.session(request)
        params = self.match_parameters(request)
        try:
            userid = params['userid']
        except KeyError:
            userid = None
        try:
            data = await self.json_data(request)
            new_password = data['password']
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid User Data",
                status=406
            )
        ### TODO: check if user is superuser:
        userinfo = session[AUTH_SESSION_OBJECT]
        if userinfo['superuser'] is False:
            return self.error(
                reason = 'Access Denied',
                status=406
            )
        try:
            db = request.app['authdb']
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=userid)
                ## Reset Password:
                user.password = set_basic_password(new_password)
                user.is_new = True
                await user.update()
                headers = {"x-status": "OK", "x-message": "Session OK"}
                response = {
                    "action": "Password was changed successfully",
                    "user": user.user_id,
                    "username": user.username,
                    "status": "OK"
                }
                return self.json_response(
                    content=response,
                    headers=headers,
                    status=202
                )
        except ValidationError as ex:
            self.error(
                reason='User info has errors',
                exception=ex.payload,
                status=412
            )
        except Exception as err: # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User: {err}",
                exception=err
            )

    async def user_session(self, request: web.Request):
        """ Getting User Session information."""
        session = await self.session(request)
        ## get session Data:
        headers = {"x-status": "OK", "x-message": "Session OK"}
        userdata = dict(session)
        _id = session[SESSION_KEY]
        data = {
            "session_id": _id,
            **userdata
        }
        if data:
            return self.json_response(
                content=data,
                headers=headers
            )
        else:
            return self.error(
                reason='Empty Session',
                status=406
            )

    async def user_profile(self, request: web.Request):
        """ Getting User Profile."""
        session = await self.session(request)
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
            user_id = userinfo['user_id']
        except KeyError:
            return self.error(
                reason = 'Invalid Session, missing Session ID',
                status=406
            )
        try:
            db = request.app['authdb']
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                user.password = None
                return self.json_response(
                    content=user,
                    status=200
                )
        except ValidationError as ex:
            self.error(
                reason='User info has errors',
                exception=ex.payload,
                status=412
            )
        except Exception as err: # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User Profile: {err}",
                exception=err
            )

    async def logout(self, request: web.Request):
        """ Logout: Close and Delete User Session."""
        session = await self.session(request)
        app = request.app
        router = app.router
        try:
            session.invalidate()
            app['session'] = None
        except (ValueError, RuntimeError) as err:
            return self.critical(
                exception=err,
                status=501
            )
        # return a redirect to LOGIN
        return self.redirect(router["login"].url_for())


class UserHandler(BaseView):
    """
    Main Class for Managing Users.
    """
    model: Any = User
    name: str = 'Users'
    pk: str = 'user_id'

    def __init__(self, request, *args, **kwargs):
        self.user_model = self.get_usermodel(AUTH_USER_MODEL)
        self.session_id = None
        super(UserHandler, self).__init__(request, *args, **kwargs)

    async def session(self):
        session = None
        try:
            session = await get_session(self.request)
        except (ValueError, RuntimeError) as err:
            return self.critical(
                reason="Error Decoding Session",
                request=self.request,
                exception=err
            )
        if not session:
            headers = {"x-status": "Empty", "x-message": "Invalid or Empty User Session"}
            return self.error(
                reason="Unauthorized",
                headers=headers,
                status=403
            )
        else:
            try:
                self.session_id = session[SESSION_KEY]
            except KeyError:
                headers = {"x-status": "Bad Session", "x-message": "Invalid User Session"}
                return self.error(
                    reason='Invalid Session, missing User Session Key',
                    headers=headers,
                    status=403
                )
            return session

    async def head(self):
        """ Getting Client information."""
        session = await self.session()
        if not session:
            return self.error(
                reason="Unauthorized",
                status=403
            )
        ## calculating resource:
        response = self.model.schema(as_dict=True)
        columns = list(response["properties"].keys())
        size = len(str(response))
        headers = {
            "Content-Length": size,
            "X-Columns": f"{columns!r}",
            "X-Model": self.model.__name__,
            "X-Tablename": self.model.Meta.name,
            "X-Schema": self.model.Meta.schema,
        }
        return self.no_content(
            headers=headers
        )

    def get_usermodel(self, model: str):
        try:
            parts = model.split(".")
            name = parts[-1]
            classpath = ".".join(parts[:-1])
            module = importlib.import_module(classpath, package=name)
            obj = getattr(module, name)
            return obj
        except ImportError:
            ## Using fallback Model
            return self.model

    async def get(self):
        """ Getting Client information."""
        session = await self.session()
        if not session:
            return self.error(
                reason="Unauthorized",
                status=403
            )
        ## getting all clients:
        params = self.match_parameters(self.request)
        try:
            if params['meta'] == ':meta':
                # returning JSON schema of Model:
                response = self.model.schema(as_dict=True)
                return self.json_response(content=response)
        except KeyError:
            pass
        try:
            data = self.get_arguments()
        except (TypeError, ValueError, AuthException):
            data = None
        ## validate directly with model:
        db = self.request.app['authdb']
        ## getting first the id from params or data:
        args = {}
        try:
            userid = data['user_id']
        except (TypeError, KeyError):
            try:
                userid = params['id']
            except KeyError:
                userid = None
        if userid:
            args = {
                'user_id': userid
            }
        if args:
            async with await db.acquire() as conn:
                self.user_model.Meta.connection = conn
                # look for this client, after, save changes
                error = {
                    "error": f"User {args!s} was not Found"
                }
                try:
                    result = await self.user_model.get(**args)
                except NoDataFound:
                    self.error(
                        exception=error,
                        status=403
                    )
                except (ProviderError, DriverError) as ex:
                    self.error(
                        exception=ex,
                        status=403
                    )
                if not result:
                    self.error(
                        exception=error,
                        status=403
                    )
                return self.json_response(content=result)
        else:
            try:
                async with await db.acquire() as conn:
                    self.user_model.Meta.connection = conn
                    if data is None:
                        result = await self.user_model.all()
                    else:
                        result = await self.user_model.filter(**data)
                    return self.json_response(content=result)
            except ValidationError as ex:
                error = {
                    "error": f"Unable to load {self.name} info from Database",
                    "payload": ex.payload,
                }
                return self.critical(
                    reason=error,
                    statu=501
                )
            except TypeError as ex:
                error = {
                    "error": f"Invalid payload for {self.name}",
                    "payload": str(ex),
                }
                return self.error(
                    exception=error,
                    statu=406
                )
            except (DriverError, ProviderError, RuntimeError):
                error = {
                    "error": "Database Error",
                    "payload": str(ex),
                }
                return self.critical(
                    reason=error,
                    statu=500
                )

    async def patch(self):
        """ Patch an existing User or retrieve the column names."""
        session = await self.session()
        if not session:
            return self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        params = self.match_parameters()
        try:
            if params['meta'] == ':meta':
                ## returning the columns on Model:
                fields = self.model.__fields__
                return self.json_response(content=fields)
        except KeyError:
            pass
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason=f"Invalid {self.name} Data",
                status=403
            )
        args = {}
        try:
            userid = data['user_id']
        except (TypeError, KeyError):
            try:
                userid = params['id']
            except KeyError:
                userid = None
        if userid:
            args = {
                'user_id': userid
            }
        db = self.request.app['authdb']
        if args:
            ## getting user
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                try:
                    result = await self.model.get(**args)
                except NoDataFound:
                    headers = {
                        "x-error": f"User was not Found: {args!r}"
                    }
                    self.no_content(
                        headers=headers
                    )
                if not result:
                    headers = {
                        "x-error": f"User was not Found: {args!r}"
                    }
                    self.no_content(
                        headers=headers
                    )
                ## saved with new changes:
                for key, val in data.items():
                    if key in result.get_fields():
                        if key == 'password':
                            passwd = set_basic_password(val)
                            result.set(key, passwd)
                        else:
                            result.set(key, val)
                data = await result.update()
                ## hidden password:
                data.password = None
                return self.json_response(content=data, status=202)
        else:
            self.error(
                reason="Invalid or missing User Data to Patch",
                status=403
            )

    async def delete(self):
        """ Delete a User."""
        session = await self.session()
        if not session:
            self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        params = self.match_parameters()
        try:
            data = await self.json_data()
        except AuthException:
            data = None
        except (TypeError, ValueError):
            self.error(
                reason="Invalid User Data",
                status=403
            )
        ## getting first the id from params or data:
        args = {}
        try:
            userid = data['user_id']
        except (TypeError, KeyError):
            try:
                userid = params['id']
            except KeyError:
                userid = None
        if userid:
            args = {
                'user_id': userid
            }
        db = self.request.app['authdb']
        if args:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                # look for this client, after, save changes
                result = await self.model.get(**args)
                if not result:
                    self.error(
                        reason="User was Not Found",
                        status=204
                    )
                # Delete them this Client
                data = await result.delete()
                return self.json_response(content=data, status=202)
        else:
            self.error(
                reason="Cannot Delete an missing User ID",
                status=404
            )

    async def put(self):
        """ Creating a New User."""
        session = await self.session()
        if not session:
            return self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid User Data",
                status=403
            )
        # first, validate with model:
        try:
            resultset = self.model(**data) # pylint: disable=E1102
            # set creation:
            resultset.created_by = session[SESSION_KEY]
        except ValidationError as ex:
            error = {
                "error": f"Unable to insert {self.name} info",
                "payload": ex.payload,
            }
            return self.error(
                reason=error,
                status=406
            )
        try:
            db = self.request.app['authdb']
            async with await db.acquire() as conn:
                resultset.Meta.connection = conn
                # changing the password:
                val = resultset.password
                if val:
                    resultset.password = set_basic_password(val)
                result = await resultset.insert()
                result.password = None
                return self.json_response(content=result, status=201)
        except StatementError as ex:
            # UniqueViolation, already exists:
            error = {
                "error": "User already exists",
                "payload": str(ex),
            }
            return self.error(
                exception=error,
                status=412
            )
        except (TypeError, AttributeError, ValueError) as ex:
            error = {
                "error": "Invalid payload for User",
                "payload": str(ex),
            }
            return self.error(
                exception=error,
                status=406
            )
        except (DriverError, ProviderError) as ex:
            error = {
                "error": "User Error",
                "payload": str(ex),
            }
            return self.error(
                exception=error,
                status=400
            )

    async def post(self):
        """ Create or Update a Client."""
        session = await self.session()
        if not session:
            return self.error(
                reason="Unauthorized",
                status=403
            )
        ### get session Data:
        params = self.match_parameters()
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid User Data",
                status=403
            )
        args = {}
        try:
            userid = data['user_id']
        except (TypeError, KeyError):
            try:
                userid = params['id']
            except KeyError:
                userid = None
        if userid:
            args = {
                'user_id': userid
            }
        db = self.request.app['authdb']
        if args:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                # look for this client, after, save changes
                error = {
                    "error": "User was not Found"
                }
                try:
                    result = await self.model.get(**args)
                except NoDataFound:
                    # create new Record
                    result = None
                if not result:
                    try:
                        resultset = self.model(**data) # pylint: disable=E1102
                        val = resultset.password
                        if val:
                            resultset.password = set_basic_password(val)
                        result = await resultset.insert()
                        result.password = None
                        return self.json_response(content=result, status=201)
                    except ValidationError as ex:
                        error = {
                            "error": f"Unable to insert {self.name} info",
                            "payload": ex.payload,
                        }
                        return self.error(
                            reason=error,
                            status=406
                        )
                ## saved with new changes:
                for key, val in data.items():
                    if key in result.get_fields():
                        if key == 'password':
                            if val:
                                pwd = set_basic_password(val)
                                result.set(key, pwd)
                        else:
                            result.set(key, val)
                data = await result.update()
                data.password = None
                return self.json_response(content=data, status=202)
        else:
            # create a new client based on data:
            try:
                resultset = self.model(**data) # pylint: disable=E1102
                async with await db.acquire() as conn:
                    resultset.Meta.connection = conn
                    val = resultset.password
                    if val:
                        resultset.password = set_basic_password(val)
                    result = await resultset.insert() # TODO: migrate to use save()
                    result.password = None
                    return self.json_response(content=result, status=201)
            except ValidationError as ex:
                error = {
                    "error": f"Unable to insert {self.name} info",
                    "payload": ex.payload,
                }
                return self.error(
                    reason=error,
                    status=406
                )
            except (TypeError, AttributeError, ValueError) as ex:
                error = {
                    "error": f"Invalid payload for {self.name}",
                    "payload": str(ex),
                }
                return self.error(
                    exception=error,
                    status=406
                )
            except (DriverError, ProviderError) as ex:
                error = {
                    "error": "User Error",
                    "payload": str(ex),
                }
                return self.error(
                    exception=error,
                    status=400
                )
