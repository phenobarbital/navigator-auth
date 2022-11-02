from typing import Any
import importlib
from datamodel.exceptions import ValidationError
from navigator_session import get_session, SESSION_KEY, AUTH_SESSION_OBJECT
from asyncdb.exceptions import (
    DriverError,
    ProviderError,
    NoDataFound,
    StatementError
)
from navigator_auth.exceptions import AuthException
from navigator_auth.models import User
from navigator_auth.conf import AUTH_USER_MODEL
from .base import BaseView



class UserSession(BaseView):

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
                _id = session[SESSION_KEY]
            except KeyError:
                headers = {"x-status": "Bad Session", "x-message": "Invalid User Session"}
                return self.error(
                    reason='Invalid Session, missing User Session Key',
                    headers=headers,
                    status=403
                )
            return session


    async def put(self):
        """ Adding (put) information (persistence) to User Session."""
        session = await self.session()
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

    async def patch(self):
        """ Changing User Attributes or Reset Password. """
        session = await self.session()
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid or Empty Session Data",
                status=406
            )
        ## Attributes: Password, is_new, is_active (disable user)

    async def get(self):
        """ Getting User Session information or User Profile."""
        session = await self.session()
        params = self.match_parameters()
        try:
            if params['meta'] == ':profile':
                ## Need to return instead User Profile
                try:
                    userinfo = session[AUTH_SESSION_OBJECT]
                    user_id = userinfo['user_id']
                except KeyError:
                    return self.error(
                        reason = 'Invalid Session, missing Session ID',
                        status=406
                    )
                try:
                    user = await User.get(user_id=user_id)
                    return self.json_response(
                        content=user.json(ensure_ascii=True, indent=4),
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
                        reason="Error getting User Profile",
                        exception=err
                    )
        except KeyError:
            pass
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

    async def delete(self):
        """ Logout: Close and Delete User Session."""
        session = await self.session()
        app = self.request.app
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
                        result.set(key, val)
                data = await result.update()
                return self.json_response(content=data, status=202)
        else:
            self.error(
                reason="Invalid or missing User Data to Patch",
                status=403
            )

    async def delete(self):
        """ Delete a Client."""
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
