from typing import Any
from datamodel.exceptions import ValidationError
from navigator_session import get_session, SESSION_KEY, AUTH_SESSION_OBJECT
from navigator_auth.exceptions import AuthException
from navigator_auth.models import User
from .model import ModelHandler
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


class UserHandler(ModelHandler):
    """
    Main Class for Managing Users.
    """
    model: Any = User
    name: str = 'Users'
    pk: str = 'user_id'
