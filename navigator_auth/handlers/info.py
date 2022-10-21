from navigator_session import get_session
from datamodel.exceptions import ValidationError
from navigator_auth.models import User
from .base import BaseHandler


class UserInfo(BaseHandler):

    async def session(self, request):
        session = None
        try:
            session = await get_session(request)
        except (ValueError, RuntimeError) as err:
            return self.critical(
                request=request,
                exception=err
            )
        return session

    async def profile(self, request):
        session = await self.session(request)
        if not session:
            headers = {"x-status": "Empty", "x-message": "Invalid User Session"}
            return self.no_content(headers=headers)
        else:
            try:
                sessionid = session['id']
            except KeyError:
                return self.error('Invalid Session, missing Session ID')
        # getting User information
        try:
            user_id = request["user_id"]
        except KeyError:
            info = session[sessionid]
            user_id = info['user_id']
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
                request=request,
                exception=err
            )

    async def logout(self, request):
        """ Close and Delete User Session."""
        try:
            session = await self.session(request)
            session.invalidate()
        except Exception as err: # pylint: disable=W0703
            response = {
                "message": f"Exception on: {err.__class__.__name__}",
                "error": str(err)
            }
            args = {
                "status": 501,
                "content_type": "application/json",
                "text": self._json.dumps(response)
            }
            return self.json_response(**args)
        # return a redirect to LOGIN
        # TODO: configure the return of LOGOUT
        return self.redirect('/')
