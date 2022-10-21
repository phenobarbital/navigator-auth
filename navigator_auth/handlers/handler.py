from navigator_session import get_session
from navigator_auth.conf import (
    SESSION_KEY
)
from .base import BaseView


class UserHandler(BaseView):

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
        return session

    async def get(self):
        """ Getting Session information."""
        session = await self.session()
        try:
            if not session:
                headers = {"x-status": "Empty", "x-message": "Invalid or Empty User Session"}
                return self.no_content(headers=headers)
            else:
                try:
                    _id = session[SESSION_KEY]
                except KeyError:
                    return self.error('Invalid Session, missing Session ID')
                headers = {"x-status": "OK", "x-message": "Session OK"}
                userdata = dict(session)
                data = {
                    "session_id": _id,
                    **userdata
                }
                if data:
                    return self.json_response(
                        response=data,
                        headers=headers
                    )
        except (ValueError, RuntimeError) as err:
            return self.error(
                request=self.request,
                exception=err
            )

    async def delete(self):
        """ Close and Delete User Session."""
        session = await self.session()
        try:
            app = self.request.app
            router = app.router
            session.invalidate()
            print(session)
        except (ValueError, RuntimeError) as err:
            print(err, err.__class__.__name__)
            return self.critical(
                request=self.request,
                exception=err,
                state=501
            )
        # return a redirect to LOGIN
        return self.redirect(router["login"].url_for())

    async def put(self):
        """Re-login and re-authenticate..."""
