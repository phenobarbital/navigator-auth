import time
from urllib.parse import urlparse
from aiohttp import web
from datamodel.exceptions import ValidationError
from navigator_session import get_session, SESSION_KEY, AUTH_SESSION_OBJECT
from navigator.views import BaseHandler
from ...exceptions import AuthException
from ...libs.cipher import Cipher
from ...models import User
from ...conf import (
    PARTNER_KEY,
    PREFERRED_AUTH_SCHEME,
    TROCTOKEN_REDIRECT_URI
)
from .passwd import check_password, set_basic_password


class UserSession(BaseHandler):
    async def session(self, request):
        session = None
        try:
            session = await get_session(request)
        except (ValueError, RuntimeError) as err:
            return self.critical(
                reason="Error Decoding Session", request=self.request, exception=err
            )
        if not session:
            headers = {
                "x-status": "Empty",
                "x-message": "Invalid or Empty User Session",
            }
            return self.error(reason="Unauthorized", headers=headers, status=403)
        else:
            try:
                _id = session[SESSION_KEY]
            except KeyError:
                headers = {
                    "x-status": "Bad Session",
                    "x-message": "Invalid User Session",
                }
                return self.error(
                    reason="Invalid Session, missing User Session Key",
                    headers=headers,
                    status=403,
                )
            return session

    async def in_session(self, request: web.Request):
        """Adding (put) information (persistence) to User Session."""
        session = await self.session(request)
        try:
            data = await self.json_data()
        except (TypeError, ValueError, AuthException):
            return self.error(reason="Invalid or Empty Session Data", status=406)
        for k, value in data.items():
            session[k] = value
        headers = {"x-status": "OK", "x-message": "Session Saved"}
        return self.json_response(response=data, headers=headers)

    def get_domain(self, request: web.Request) -> str:
        uri = urlparse(str(request.url))
        domain_url = f"{PREFERRED_AUTH_SCHEME}://{uri.netloc}"
        self.logger.debug(
            f"DOMAIN: {domain_url}"
        )
        return domain_url

    async def gen_token(self, request: web.Request):
        """Generate a RCCRYPT TOKEN from Email account."""
        session = await self.session(request)
        params = self.match_parameters(request)
        try:
            userid = params["userid"]
        except KeyError:
            userid = None
        ### TODO: check if user is superuser:
        userinfo = session[AUTH_SESSION_OBJECT]
        if userinfo["superuser"] is False:
            return self.error(
                reason="Access Denied",
                status=406
            )
        try:
            db = request.app["authdb"]
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=userid)
                data = {
                    "magic": "Navigator",
                    "firstName": user.first_name,
                    "lastName": user.last_name,
                    "email": user.email,
                    "username": user.username,
                    "timestamp": str(time.time()),
                }
                cipher = Cipher(PARTNER_KEY, type="RNC")
                rnc = cipher.encode(self._json.dumps(data))
                headers = {"x-status": "OK", "x-message": "Token Generated"}
                token = rnc.upper()
                api_url = self.get_domain(request)
                red = TROCTOKEN_REDIRECT_URI
                response = {
                    "token": token,
                    "uri": f"{api_url}/api/v1/login?auth={token}&redirect_uri={red}"
                }
                return self.json_response(response=response, headers=headers)
        except ValidationError as ex:
            self.error(
                reason="User info has errors",
                exception=ex.payload,
                status=412
            )
        except Exception as err:  # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User: {err}",
                exception=err
            )

    async def password_change(self, request: web.Request):
        """Reset User Password."""
        session = await self.session(request)
        params = self.match_parameters(request)
        try:
            userid = params["userid"]
        except KeyError:
            userid = None
        try:
            data = await self.get_json(request)
            new_password = data["password"]
            old_password = data["old_password"]
        except (TypeError, ValueError, AuthException):
            return self.error(reason="Invalid User Data", status=406)
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
            user_id = userinfo["user_id"]
        except KeyError:
            return self.error(
                reason="Invalid Session, missing Session ID",
                status=406
            )
        ## validating user Id:
        if userid is not None and userid != user_id:
            return self.error(
                reason="Forbidden: User ID from session and URL doesn't match.",
                status=403,
            )
        try:
            db = request.app["authdb"]
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                if check_password(user.password, old_password):
                    # valid, can change password
                    user.password = set_basic_password(new_password)
                    await user.update()
                    headers = {"x-status": "OK", "x-message": "Session OK"}
                    response = {"action": "Password Changed", "status": "OK"}
                    return self.json_response(
                        response=response, headers=headers, status=202
                    )
                else:
                    return self.error(
                        reason="Forbidden: Current Password doesn't match.", status=403
                    )
        except ValidationError as ex:
            self.error(reason="User info has errors", exception=ex.payload, status=412)
        except Exception as err:  # pylint: disable=W0703
            return self.critical(reason=f"Error getting User: {err}", exception=err)

    async def password_reset(self, request: web.Request):
        """Reset User Password."""
        session = await self.session(request)
        params = self.match_parameters(request)
        try:
            userid = params["userid"]
        except KeyError:
            userid = None
        try:
            data = await self.json_data(request)
            new_password = data["password"]
        except (TypeError, ValueError, AuthException):
            return self.error(
                reason="Invalid User",
                status=406
            )
        ### TODO: check if user is superuser:
        userinfo = session[AUTH_SESSION_OBJECT]
        if userinfo["superuser"] is False:
            return self.error(
                reason="Access Denied, Session Missing",
                status=406
            )
        try:
            db = request.app["authdb"]
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=userid)
                if not user:
                    return self.error(
                        reason="User not found",
                        status=404
                    )
                ## Reset Password:
                user.password = set_basic_password(new_password)
                user.is_new = True
                await user.update()
                headers = {"x-status": "OK", "x-message": "Session OK"}
                response = {
                    "action": "Password was changed successfully",
                    "user": user.user_id,
                    "username": user.username,
                    "status": "OK",
                }
                return self.json_response(
                    response=response,
                    headers=headers,
                    status=202
                )
        except ValidationError as ex:
            self.error(
                reason="User data has errors",
                exception=ex.payload,
                status=412
            )
        except Exception as err:  # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User: {err}",
                exception=err
            )

    async def user_session(self, request: web.Request):
        """Getting User Session information."""
        session = await self.session(request)
        ## get session Data:
        headers = {"x-status": "OK", "x-message": "Session OK"}
        userdata = dict(session)
        _id = session[SESSION_KEY]
        data = {"session_id": _id, **userdata}
        if data:
            return self.json_response(response=data, headers=headers)
        else:
            return self.error(reason="Empty Session", status=406)

    async def user_profile(self, request: web.Request):
        """Getting User Profile."""
        session = await self.session(request)
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
            user_id = userinfo["user_id"]
        except KeyError:
            return self.error(reason="Invalid Session, missing Session ID", status=406)
        try:
            db = request.app["authdb"]
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                user.password = None
                return self.json_response(response=user, status=200)
        except ValidationError as ex:
            self.error(reason="User info has errors", exception=ex.payload, status=412)
        except Exception as err:  # pylint: disable=W0703
            return self.critical(
                reason=f"Error getting User Profile: {err}", exception=err
            )

    async def logout(self, request: web.Request):
        """Logout: Close and Delete User Session."""
        session = await self.session(request)
        app = request.app
        router = app.router
        try:
            session.invalidate()
            app["session"] = None
        except (ValueError, RuntimeError) as err:
            return self.critical(exception=err, status=501)
        # return a redirect to LOGIN
        return self.redirect(router["login"].url_for())
