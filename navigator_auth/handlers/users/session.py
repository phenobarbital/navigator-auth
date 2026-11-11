import time
import secrets
from urllib.parse import urlparse
from aiohttp import web
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError
from navigator_session import get_session, SESSION_KEY, AUTH_SESSION_OBJECT
from navigator.views import BaseHandler
from ...exceptions import AuthException
from ...libs.cipher import Cipher
from ...models import User
from ...conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, PARTNER_KEY, PREFERRED_AUTH_SCHEME, TROCTOKEN_REDIRECT_URI
from .passwd import check_password, set_basic_password
from ...mfa.events import TransitionAborted, security_transition
from ...mfa.exceptions import MfaStorageError
from ...security_state.store import SecurityStateError, increment_generation
from ..recovery.handler import PasswordRecoveryHandler
from ..recovery.revoke import RevocationError

_USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"


class UserSession(BaseHandler):
    async def session(self, request):
        session = None
        try:
            session = await get_session(request)
        except (ValueError, RuntimeError) as err:
            return self.critical(reason="Error Decoding Session", request=self.request, exception=err)
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
        self.logger.debug(f"DOMAIN: {domain_url}")
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
            return self.error(reason="Access Denied", status=406)
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
                response = {"token": token, "uri": f"{api_url}/api/v1/login?auth={token}&redirect_uri={red}"}
                return self.json_response(response=response, headers=headers)
        except ValidationError as ex:
            self.error(reason="User info has errors", exception=ex.payload, status=412)
        except Exception as err:  # pylint: disable=W0703
            return self.critical(reason=f"Error getting User: {err}", exception=err)

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
            return self.error(reason="Invalid Session, missing Session ID", status=406)
        ## validating user Id:
        if userid is not None and userid != user_id:
            return self.error(
                reason="Forbidden: User ID from session and URL doesn't match.",
                status=403,
            )
        db = request.app["authdb"]
        try:
            # Phase 1: read + validate on a pooled connection, released before the lock.
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                if not check_password(user.password, old_password):
                    return self.error(reason="Forbidden: Current Password doesn't match.", status=403)
                target_id = user.user_id
                captured = user.password
            new_hash = set_basic_password(new_password)
            # Phase 2: one transaction containing the password and MFA bookkeeping.
            async with security_transition(request.app, target_id, "password_change", actor_user_id=target_id) as conn:
                current = await conn.fetchval(f"SELECT password FROM {_USERS} WHERE user_id = $1 FOR UPDATE", target_id)
                if current is None or not secrets.compare_digest(str(current), str(captured or "")):
                    raise TransitionAborted("credentials_changed")
                await conn.fetchval(
                    f"UPDATE {_USERS} SET password = $2 WHERE user_id = $1 RETURNING user_id", target_id, new_hash
                )
            headers = {"x-status": "OK", "x-message": "Session OK"}
            response = {"action": "Password Changed", "status": "OK"}
            return self.json_response(response=response, headers=headers, status=202)
        except TransitionAborted as aborted:
            return self.json_response(response={"error": aborted.reason}, status=409)
        except MfaStorageError:
            return self.json_response(response={"error": "mfa_unavailable"}, status=503)
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
            return self.error(reason="Invalid User", status=406)
        ### TODO: check if user is superuser:
        userinfo = session[AUTH_SESSION_OBJECT]
        if userinfo["superuser"] is False:
            return self.error(reason="Access Denied, Session Missing", status=406)
        db = request.app["authdb"]
        try:
            # Phase 1: existence check only, on a connection released before the lock.
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                try:
                    user = await User.get(user_id=userid)
                except NoDataFound:
                    user = None
                if not user:
                    return self.error(reason="User not found", status=404)
                captured = user.password
            new_hash = set_basic_password(new_password)
            revoker = PasswordRecoveryHandler.session_revoker()
            async with security_transition(
                request.app, user.user_id, "password_reset", actor_user_id=userinfo.get("user_id")
            ) as conn:
                current = await conn.fetchval(
                    f"SELECT password FROM {_USERS} WHERE user_id = $1 FOR UPDATE", user.user_id
                )
                if current is None or not secrets.compare_digest(str(current), str(captured or "")):
                    raise TransitionAborted("credentials_changed")
                await conn.fetchval(
                    f"UPDATE {_USERS} SET password = $2, is_new = true WHERE user_id = $1 RETURNING user_id",
                    user.user_id,
                    new_hash,
                )
                await increment_generation(conn, user.user_id)
                await revoker.revoke_user(request, user, strict=True)
            headers = {"x-status": "OK", "x-message": "Session OK"}
            response = {
                "action": "Password was changed successfully",
                "user": user.user_id,
                "username": user.username,
                "status": "OK",
            }
            return self.json_response(response=response, headers=headers, status=202)
        except TransitionAborted as aborted:
            return self.json_response(response={"error": aborted.reason}, status=409)
        except MfaStorageError:
            return self.json_response(response={"error": "mfa_unavailable"}, status=503)
        except (RevocationError, SecurityStateError) as err:
            self.logger.error(f"password_reset rolled back for user {user.user_id}: {type(err).__name__}")
            return self.json_response(response={"error": "temporarily_unavailable"}, status=503)
        except ValidationError as ex:
            self.error(reason="User data has errors", exception=ex.payload, status=412)
        except Exception as err:  # pylint: disable=W0703
            return self.critical(reason=f"Error getting User: {err}", exception=err)

    async def user_session(self, request: web.Request):
        """Getting User Session information."""
        session = await self.session(request)
        ## get session Data:
        headers = {"x-status": "OK", "x-message": "Session OK"}
        userdata = session.session_data()
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
            return self.critical(reason=f"Error getting User Profile: {err}", exception=err)

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
