from typing import Any
from asyncdb.exceptions import (
    NoDataFound
)
from asyncdb.exceptions import DriverError
from navigator_session import (
    get_session,
    AUTH_SESSION_OBJECT
)
from ..models import (
    UserAccount, UserIdentity, VwUserIdentity
)
from ..conf import (
    AUTH_USER_IDENTITY_MODEL
)
from .model import ModelHandler


class UserAccountHandler(ModelHandler):
    model: Any = UserAccount
    name: str = "User Account"
    pk: str = "account_id"

    async def _get_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    async def _get_address(self, value, column, data):
        db = self.request.app['authdb']
        try:
            userid = data['uid']
        except KeyError:
            return self.error(
                reason=f"Invalid User ID for {self.name}", status=410
            )
        try:
            provider = data['provider']
        except KeyError:
            provider = None
        if provider:
            try:
                async with await db.acquire() as conn:
                    qry = f"SELECT social_url FROM auth.social_networks WHERE social_network = '{provider}'"
                    result = await conn.fetchval(qry, column='social_url')
                    return result.format(uid=userid)
            except DriverError:
                pass
            except Exception as ex:
                self.logger.error(str(ex))
        return None

    async def get(self):
        db = self.request.app["authdb"]
        params = self.match_parameters(self.request)
        try:
            if params["meta"] == ":meta":
                response = self.model.schema(as_dict=True)
                return self.json_response(content=response)
        except KeyError:
            pass
        try:
            session = await self.session()
            user_id = await self.get_userid(session=session)
        except (KeyError, TypeError):
            user_id = None

        args = {}
        if isinstance(self.pk, str):
            try:
                objid = params["id"]
            except KeyError:
                objid = None
            if objid:
                args = {self.pk: objid}
        elif isinstance(self.pk, list):
            try:
                paramlist = params["id"].split("/")
                if len(paramlist) != len(self.pk):
                    return self.error(
                        reason=f"Invalid Number of URL elements for PK: {self.pk}, {paramlist!r}",
                        status=410,
                    )
                args = {}
                for key in self.pk:
                    args[key] = paramlist.pop(0)
            except KeyError:
                pass
        else:
            return self.error(
                reason=f"Invalid PK definition for {self.name}: {self.pk}", status=410
            )
        if args:
            # get data for specific client:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn
                # look for this client, after, save changes
                error = {"error": f"{self.name} was not Found"}
                try:
                    result = await self.model.get(**args)
                except NoDataFound:
                    self.error(exception=error, status=403)
                if not result:
                    self.error(exception=error, status=403)
                return self.json_response(content=result)
        else:
            async with await db.acquire() as conn:
                self.model.Meta.connection = conn

                try:
                    filter = {
                        "user_id": user_id
                    }
                    UserAccounts = await self.model.filter(**filter)
                    if not UserAccounts:
                        headers = {
                            "X-STATUS": "EMPTY",
                            "X-MESSAGE": "UserAccounts not Found",
                        }
                        data = {"message": "No Content"}
                        code = 204

                        return self.response(
                            response=data, headers=headers, status=code
                        )
                    else:
                        headers = {"x-status": "OK", "x-message": "User Account Data"}
                        return self.json_response(
                            content=UserAccounts, headers=headers, status=200
                        )
                except Exception as err:
                    print(err)
                    return self.error(exception=err, status=500)


class UserIdentityHandler(ModelHandler):
    model: Any = UserIdentity
    model_name: str = AUTH_USER_IDENTITY_MODEL
    name: str = "User Identity"
    pk: str = "identity_id"

    async def _get_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    async def get(self):
        db = self.request.app["authdb"]
        params = self.match_parameters(self.request)
        try:
            if params["meta"] == ":meta":
                # returning JSON schema of Model:
                response = self.model.schema(as_dict=True)
                return self.json_response(content=response)
        except KeyError:
            pass
        try:
            session = await get_session(self.request)
            user_id = session[AUTH_SESSION_OBJECT]["user_id"]
        except (KeyError, TypeError):
            user_id = None

        args = {}
        if isinstance(self.pk, str):
            try:
                objid = params["id"]
            except KeyError:
                objid = None
            if objid:
                args = {self.pk: objid}
        elif isinstance(self.pk, list):
            try:
                paramlist = params["id"].split("/")
                if len(paramlist) != len(self.pk):
                    return self.error(
                        reason=f"Invalid Number of URL elements for PK: {self.pk}, {paramlist!r}",
                        status=410,
                    )
                args = {}
                for key in self.pk:
                    args[key] = paramlist.pop(0)
            except KeyError:
                pass
        else:
            return self.error(
                reason=f"Invalid PK definition for {self.name}: {self.pk}", status=410
            )
        if args:
            # get data for specific client:
            async with await db.acquire() as conn:
                VwUserIdentity.Meta.connection = conn
                # look for this client, after, save changes
                error = {"error": f"{self.name} was not Found"}
                try:
                    result = await VwUserIdentity.get(**args)
                except NoDataFound:
                    self.error(exception=error, status=403)
                if not result:
                    self.error(exception=error, status=403)
                return self.json_response(content=result)
        else:
            async with await db.acquire() as conn:
                VwUserIdentity.Meta.connection = conn
                try:
                    filter = {
                        "user_id": user_id
                    }
                    UserIdentity = await VwUserIdentity.filter(**filter)
                    if not UserIdentity:
                        headers = {
                            "X-STATUS": "EMPTY",
                            "X-MESSAGE": "UserIdentity not Found",
                        }
                        data = {"message": "No Content"}
                        code = 204

                        return self.response(
                            response=data, headers=headers, status=code
                        )
                    else:
                        headers = {"x-status": "OK", "x-message": "User Identity Data"}
                        return self.json_response(
                            content=UserIdentity, headers=headers, status=200
                        )
                except Exception as err:
                    print(err)
                    return self.error(exception=err, status=500)
