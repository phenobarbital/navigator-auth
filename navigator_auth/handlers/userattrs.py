from typing import Any
from navigator_auth.models import (
    UserAccount, UserIdentity, VwUserIdentity
)
from navigator_session import get_session, AUTH_SESSION_OBJECT
from navigator_auth.exceptions import AuthException
from datamodel.exceptions import ValidationError
from asyncdb.exceptions import DriverError, ProviderError, NoDataFound, StatementError
from .model import ModelHandler
from navigator_auth.conf import (
    AUTH_USER_IDENTITY_MODEL
)

class UserAccountHandler(ModelHandler):
    model: Any = UserAccount
    name: str = "User Accounts"
    pk: str = "account_id"

class UserIdentityHandler(ModelHandler):
    model: Any = UserIdentity
    model_name: str = AUTH_USER_IDENTITY_MODEL
    name: str = "User Identity"
    pk: str = "identity_id"

    async def get(self):
        db = self.request.app["database"]
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

                    return self.response(response=data, headers=headers, status=code)
                else:
                    headers = {"x-status": "OK", "x-message": "User Identity Data"}
                    print(UserIdentity)
                    return self.json_response(content=UserIdentity, headers=headers, status=200)
            except Exception as err:
                print(err)
                return self.error(exception=err, status=500)
    
    async def put(self):
        """Creating Model information."""
        session = await self.session()
        if not session:
            return self.error(reason="Unauthorized", status=403)
        ### get session Data:
        try:
            user_id = session[AUTH_SESSION_OBJECT]["user_id"]
        except (KeyError, TypeError):
            user_id = None
        try:
            data = await self.json_data()
            data['user_id'] = user_id
        except (TypeError, ValueError, AuthException):
            return self.error(reason=f"Invalid {self.name} Data", status=403)
        ## validate directly with model:
        try:
            print(data)
            resultset = self.model(**data)  # pylint: disable=E1102
            db = self.request.app["authdb"]
            async with await db.acquire() as conn:
                resultset.Meta.connection = conn
                result = await resultset.insert()
                return self.json_response(content=result, status=201)
        except ValidationError as ex:
            error = {
                "error": f"Unable to insert {self.name} info",
                "payload": ex.payload,
            }
            return self.error(reason=error, status=406)
        except StatementError as ex:
            # UniqueViolation, already exists:
            error = {
                "error": f"Record already exists for {self.name}",
                "payload": str(ex),
            }
            return self.error(exception=error, status=412)
        except (TypeError, AttributeError, ValueError) as ex:
            error = {
                "error": f"Invalid payload for {self.name}",
                "payload": str(ex),
            }
            return self.error(exception=error, status=406)

        
