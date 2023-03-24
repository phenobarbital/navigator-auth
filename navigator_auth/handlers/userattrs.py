from typing import Any
from navigator_auth.models import (
    UserAccount, UserIdentity, VwUserIdentity
)
from navigator_session import get_session, AUTH_SESSION_OBJECT
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
        
