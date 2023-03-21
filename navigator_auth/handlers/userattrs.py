from typing import Any
from navigator_auth.models import (
    UserAccount
)
from .model import ModelHandler


class UserAccountHandler(ModelHandler):
    model: Any = UserAccount
    name: str = "User Accounts"
    pk: str = "account_id"
