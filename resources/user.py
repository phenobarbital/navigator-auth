from datetime import datetime
from asyncdb.models import Column, Model
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,
    AUTH_USERS_VIEW
)


class User(Model):
    """Basic User notation."""

    user_id: int = Column(required=False, primary_key=True)
    first_name: str
    last_name: str
    display_name: str
    email: str = Column(required=False, max=254)
    alt_email: str = Column(required=False, max=254)
    password: str = Column(required=False, max=128)
    last_login: datetime = Column(required=False)
    username: str = Column(required=False)
    is_superuser: bool = Column(required=True, default=False)
    is_active: bool = Column(required=True, default=True)
    is_new: bool = Column(required=True, default=True)
    is_staff: bool = Column(required=False, default=True)
    title: str = Column(equired=False, max=90)
    avatar: str = Column(max=512)
    associate_id: str = Column(required=False)
    associate_oid: str = Column(required=False)
    company: str = Column(required=False)
    department_code: str = Column(required=False)
    department: str = Column(required=False)
    position_id: str = Column(required=False)
    group_id: list = Column(required=False)
    groups: list = Column(required=False)
    # program_id: list = Column(required=False)
    programs: list = Column(required=False)
    # created_at: datetime = Column(required=False)
    date_joined: datetime = Column(required=False)

    class Meta:
        driver = "pg"
        name = AUTH_USERS_VIEW
        schema = AUTH_DB_SCHEMA
        strict = True
        frozen = False
        connection = None
