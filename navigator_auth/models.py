"""
Model System for Navigator Auth.

Model for User, Group and Roles for Navigator Auth.
"""
from uuid import UUID, uuid4
from typing import Optional
from datetime import datetime, timedelta
from enum import Enum
import jwt
from slugify import slugify
from datamodel.types import Text
from asyncdb.models import Model, Column
from .libs.cipher import Cipher
from .libs.json import json_encoder
from .conf import (
    AUTH_DB_SCHEMA,
    AUTH_USERS_TABLE,
    AUTH_GROUPS_TABLE,
    AUTH_DEFAULT_ISSUER,
    SECRET_KEY,
    AUTH_JWT_ALGORITHM,
    AUTH_TOKEN_SECRET,
)


def auto_uuid():
    return uuid4()

class UserType(Enum):
    USER = 1  # , 'user'
    CUSTOMER = 2  # , 'customer'
    STAFF = 3  # , 'staff'
    MANAGER = 4  # , 'manager'
    ADMIN = 5  # , 'admin'
    ROOT = 10  # , 'superuser'


class User(Model):
    """Basic User notation."""

    user_id: int = Column(
        required=False, primary_key=True, db_default="auto", repr=False
    )
    userid: UUID = Column(required=True, db_default="auto", repr=False)
    first_name: str = Column(required=False, max=254, label="First Name")
    last_name: str = Column(required=False, max=254, label="Last Name")
    display_name: str = Column(required=False, repr=False)
    email: str = Column(required=False, max=254, label="User's Email")
    alt_email: str = Column(required=False, max=254, label="Alternate Email")
    password: str = Column(required=False, max=16, secret=True, repr=False)
    username: str = Column(required=True)
    user_role: UserType = Column(required=False, widget="/properties/select")
    is_superuser: bool = Column(required=True, default=False)
    is_staff: bool = Column(required=False, default=True)
    title: str = Column(required=False, max=120)
    avatar: Text
    is_active: bool = Column(required=True, default=True)
    is_new: bool = Column(required=True, default=True)
    timezone: str = Column(required=False, max=75, default="UTC", repr=False)
    attributes: Optional[dict] = Column(required=False, default_factory=dict)
    created_at: datetime = Column(required=False, default=datetime.now())
    last_login: datetime = Column(
        required=False, readonly=True, default=datetime.now()
    )
    # created_by: str = Column(required=False)

    class Meta:
        name = AUTH_USERS_TABLE
        schema = AUTH_DB_SCHEMA
        description: str = 'User Schema'
        strict = True
        connection = None
        frozen = False


class UserIdentity(Model):
    identity_id: UUID = Column(
        required=False, primary_key=True, db_default="auto", repr=False
    )
    display_name: str = Column(required=False)
    title: str = Column(required=False)
    nickname: str = Column(required=False)
    email: str = Column(required=False)
    phone: str = Column(required=False)
    short_bio: Text = Column(required=False)
    avatar: Text = Column(required=False)
    user_id: User = Column(
        required=True, fk="user_id|username", api="users", label="User"
    )
    auth_provider: str = Column(required=False)
    auth_data: Optional[dict] = Column(required=False, repr=False)
    attributes: Optional[dict] = Column(required=False, repr=False)
    created_at: datetime = Column(
        required=False, default=datetime.now(), repr=False
    )

    class Meta:
        name = "user_identities"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False

class VwUserIdentity(Model):
    identity_id: UUID = Column(
        required=False, primary_key=True, db_default="auto", repr=False
    )
    display_name: str = Column(required=False)
    title: str = Column(required=False)
    nickname: str = Column(required=False)
    email: str = Column(required=False)
    phone: str = Column(required=False)
    short_bio: Text = Column(required=False)
    avatar: Text = Column(required=False)
    user_id: User = Column(
        required=True, fk="user_id|username", api="users", label="User"
    )
    accounts: Optional[dict] = Column(required=False, default_factory=dict)

    class Meta:
        name = "vw_user_identities"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


class UserDevices(Model):
    """Users can create API Keys or JWT Tokens with expiration for accessing."""

    user_id: User = Column(required=True, primary_key=True)
    device_id: UUID = Column(required=True, db_default="auto")
    name: str = Column(required=True)
    token: str = Column(required=False)
    api_key: str = Column(required=False)
    issuer: str = Column(required=False)
    revoked: bool = Column(required=True, default=False)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    def __post_init__(self) -> None:
        super(UserDevices, self).__post_init__()
        if not self.issuer:
            self.issuer = AUTH_DEFAULT_ISSUER
        if not self.token:
            payload = {
                "exp": datetime.utcnow() + timedelta(days=1460),
                "iat": datetime.utcnow(),
                "iss": self.issuer,
                "user_id": self.user_id,
                "device_id": str(self.device_id),
            }
            self.token = jwt.encode(
                payload,
                SECRET_KEY,
                AUTH_JWT_ALGORITHM,
            )
        if not self.api_key:
            ## generate the API key for Name:
            cipher = Cipher(AUTH_TOKEN_SECRET, type="AES")
            data = {"user_id": self.user_id, "device_id": self.device_id}
            self.api_key = cipher.encode(json_encoder(data))

    class Meta:
        name = "user_devices"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


class Group(Model):
    group_id: int = Column(
        required=True, primary_key=True, db_default="auto", repr=False
    )
    group_name: str = Column(required=True)
    is_active: bool = Column(required=True, default=True)
    client_id: int = Column(required=False)
    description: Text = Column(required=False)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = AUTH_GROUPS_TABLE
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


## User belong to Group:
class UserGroup(Model):
    user_id: User = Column(required=True, primary_key=True)
    group_id: Group = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = "user_groups"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


class Permission(Model):
    permission_id: int = Column(required=True, primary_key=True, db_default="auto")
    permission: str = Column(required=False, max=254, label="Permission")
    description: str
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())

    def __post_init__(self) -> None:
        super(Permission, self).__post_init__()
        if not self.permission:
            self.permission = slugify(self.description)

    class Meta:
        name = "permissions"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


class GroupPermission(Model):
    """Direct association between a permission and a Group."""

    group_id: Group = Column(required=True, primary_key=True)
    permission_id: Permission = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())

    class Meta:
        name = "group_permissions"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


class UserPermission(Model):
    """Direct asssociation between an User and a Permission."""

    user_id: User = Column(required=True, primary_key=True)
    permission_id: Permission = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())

    class Meta:
        name = "user_permissions"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False

class UserAttributes(Model):
    """Example of Extending User Model for adding more properties"""
    user_id: User = Column(required=True, primary_key=True)
    department_code: str = Column(required=False)
    position_id: str = Column(required=False)
    associate_id: str = Column(required=False)
    associate_oid: str = Column(required=False)
    attributes: Optional[dict] = Column(required=False, default_factory=dict)
    location_code: str = Column(required=False)
    job_code: str = Column(required=False)
    start_date: datetime = Column(required=False)
    birthday: str = Column(required=False)
    worker_type: str = Column(required=False)
    created_at: datetime = Column(required=False, default=datetime.now())

    class Meta:
        name = "user_attributes"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False


class UserAccount(Model):
    """Social Accounts from User"""
    account_id: UUID = Column(
        required=False, primary_key=True, db_default="auto", repr=False
    )
    user_id: User = Column(required=True)
    provider: str = Column(required=True)
    uid: str = Column(required=False)
    address: str = Column(required=False, repr=False)
    account: Optional[dict] = Column(required=False, default_factory=dict)
    created_at: datetime = Column(required=False, default=datetime.now(), repr=False)

    class Meta:
        name = "user_accounts"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False
