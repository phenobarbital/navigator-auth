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
from asyncdb.models import Model, Column
from .libs.cipher import Cipher
from .libs.json import json_encoder
from .conf import (
    USERS_TABLE,
    AUTH_DEFAULT_ISSUER,
    SECRET_KEY,
    AUTH_JWT_ALGORITHM,
    AUTH_TOKEN_SECRET
)

class Text(str):
    """Base Definition for Big Text.
    """

## Create a TENANT as Main Level.

class Client(Model):
    """Highest hierarchy level."""
    client_id: int = Column(required=False, primary_key=True, db_default='auto')
    client: str = Column(required=True, max=254)
    description: Text
    auth_backends: list = Column(required=False)
    attributes: dict = Column(required=False)
    client_slug: str
    subdomain_prefix: str
    is_active: bool = Column(required=True, default=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)
    class Meta:
        name = 'clients'
        schema = "auth"
        strict = True
        connection = None

    def __post_init__(self) -> None:
        super(Client, self).__post_init__()
        if not self.client_slug:
            self.client_slug = slugify(self.client)

class Organization(Model):
    org_id: int = Column(required=False, primary_key=True, db_default='auto')
    oid: UUID = Column(required=True, db_default='auto')
    organization: str = Column(required=True, max=254)
    description: Text
    attributes: dict = Column(required=False, default_factory=dict)
    org_slug: str = Column(required=True, max=254)
    is_active: bool = Column(required=True, default=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)
    class Meta:
        name = 'organizations'
        schema = "auth"
        strict = True
        frozen = False

    def __post_init__(self) -> None:
        super(Organization, self).__post_init__()
        if not self.org_slug:
            self.org_slug = slugify(self.organization)

class ProgramCategory(Model):
    program_cat_id: int = Column(required=False, primary_key=True, db_default='auto')
    category: str = Column(required=True)
    class Meta:
        name = 'program_categories'
        schema = "auth"
        strict = True
        frozen = False

class Program(Model):
    program_id: int = Column(required=False, primary_key=True, db_default='auto')
    program_name: str
    description: Text
    attributes: dict = Column(required=False, default_factory=dict)
    program_slug: str
    program_cat_id: ProgramCategory = Column(required=True)
    is_active: bool = Column(required=True, default=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    def __post_init__(self) -> None:
        super(Program, self).__post_init__()
        if not self.program_slug:
            self.program_slug = slugify(self.program_name)
    class Meta:
        name = 'programs'
        schema = "auth"
        strict = True
        frozen = False

class ProgramAttribute(Model):
    program_id: Program = Column(required=True, primary_key=True)
    attribute: str = Column(required=True, max=254, primary_key=True)
    properties: dict = Column(required=False, default_factory=dict)
    created_by: str = Column(required=False)

    class Meta:
        name = 'program_attributes'
        schema = "auth"
        strict = True
        frozen = False

class ProgramClient(Model):
    program_id: Program = Column(required=True, primary_key=True)
    client_id: Client  = Column(required=True, primary_key=True)
    client_slug: str
    program_slug: str
    active: bool = Column(required=False, default=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = 'program_clients'
        schema = "auth"
        strict = True
        frozen = False

class UserType(Enum):
    USER = 1 #, 'user'
    CUSTOMER = 2 #, 'customer'
    STAFF  = 3 #, 'staff'
    MANAGER = 4 #, 'manager'
    ADMIN = 5 #, 'admin'
    ROOT = 10 #, 'superuser'

class User(Model):
    """Basic User notation."""

    user_id: int = Column(required=False, primary_key=True, db_default='auto')
    userid: UUID = Column(required=True, db_default='auto')
    first_name: str = Column(required=True, max=254, label="First Name")
    last_name: str = Column(required=True, max=254, label="Last Name")
    display_name: str = Column(required=False)
    email: str = Column(required=False, max=254, label="User's Email")
    alt_email: str = Column(required=False, max=254, label="Alternate Email")
    password: str = Column(required=False, max=16, secret=True, repr=False)
    last_login: datetime = Column(required=False, readonly=True, default=datetime.now())
    username: str = Column(required=False)
    user_role: UserType = Column(required=False)
    is_superuser: bool = Column(required=True, default=False)
    is_staff: bool = Column(required=False, default=True)
    title: str = Column(required=False, max=120)
    registration_key: str = Column(required=False, max=512)
    challenge_key: str = Column(required=False, max=512)
    avatar: Text = Column(max=2048)
    is_active: bool = Column(required=True, default=True)
    is_new: bool = Column(required=True, default=True)
    timezone: str = Column(required=False, max=75, default='UTC')
    attributes: Optional[dict] = Column(required=False, default_factory=dict)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = USERS_TABLE
        schema = "auth"
        strict = True
        connection = None

class UserIdentity(Model):
    user_id: User = Column(required=True)
    auth_provider: str = Column(required=True, default='BasicAuth')
    uid: str = Column(required=True, comment='User Id on Auth Backend')
    auth_data: Optional[dict] = Column(required=False, default_factory=dict)
    attributes: Optional[dict] = Column(required=False, default_factory=dict)
    created_at: datetime = Column(required=False, default=datetime.now())

    class Meta:
        name = "user_identities"
        schema = "auth"
        strict = True
        connection = None


def auto_uuid():
    return uuid4()
class UserDevices(Model):
    """Users can create API Keys or JWT Tokens with expiration for accessing.
    """
    user_id: User = Column(required=True, primary_key=True)
    device_id: UUID = Column(required=True, db_default='auto')
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
                "device_id": str(self.device_id)
            }
            self.token = jwt.encode(
                payload,
                SECRET_KEY,
                AUTH_JWT_ALGORITHM,
            )
        if not self.api_key:
            ## generate the API key for Name:
            cipher = Cipher(AUTH_TOKEN_SECRET, type='AES')
            data = {
                "user_id": self.user_id,
                "device_id": self.device_id
            }
            self.api_key = cipher.encode(json_encoder(data))

    class Meta:
        name = "user_devices"
        schema = "auth"
        strict = True
        connection = None


class OrganizationUser(Model):
    org_id: Organization = Column(required=True)
    user_id: User = Column(required=True)
    properties: dict = Column(required=False, default_factory=dict)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = 'organization_users'
        schema = "auth"
        strict = True
        frozen = False

class Group(Model):
    group_id: int = Column(required=True, primary_key=True, db_default='auto')
    group_name: str = Column(required=True)
    client_id: Optional[Client] = Column(required=False)
    is_active: bool = Column(required=True, default=True)
    description: Text = Column(required=False)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = "groups"
        schema = "auth"
        strict = True
        connection = None

## User belong to Group:
class UserGroup(Model):
    user_id: User = Column(required=True, primary_key=True)
    group_id: Group = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = "user_groups"
        schema = "auth"
        strict = True
        connection = None

class ProgramGroup(Model):
    program_id: Program = Column(required=True, primary_key=True)
    group_id: Group = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    created_by: str = Column(required=False)

    class Meta:
        name = "program_groups"
        schema = "auth"
        strict = True
        connection = None

class Permission(Model):
    permission_id: int = Column(required=True, primary_key=True, db_default='auto')
    permission: str = Column(required=False, max=254, label="Permission")
    description: str
    program_id: Program = Column(required=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())

    def __post_init__(self) -> None:
        super(Permission, self).__post_init__()
        if not self.permission:
            self.permission = slugify(self.description)

    class Meta:
        name = "permissions"
        schema = "auth"
        strict = True
        connection = None

class GroupPermission(Model):
    """Direct association between a permission and a Group (associated to a Program).
    """
    group_id: Group = Column(required=True, primary_key=True)
    permission_id: Permission = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())

    class Meta:
        name = "group_permissions"
        schema = "auth"
        strict = True
        connection = None

class UserPermission(Model):
    """Direct asssociation between an User and a Permission.
    """
    user_id: User = Column(required=True, primary_key=True)
    permission_id: Permission = Column(required=True, primary_key=True)
    created_at: datetime = Column(required=False, default=datetime.now())
    updated_at: datetime = Column(required=False, default=datetime.now())

    class Meta:
        name = "user_permissions"
        schema = "auth"
        strict = True
        connection = None
