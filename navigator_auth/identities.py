from typing import Any, List, Optional, Union
from collections.abc import Mapping
from dataclasses import InitVar
from slugify import slugify
from datamodel import BaseModel, Column
from datamodel.exceptions import ValidationError


class AuthBackend(BaseModel):
    name: str
    uri: str
    description: str
    icon: str
    external: bool = Column(required=True, default=False)
    headers: dict = Column(required=False, default_factory=dict)

    class Meta:
        strict = True
        frozen = False


class Group(BaseModel):
    """Group.

    Association (group) were users belongs to.
    """

    group: str = Column(required=True)

    class Meta:
        strict = True
        frozen = False


# create a Guest Group.
Guest = Group(group="guest")


class Organization(BaseModel):
    org_id: str = Column(required=True)
    organization: str = Column(required=True)
    slug: str = Column(required=False)

    def __post_init__(self) -> None:
        super(Organization, self).__post_init__()
        if not self.slug:
            self.slug = slugify(self.organization)

    class Meta:
        strict = True
        frozen = False


def _coerce_organization(org: Any) -> Organization:
    """Return *org* as an ``Organization``.

    Args:
        org: An ``Organization`` instance (returned unchanged, same object) or a
            ``Mapping`` with the model's fields (``org_id``, ``organization``,
            optional ``slug``). The mapping is copied; the caller's object is
            never mutated.

    Returns:
        A valid ``Organization``.

    Raises:
        TypeError: *org* is neither an ``Organization`` nor a ``Mapping``
            (this includes ``str`` — the former string shortcut is gone).
        ValueError: the mapping cannot build a valid ``Organization``
            (missing required field, unknown key, model validation error),
            or ``org_id`` / ``organization`` is empty or whitespace-only.
            The original exception, when any, is chained.
    """
    if isinstance(org, Organization):
        result = org
    elif isinstance(org, Mapping):
        try:
            result = Organization(**dict(org))
        except (ValueError, TypeError, ValidationError) as err:
            raise ValueError(f"Invalid organization entry {org!r}: {err}") from err
    else:
        raise TypeError("organization must be an Organization or a mapping, " f"got {type(org).__name__}")
    if str(result.org_id).strip() == "" or str(result.organization).strip() == "":
        raise ValueError(f"Invalid organization entry {org!r}: empty org_id/organization")
    return result


def _coerce_group(group: Any) -> Group:
    """Return *group* as a ``Group``.

    Args:
        group: A ``Group`` (returned unchanged), a non-empty ``str`` (becomes
            ``Group(group=<str>)``) or a ``Mapping`` with the model's fields.

    Raises:
        TypeError: any other type.
        ValueError: the mapping cannot build a ``Group``, or the resulting
            ``group`` name is empty / whitespace-only (chained when possible).
    """
    if isinstance(group, Group):
        result = group
    elif isinstance(group, str):
        result = Group(group=group)
    elif isinstance(group, Mapping):
        try:
            result = Group(**dict(group))
        except (ValueError, TypeError, ValidationError) as err:
            raise ValueError(f"Invalid group entry {group!r}: {err}") from err
    else:
        raise TypeError(f"group must be a Group, str or mapping, got {type(group).__name__}")
    if str(result.group).strip() == "":
        raise ValueError(f"Invalid group entry {group!r}: empty group")
    return result


def _coerce_program(program: Any) -> "Program":
    """Return *program* as a ``Program``.

    An instance is kept; a ``Mapping`` becomes ``Program(**dict(program))``.

    Raises:
        TypeError: not a ``Program`` or ``Mapping`` (``str`` included —
            ``program_id`` is required).
        ValueError: the mapping cannot build a ``Program``, or
            ``program_name`` is empty / whitespace-only.
    """
    if isinstance(program, Program):
        result = program
    elif isinstance(program, Mapping):
        try:
            result = Program(**dict(program))
        except (ValueError, TypeError, ValidationError) as err:
            raise ValueError(f"Invalid program entry {program!r}: {err}") from err
    else:
        raise TypeError("program must be a Program or a mapping, " f"got {type(program).__name__}")
    if str(result.program_name).strip() == "":
        raise ValueError(f"Invalid program entry {program!r}: empty program_name")
    return result


class Program(BaseModel):
    program_id: int = Column(required=True)
    program_name: str = Column(required=True)
    program_slug: str = Column(required=False)

    def __post_init__(self) -> None:
        super(Program, self).__post_init__()
        if not self.program_slug:
            self.program_slug = slugify(self.program_name)

    class Meta:
        strict = True
        frozen = False


class Identity(BaseModel):
    """Identity.

    Describe an Authenticated Entity on Navigator.
    """

    id: Any = Column(required=True)
    auth_method: str = None
    access_token: Optional[str] = None
    enabled: bool = Column(required=True, default=True)
    data: InitVar = {}
    is_authenticated: bool = Column(equired=False, default=False)
    userdata: dict = Column(required=False, default_factory=dict)

    def __post_init__(self, data):  # pylint: disable=W0221
        self.userdata = data
        for key, value in data.items():
            self.create_field(key, value)

    def set(self, name: str, value: Any) -> None:
        # alias for "create_field"
        self.create_field(name, value)

    class Meta:
        strict = False
        frozen = False


class AuthUser(Identity):
    """AuthUser

    Model for any Authenticated User.

    Organizations: every element of ``organizations`` is an ``Organization``;
    mappings are coerced in ``add_organization`` (``str`` entries raise
    ``TypeError``, invalid mappings raise ``ValueError``). Sessions written
    before FEAT-102 may hold dicts — navigator-auth normalizes them in its
    own rehydration points; code that calls ``session.decode('user')``
    directly must call ``normalize_memberships()`` or wait for re-login /
    session expiry.
    """

    first_name: str
    last_name: str
    display_name: str
    name: str
    email: str
    username: str
    groups: List[Group] = Column(required=False, default_factory=list)
    organizations: List[Organization] = Column(required=False, default_factory=list)
    superuser: bool = Column(required=True, default=False)

    class Meta:
        strict = False
        frozen = False

    def __post_init__(self, data) -> None:
        super(AuthUser, self).__post_init__(data)
        if self.groups is not None:
            groups = self.groups.copy()
            self.groups = []
            for group in groups:
                self.add_group(group)
        else:
            self.groups = []
        if self.organizations is not None:
            org = self.organizations.copy()
            self.organizations = []
            for o in org:
                self.add_organization(o)
        else:
            self.organizations = []

    ### User Methods.
    def add_group(self, group: Union[Group, str, Mapping[str, Any]]) -> None:
        """Append *group* to ``self.groups`` as a ``Group`` (see :func:`_coerce_group`)."""
        self.groups.append(_coerce_group(group))

    def normalize_groups(self) -> None:
        """Re-run group normalization over ``self.groups`` (idempotent, atomic; ``None`` → ``[]``)."""
        current = list(self.groups or [])
        self.groups = [_coerce_group(g) for g in current]

    def add_organization(self, org: Union[Organization, Mapping[str, Any]]) -> None:
        """Append *org* to ``self.organizations`` as an ``Organization``.

        Delegates to :func:`_coerce_organization`; see it for accepted inputs
        and raised errors. Idempotent for already-valid instances.
        """
        self.organizations.append(_coerce_organization(org))

    def normalize_organizations(self) -> None:
        """Re-run organization normalization over ``self.organizations``.

        Intended for objects rehydrated without ``__post_init__`` (jsonpickle
        session payloads written before FEAT-102). Idempotent: a list that is
        already all ``Organization`` is rebuilt with the same objects. A
        ``None`` list becomes ``[]``.

        Raises:
            ValueError, TypeError: as :func:`_coerce_organization`; the list
                is left as it was before the call when an entry fails.
        """
        current = list(self.organizations or [])
        self.organizations = [_coerce_organization(o) for o in current]

    def normalize_memberships(self) -> None:
        """Normalize every membership list of this user in place.

        Covers organizations and groups; subclasses with more membership
        lists override and call ``super()``. This is the method the session
        rehydration hooks call. Idempotent; raises like the parts
        (``ValueError`` / ``TypeError``) and is atomic: every list is
        rebuilt first and assigned only when all of them are valid.
        """
        organizations = [_coerce_organization(o) for o in list(self.organizations or [])]
        groups = [_coerce_group(g) for g in list(self.groups or [])]
        self.organizations = organizations
        self.groups = groups
