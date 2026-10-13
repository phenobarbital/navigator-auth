"""FEAT-102 / TASK-99 — AuthUser.organizations normalization (spec §4 table 1)."""

import copy

import pytest

from navigator_auth.identities import AuthUser, Organization
from navigator_auth.backends.basic import BasicUser
from navigator_auth.backends.external import OauthUser
from navigator_auth.backends.token import TokenUser
from navigator_auth.backends.api import APIKeyUser
from navigator_auth.backends.noauth import AnonymousUser
from navigator_auth.backends.django import DjangoUser
from navigator_auth.backends.passkey import PasskeyUser

ORG_DICT = {"org_id": "7", "organization": "Example", "slug": "example"}
ORG_DICT_NO_SLUG = {"org_id": 7, "organization": "Example Org"}
BAD_ORG_DICTS = [
    {"organization": "x"},
    {"org_id": "1"},
    {"org_id": "1", "organization": "n", "extra": 1},
    {"org_id": "", "organization": "x"},  # AC9
    {"org_id": "1", "organization": "   "},  # AC9
]
SUBCLASS_KWARGS = [
    (BasicUser, {}),
    (OauthUser, {"token": "t", "given_name": "a", "family_name": "b"}),
    (TokenUser, {"tenant": "t", "programs": []}),
    (APIKeyUser, {"token": "t", "api_key": "k"}),
    (AnonymousUser, {}),
    (DjangoUser, {"sessionid": "s"}),
    (PasskeyUser, {}),
]


def test_basicuser_dict_organizations_become_models():
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT)])
    assert isinstance(user.organizations[0], Organization)
    assert user.organizations[0].org_id == "7"  # AC1


def test_dict_organizations_via_data_initvar():
    user = BasicUser(id=1, data={"organizations": [dict(ORG_DICT)]})
    assert user.organizations
    assert all(isinstance(o, Organization) for o in user.organizations)
    assert user.organizations[0].org_id == "7"


def test_add_organization_dict_after_construction():
    user = BasicUser(id=1, data={})
    user.add_organization(dict(ORG_DICT))
    assert isinstance(user.organizations[0], Organization)
    assert user.organizations[0].organization == "Example"


def test_mixed_list_normalized_and_instances_preserved():
    inst = Organization(org_id="9", organization="Other")
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT), inst])
    assert isinstance(user.organizations[0], Organization)
    assert user.organizations[1] is inst


def test_fields_keep_model_semantics():
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT_NO_SLUG), dict(ORG_DICT)])
    assert user.organizations[0].org_id == "7"
    assert user.organizations[0].slug == "example-org"
    assert user.organizations[1].slug == "example"


def test_normalization_idempotent_and_input_untouched():
    payload = [dict(ORG_DICT)]
    before = copy.deepcopy(payload)
    user = BasicUser(id=1, data={}, organizations=payload)
    assert payload == before
    first = list(user.organizations)
    user.normalize_organizations()
    user.normalize_organizations()
    assert user.organizations == first
    assert all(a is b for a, b in zip(user.organizations, first))


@pytest.mark.parametrize("kwargs", [{}, {"organizations": None}, {"organizations": []}])
def test_absent_none_empty_organizations(kwargs):
    assert BasicUser(id=1, data={}, **kwargs).organizations == []


@pytest.mark.parametrize("bad", ["acme", 7, None, ["x"]])
def test_non_mapping_entries_raise_typeerror(bad):
    user = BasicUser(id=1, data={})
    with pytest.raises(TypeError):
        user.add_organization(bad)
    assert user.organizations == []


@pytest.mark.parametrize("bad", BAD_ORG_DICTS)
def test_bad_mapping_entries_raise_valueerror(bad):
    user = BasicUser(id=1, data={})
    with pytest.raises(ValueError) as exc:
        user.add_organization(dict(bad))
    if "extra" in bad or len(bad) == 1 or "organization" not in bad or "org_id" not in bad:
        assert exc.value.__cause__ is not None


def test_failed_add_leaves_list_unchanged():
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT)])
    before = list(user.organizations)
    with pytest.raises(ValueError):
        user.add_organization({"organization": "x"})
    assert user.organizations == before
    user.organizations = before + [{"org_id": "", "organization": "x"}]
    snapshot = list(user.organizations)
    with pytest.raises(ValueError):
        user.normalize_organizations()
    assert user.organizations == snapshot


@pytest.mark.parametrize("cls,extra", SUBCLASS_KWARGS)
def test_all_ident_subclasses_normalize(cls, extra):
    user = cls(id=1, data={}, organizations=[dict(ORG_DICT)], **extra)
    assert all(isinstance(o, Organization) for o in user.organizations)
    assert isinstance(user, AuthUser)
