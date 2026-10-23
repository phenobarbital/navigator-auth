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
    {"org_id": "", "organization": "x"},  # AC9
    {"org_id": "1", "organization": "   "},  # AC9
    {"org_id": "1", "name": "   "},  # AC9 via the `name` fallback
    {"org_id": "1", "user_id": 35, "properties": None},  # extras only, no name
]

#: One element of `auth.vw_users`.`organizations`, verbatim: the view builds
#: `to_jsonb(organization_users.*) || jsonb_build_object('name',
#: organizations.organization)`, so the name arrives as `name` and five
#: bookkeeping columns ride along.
VW_USERS_ORG_ROW = {
    "name": "Pokémon",
    "org_id": 1,
    "user_id": 35,
    "created_at": "2026-10-12T22:35:04.675621+00:00",
    "created_by": "35",
    "properties": None,
    "updated_at": "2026-10-12T22:35:04.675621+00:00",
}
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
    if len(bad) == 1 or not {"organization", "name"} & set(bad) or "org_id" not in bad:
        assert exc.value.__cause__ is not None


# --- FEAT-102 §8 Q5 override (2026-10-23): tolerate view rows -------------
# The strict reading rejected any unknown key, which cost a 403 on every
# login for a user with an organization, because `auth.vw_users` ships five
# bookkeeping columns and spells the name `name`.


def test_vw_users_row_is_accepted_verbatim():
    """The real view row must normalize without the caller reshaping it."""
    user = BasicUser(id=1, data={}, organizations=[dict(VW_USERS_ORG_ROW)])
    org = user.organizations[0]
    assert isinstance(org, Organization)
    assert org.org_id == "1"           # int coerced by the model
    assert org.organization == "Pokémon"  # from `name`
    assert org.slug == "pokemon"       # derived, the view's slug is not read


def test_unknown_keys_are_ignored_not_fatal():
    user = BasicUser(id=1, data={})
    user.add_organization(
        {"org_id": "7", "organization": "Example", "user_id": 35, "properties": None}
    )
    org = user.organizations[0]
    assert (org.org_id, org.organization) == ("7", "Example")
    # ignored, not absorbed
    assert not hasattr(org, "user_id")


def test_name_is_a_fallback_for_organization():
    user = BasicUser(id=1, data={})
    user.add_organization({"org_id": "7", "name": "From Name"})
    assert user.organizations[0].organization == "From Name"


def test_organization_wins_when_both_keys_are_present():
    """The declared field beats the alias, so FEAT-102 payloads are unchanged."""
    user = BasicUser(id=1, data={})
    user.add_organization({"org_id": "7", "organization": "Declared", "name": "Alias"})
    assert user.organizations[0].organization == "Declared"


def test_explicit_slug_still_wins_over_derivation():
    user = BasicUser(id=1, data={})
    user.add_organization({"org_id": "7", "name": "From Name", "slug": "explicit"})
    assert user.organizations[0].slug == "explicit"


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
