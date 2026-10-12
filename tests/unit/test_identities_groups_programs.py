"""FEAT-102 / TASK-101 — groups and programs normalization (spec §4 Module 4 table)."""
import pytest

from navigator_auth.identities import Group, Guest, Organization, Program
from navigator_auth.backends.basic import BasicUser
from navigator_auth.backends.token import TokenUser

PROGRAM_DICT = {"program_id": 1, "program_name": "P"}


def test_groups_str_dict_instance_normalized():
    inst = Group(group="x")
    user = BasicUser(id=1, data={}, groups=["editors", {"group": "admins"}, inst])
    assert [type(g) for g in user.groups] == [Group, Group, Group]
    assert user.groups[2] is inst
    user.add_group(Guest)
    assert user.groups[-1] is Guest                                     # AC10


@pytest.mark.parametrize("bad,exc", [
    ("", ValueError), ("  ", ValueError), ({"group": ""}, ValueError),
    ({"group": "x", "extra": 1}, ValueError), (7, TypeError), (None, TypeError),
])
def test_group_invalid_entries_raise(bad, exc):
    user = BasicUser(id=1, data={})
    with pytest.raises(exc):
        user.add_group(bad)
    assert user.groups == []


def test_tokenuser_programs_normalized_on_construction_and_add():
    user = TokenUser(id=1, data={}, tenant="t", programs=[dict(PROGRAM_DICT)])
    assert isinstance(user.programs[0], Program)
    assert user.programs[0].program_slug == "p"
    user.add_program({"program_id": 2, "program_name": "Other Prog"})
    assert isinstance(user.programs[1], Program)
    assert user.programs[1].program_slug == "other-prog"
    assert TokenUser(id=1, data={}, tenant="t").programs == []


@pytest.mark.parametrize("bad,exc", [
    ("name", TypeError), ({"program_name": "x"}, ValueError), ({"program_id": 1, "program_name": ""}, ValueError),
])
def test_program_invalid_entries_raise(bad, exc):
    user = TokenUser(id=1, data={}, tenant="t")
    with pytest.raises(exc):
        user.add_program(bad)
    assert user.programs == []


def test_normalize_memberships_covers_all_lists():
    user = TokenUser(id=1, data={}, tenant="t")
    object.__setattr__(user, "organizations", [{"org_id": "7", "organization": "Example"}])
    object.__setattr__(user, "groups", [{"group": "admins"}, "editors"])
    object.__setattr__(user, "programs", [dict(PROGRAM_DICT)])
    user.normalize_memberships()
    assert all(isinstance(o, Organization) for o in user.organizations)
    assert all(isinstance(g, Group) for g in user.groups)
    assert all(isinstance(p, Program) for p in user.programs)
    assert len(user.groups) == 2


def test_tokenauth_assignment_path_normalizes():
    usr = TokenUser(id=1, data={}, tenant="t")
    usr.programs = [dict(PROGRAM_DICT)]
    usr.normalize_programs()
    assert isinstance(usr.programs[0], Program)
