"""Type-confusion tests for ``_check_superuser`` (decorators.py).

``in`` is SUBSTRING matching on a str and membership only on a collection,
so an unguarded ``SUPERUSER_GROUP in userinfo["groups"]`` grants superuser
to any string value merely CONTAINING the word — e.g.
``groups="ex_superuser_revoked"`` — and raises TypeError on ``groups=None``.
These cases were found (and are equally guarded) downstream in fieldsync
(Trocdigital/fieldsync#146).
"""
from unittest.mock import MagicMock

import pytest

from navigator_auth.decorators import _check_superuser


@pytest.mark.parametrize("hostile", [
    "superuser",
    "ex_superuser_revoked",
    "ns_superuser_pending",
    "not_a_superuser",
])
def test_string_groups_never_grants_superuser(hostile):
    assert _check_superuser({"groups": hostile}) is False, (
        f"groups={hostile!r} as a string must not grant superuser"
    )


@pytest.mark.parametrize("malformed", [None, 42, {"superuser": True}])
def test_malformed_groups_denies_without_raising(malformed):
    assert _check_superuser({"groups": malformed}) is False


@pytest.mark.parametrize("groups, expected", [
    (["superuser"], True),
    (("superuser",), True),
    ({"superuser"}, True),
    (["editors"], False),
    ([], False),
])
def test_collection_groups_resolve_normally(groups, expected):
    assert _check_superuser({"groups": groups}) is expected


@pytest.mark.parametrize("flag", ["superuser", "is_superuser"])
def test_explicit_flag_still_wins(flag):
    assert _check_superuser({flag: True, "groups": []}) is True


def test_user_object_group_fallback_still_works():
    group = MagicMock()
    group.group = "superuser"
    user = MagicMock()
    user.groups = [group]
    assert _check_superuser({}, user) is True
