"""FEAT-101 TASK-91 — user_is_active helper."""

from types import SimpleNamespace

import pytest

from navigator_auth.backends.abstract import user_is_active


@pytest.mark.parametrize(
    "user, expected",
    [
        ({"is_active": True}, True),
        ({"is_active": False}, False),
        ({"enabled": True}, True),  # field missing → active
        ({"is_active": None}, True),
        (SimpleNamespace(is_active=False), False),
        (SimpleNamespace(), True),
    ],
)
def test_user_is_active_dict_and_model(user, expected):
    assert user_is_active(user) is expected
