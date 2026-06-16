"""Unit tests for AuthHandler exclude-list mutation API (FEAT-241 M1).

Tests cover:
- add_exclude_list: idempotent append
- remove_exclude_list: idempotent removal
- register_exclusions: bulk idempotent add
- unregister_exclusions: bulk idempotent remove
"""
import pytest
from navigator_auth.auth import AuthHandler
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY


@pytest.fixture
def auth_handler():
    """Minimal AuthHandler with a fake app dict (bypasses full __init__)."""
    handler = AuthHandler.__new__(AuthHandler)
    app = {AUTH_EXCLUDE_LIST_KEY: []}
    handler.app = app
    return handler


class TestAddExcludeListIdempotent:
    def test_adds_path(self, auth_handler):
        auth_handler.add_exclude_list("/api/v1/forms/test")
        assert "/api/v1/forms/test" in auth_handler.app[AUTH_EXCLUDE_LIST_KEY]

    def test_no_duplicate_on_second_add(self, auth_handler):
        auth_handler.add_exclude_list("/api/v1/forms/test")
        auth_handler.add_exclude_list("/api/v1/forms/test")
        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert lst.count("/api/v1/forms/test") == 1

    def test_distinct_paths_both_added(self, auth_handler):
        auth_handler.add_exclude_list("/api/v1/forms/a")
        auth_handler.add_exclude_list("/api/v1/forms/b")
        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/api/v1/forms/a" in lst
        assert "/api/v1/forms/b" in lst


class TestRemoveExcludeList:
    def test_removes_existing_path(self, auth_handler):
        auth_handler.app[AUTH_EXCLUDE_LIST_KEY].append("/api/v1/forms/test")
        auth_handler.remove_exclude_list("/api/v1/forms/test")
        assert "/api/v1/forms/test" not in auth_handler.app[AUTH_EXCLUDE_LIST_KEY]

    def test_noop_on_absent_path(self, auth_handler):
        # Must not raise ValueError
        auth_handler.remove_exclude_list("/nonexistent")

    def test_removes_only_target(self, auth_handler):
        auth_handler.app[AUTH_EXCLUDE_LIST_KEY].extend(["/a", "/b", "/c"])
        auth_handler.remove_exclude_list("/b")
        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/a" in lst
        assert "/b" not in lst
        assert "/c" in lst


class TestBulkMutations:
    def test_register_exclusions_bulk(self, auth_handler):
        paths = ["/a", "/b", "/c"]
        auth_handler.register_exclusions(paths)
        for p in paths:
            assert p in auth_handler.app[AUTH_EXCLUDE_LIST_KEY]

    def test_register_exclusions_idempotent(self, auth_handler):
        auth_handler.register_exclusions(["/x", "/x"])
        assert auth_handler.app[AUTH_EXCLUDE_LIST_KEY].count("/x") == 1

    def test_unregister_exclusions_bulk(self, auth_handler):
        auth_handler.app[AUTH_EXCLUDE_LIST_KEY].extend(["/a", "/b", "/c"])
        auth_handler.unregister_exclusions(["/a", "/c"])
        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/a" not in lst
        assert "/c" not in lst
        assert "/b" in lst

    def test_unregister_exclusions_noop_on_absent(self, auth_handler):
        # Must not raise
        auth_handler.unregister_exclusions(["/nonexistent1", "/nonexistent2"])

    def test_register_then_unregister(self, auth_handler):
        auth_handler.register_exclusions(["/api/v1/forms/contact", "/api/v1/forms/contact/schema"])
        auth_handler.unregister_exclusions(["/api/v1/forms/contact"])
        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/api/v1/forms/contact" not in lst
        assert "/api/v1/forms/contact/schema" in lst
