"""Regression tests for the review fixes (FEAT-105)."""
import inspect

from navigator_auth.handlers import model as local_model
from navigator_auth.handlers.redaction import scrub_payload

PUBLIC = frozenset({"name"})
CREDS = frozenset({"token"})


def test_scrub_walks_wrapper_dicts():
    out = scrub_payload({"data": {"name": "n", "token": "T"}}, PUBLIC, CREDS)
    assert out == {"data": {"name": "n"}}


def test_scrub_lists_and_scalars():
    assert scrub_payload([{"token": "T", "name": "n"}], PUBLIC, CREDS) == [{"name": "n"}]
    assert scrub_payload("msg", PUBLIC, CREDS) == "msg"
    assert scrub_payload({"error": "x"}, PUBLIC, CREDS) == {"error": "x"}


def test_local_base_does_not_use_removed_content_kwarg():
    src = inspect.getsource(local_model)
    assert "json_response(content=" not in src
    assert "status=204)" not in src
