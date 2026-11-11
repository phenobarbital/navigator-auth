"""FEAT-108 — examples/oauth2_3lo_server.py wiring (M1) and, from TASK-206, the app-level flow (M8)."""
import importlib.util
import logging
from pathlib import Path
from types import ModuleType

import pytest

import navigator_auth.conf as nav_conf

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "oauth2_3lo_server.py"
SETTINGS = Path(__file__).resolve().parent.parent / "settings" / "settings.py"


def _load_example() -> ModuleType:
    """Import examples/oauth2_3lo_server.py by path (it is not a package).

    Its ``os.environ.setdefault`` side effects are expected.
    """
    spec = importlib.util.spec_from_file_location("oauth2_3lo_server_example", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_pins_oauth2_backend_only():
    """AC1: only Oauth2Provider, no authorization backends, even with a richer settings.py."""
    if not SETTINGS.exists():
        pytest.skip("settings/settings.py absent: nothing to override")
    example = _load_example()
    app = example.make_app()
    auth = app["auth"]
    assert set(auth.backends) == {"Oauth2Provider"}
    assert auth._authz_backends == []


@pytest.mark.parametrize("key", ["short", b"tiny", None])
def test_example_warns_on_short_secret(monkeypatch, caplog, key):
    """AC2: one warning naming AUTH_SECRET_KEY, never the key."""
    example = _load_example()
    monkeypatch.setattr(nav_conf, "SECRET_KEY", key)
    with caplog.at_level(logging.WARNING):
        example._warn_on_short_secret()
    records = [record for record in caplog.records if "AUTH_SECRET_KEY" in record.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert str(key) not in records[0].getMessage()


def test_example_quiet_on_long_secret(monkeypatch, caplog):
    """AC2: nothing logged for a >= 32-byte key."""
    example = _load_example()
    monkeypatch.setattr(nav_conf, "SECRET_KEY", "k" * 48)
    with caplog.at_level(logging.WARNING):
        example._warn_on_short_secret()
    assert not [record for record in caplog.records if "AUTH_SECRET_KEY" in record.getMessage()]
