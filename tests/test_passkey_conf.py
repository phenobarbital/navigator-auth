"""FEAT-101 TASK-86 — PASSKEY_* settings defaults and parsing."""

import importlib
import logging

import pytest

_KEYS = (
    "PASSKEY_RELYING_PARTIES",
    "PASSKEY_CHALLENGE_TTL",
    "PASSKEY_USER_VERIFICATION",
    "PASSKEY_TENANT_ATTRIBUTE",
    "PASSKEY_DECOY_CREDENTIALS",
)


def _reload_conf(monkeypatch, **env):
    """Reload navigator_auth.conf with the given environment values."""
    for key in _KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import navigator_auth.conf as conf

    return importlib.reload(conf)


@pytest.fixture(autouse=True)
def _restore_conf(monkeypatch):
    yield
    monkeypatch.undo()
    for key in _KEYS:
        monkeypatch.delenv(key, raising=False)
    import navigator_auth.conf as conf

    importlib.reload(conf)


def test_conf_passkey_defaults(monkeypatch):
    """TTL 300, UV required, empty RP map, tenant check off, one decoy."""
    conf = _reload_conf(monkeypatch)
    assert conf.PASSKEY_RELYING_PARTIES == []
    assert conf.PASSKEY_CHALLENGE_TTL == 300
    assert conf.PASSKEY_USER_VERIFICATION == "required"
    assert conf.PASSKEY_TENANT_ATTRIBUTE is None
    assert conf.PASSKEY_DECOY_CREDENTIALS == 1


def test_conf_passkey_invalid_json_yields_empty(monkeypatch, caplog):
    """Invalid PASSKEY_RELYING_PARTIES JSON is logged and yields []."""
    with caplog.at_level(logging.ERROR):
        conf = _reload_conf(monkeypatch, PASSKEY_RELYING_PARTIES="not-json")
    assert conf.PASSKEY_RELYING_PARTIES == []
    assert any("PASSKEY_RELYING_PARTIES" in r.getMessage() for r in caplog.records)


def test_conf_passkey_non_list_yields_empty(monkeypatch):
    """A JSON object (not a list) resets to []."""
    conf = _reload_conf(monkeypatch, PASSKEY_RELYING_PARTIES='{"a": 1}')
    assert conf.PASSKEY_RELYING_PARTIES == []


def test_conf_passkey_valid_json(monkeypatch):
    """A valid list is parsed."""
    conf = _reload_conf(
        monkeypatch,
        PASSKEY_RELYING_PARTIES='[{"origin": "https://a.com", "rp_id": "a.com"}]',
    )
    assert conf.PASSKEY_RELYING_PARTIES[0]["rp_id"] == "a.com"


def test_conf_passkey_rate_limit_default_off(monkeypatch):
    conf = _reload_conf(monkeypatch)
    assert conf.PASSKEY_LOGIN_OPTIONS_RATE == 0
