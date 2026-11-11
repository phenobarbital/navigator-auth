"""HMAC key-length startup warning (FEAT-109 M4)."""

import logging
import warnings
from unittest.mock import MagicMock

import pytest
from aiohttp import web

import navigator_auth.auth as auth_mod
from navigator_auth import conf
from navigator_auth.libs.hmac_keys import (
    SECURITY_LOGGER,
    configured_hmac_keys,
    short_hmac_keys,
    warn_short_hmac_keys,
)

LONG = "k" * 48


@pytest.fixture
def long_keys(monkeypatch):
    """All configured keys >= 32 bytes."""
    monkeypatch.setattr(conf, "SECRET_KEY", LONG)
    monkeypatch.setattr(conf, "PARTNER_KEY", None)
    monkeypatch.setattr(conf, "AUTH_TOKEN_SECRET", LONG + "t")
    monkeypatch.setattr(conf, "AUTH_RECOVERY_SECRET", LONG.encode("utf-8"))


def test_short_hmac_keys_reports_lengths():
    keys = {"A": "abcdef", "B": b"x" * 16, "C": "y" * 32, "D": None}
    assert short_hmac_keys(keys) == [("A", 6), ("B", 16)]


def test_warn_short_hmac_keys_never_logs_value(long_keys, monkeypatch, caplog):
    monkeypatch.setattr(conf, "SECRET_KEY", "s3cr3t")
    monkeypatch.setattr(conf, "AUTH_RECOVERY_SECRET", b"s3cr3t")
    caplog.set_level(logging.WARNING, logger=SECURITY_LOGGER)
    assert warn_short_hmac_keys() == ["AUTH_SECRET_KEY"]
    messages = [r.getMessage() for r in caplog.records if r.name == SECURITY_LOGGER]
    assert len(messages) == 1 and "AUTH_SECRET_KEY" in messages[0] and "6 bytes" in messages[0]
    assert "s3cr3t" not in messages[0]


def test_auth_setup_calls_warn_once(monkeypatch):
    spy = MagicMock(return_value=[])
    monkeypatch.setattr(auth_mod, "warn_short_hmac_keys", spy)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        handler = auth_mod.AuthHandler(secure_cookies=False, enable_authdb=False)
    handler.setup(web.Application())
    spy.assert_called_once_with()


def test_configured_hmac_keys_recovery_fallback_skipped(long_keys, monkeypatch):
    assert "AUTH_RECOVERY_SECRET" not in configured_hmac_keys()
    monkeypatch.setattr(conf, "AUTH_RECOVERY_SECRET", b"other-recovery")
    assert "AUTH_RECOVERY_SECRET" in configured_hmac_keys()


def test_partner_key_fallback_label(long_keys, monkeypatch):
    monkeypatch.setattr(conf, "PARTNER_KEY", "p" * 16)
    monkeypatch.setattr(conf, "AUTH_TOKEN_SECRET", "p" * 16)
    keys = configured_hmac_keys()
    assert "AUTH_TOKEN_SECRET (PARTNER_KEY)" in keys
    assert "AUTH_TOKEN_SECRET" not in keys


def test_no_warning_when_all_keys_long(long_keys, caplog):
    caplog.set_level(logging.WARNING, logger=SECURITY_LOGGER)
    assert warn_short_hmac_keys() == []
    assert not [r for r in caplog.records if r.name == SECURITY_LOGGER]


def test_no_warnings_warn(monkeypatch):
    monkeypatch.setattr(conf, "SECRET_KEY", "short")
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        warn_short_hmac_keys()
    assert recorded == []
