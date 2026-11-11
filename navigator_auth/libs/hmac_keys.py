"""Startup check for short HMAC signing keys (FEAT-109).

PyJWT warns on every token signed with an HMAC key shorter than the hash
output (RFC 7518 §3.2). ``warn_short_hmac_keys`` checks the configured keys
once at setup and logs one WARNING per short key on the security logger,
naming the setting and its byte length — never the value.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from .. import conf

MIN_HMAC_KEY_BYTES: int = 32
SECURITY_LOGGER = "navigator_auth.security"  # same name as middlewares/probes.py:31


def configured_hmac_keys() -> dict[str, str | bytes | None]:
    """Return the configured HMAC keys, read from ``navigator_auth.conf`` at call time.

    Returns:
        ``{setting label: value}``: "AUTH_SECRET_KEY" -> ``conf.SECRET_KEY``;
        "AUTH_TOKEN_SECRET" -> ``conf.AUTH_TOKEN_SECRET`` (labelled
        "AUTH_TOKEN_SECRET (PARTNER_KEY)" when it is the ``PARTNER_KEY`` fallback);
        "AUTH_RECOVERY_SECRET" only when it differs from the encoded
        ``SECRET_KEY`` fallback.
    """
    keys: dict[str, str | bytes | None] = {"AUTH_SECRET_KEY": conf.SECRET_KEY}
    token_secret = conf.AUTH_TOKEN_SECRET
    if token_secret is not None and token_secret == conf.PARTNER_KEY:
        token_label = "AUTH_TOKEN_SECRET (PARTNER_KEY)"
    else:
        token_label = "AUTH_TOKEN_SECRET"
    keys[token_label] = token_secret
    secret = conf.SECRET_KEY
    fallback = secret.encode("utf-8") if isinstance(secret, str) else secret
    if conf.AUTH_RECOVERY_SECRET != fallback:
        keys["AUTH_RECOVERY_SECRET"] = conf.AUTH_RECOVERY_SECRET
    return keys


def short_hmac_keys(keys: Mapping[str, str | bytes | None]) -> list[tuple[str, int]]:
    """Measure keys against ``MIN_HMAC_KEY_BYTES``.

    Args:
        keys: ``{label: value}``; ``str`` values are measured as UTF-8 bytes.

    Returns:
        ``(label, byte length)`` for every non-empty key shorter than the
        minimum, in input order. None/empty keys are ignored.
    """
    short: list[tuple[str, int]] = []
    for label, value in keys.items():
        if not value:
            continue
        size = len(value.encode("utf-8")) if isinstance(value, str) else len(value)
        if size < MIN_HMAC_KEY_BYTES:
            short.append((label, size))
    return short


def warn_short_hmac_keys(logger: logging.Logger | None = None) -> list[str]:
    """Log one WARNING per configured HMAC key shorter than 32 bytes.

    Args:
        logger: Target logger; defaults to ``logging.getLogger(SECURITY_LOGGER)``.

    Returns:
        The labels of the short keys. Never raises, never calls ``warnings.warn``,
        never logs a key value.
    """
    log = logger or logging.getLogger(SECURITY_LOGGER)
    try:
        short = short_hmac_keys(configured_hmac_keys())
    except Exception as exc:  # pylint: disable=W0703
        log.debug("HMAC key-length check skipped: %s", type(exc).__name__)
        return []
    for label, size in short:
        log.warning(
            "%s is %d bytes; HMAC keys should be at least %d bytes (RFC 7518 §3.2).",
            label,
            size,
            MIN_HMAC_KEY_BYTES,
        )
    return [label for label, _ in short]
