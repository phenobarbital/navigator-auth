"""Durable credential-change state helpers (FEAT-106 review fixes, spec M4).

Every write helper runs on the caller's connection inside the caller's transaction and never commits,
rolls back or acquires. Any database failure raises :class:`SecurityStateError` so callers fail closed.
"""

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from ..conf import AUTH_DB_SCHEMA

GENERATION_CLAIM = "gen"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GENERATION_TABLE = f"{AUTH_DB_SCHEMA}.oauth_user_generation"
_CONSUMPTION_TABLE = f"{AUTH_DB_SCHEMA}.recovery_confirm_consumptions"


class SecurityStateError(Exception):
    """Durable security state could not be read or written; never shown to a client."""


def generation_of(payload: Mapping[str, Any]) -> int:
    """Return the generation an OAuth artifact carries (missing/None -> 0).

    Raises:
        SecurityStateError: For a bool, non-int or negative value.
    """
    value = payload.get(GENERATION_CLAIM)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SecurityStateError("invalid OAuth credential generation")
    return value


def stamp_generation(payload: dict, generation: int) -> dict:
    """Set ``GENERATION_CLAIM`` only when positive and return ``payload``.

    Args:
        payload: OAuth artifact payload to mutate.
        generation: Non-negative credential generation.

    Raises:
        ValueError: If ``generation`` is negative.
    """
    if generation < 0:
        raise ValueError("generation must be non-negative")
    if generation > 0:
        payload[GENERATION_CLAIM] = generation
    return payload


async def current_generation(conn: Any, user_id: int) -> int:
    """Return the user's OAuth credential generation (absent row -> 0) on ``conn``."""
    try:
        value = await conn.fetchval(f"SELECT generation FROM {_GENERATION_TABLE} WHERE user_id = $1", int(user_id))
    except Exception as err:
        raise SecurityStateError(f"generation read failed: {type(err).__name__}") from err
    return 0 if value is None else int(value)


async def increment_generation(conn: Any, user_id: int) -> int:
    """Increment and return the user's generation inside the caller's transaction."""
    sql = (
        f"INSERT INTO {_GENERATION_TABLE} (user_id, generation) VALUES ($1, 1) "
        f"ON CONFLICT (user_id) DO UPDATE SET generation = {_GENERATION_TABLE}.generation + 1, updated_at = now() "
        "RETURNING generation"
    )
    try:
        generation = await conn.fetchval(sql, int(user_id))
        if generation is None:
            raise ValueError("generation was not returned")
        return int(generation)
    except Exception as err:
        raise SecurityStateError(f"generation increment failed: {type(err).__name__}") from err


async def record_confirmation(conn: Any, digest: str, user_id: int, expires_at: datetime) -> bool:
    """Insert a consumption marker and return whether it was newly recorded.

    Raises:
        ValueError: If ``digest`` is not a lowercase SHA-256 hex digest.
        SecurityStateError: On any database failure.
    """
    if not isinstance(digest, str) or not _DIGEST.match(digest):
        raise ValueError("digest must be a lowercase hex SHA-256 digest")
    sql = (
        f"INSERT INTO {_CONSUMPTION_TABLE} (digest, user_id, expires_at) VALUES ($1, $2, $3) "
        "ON CONFLICT (digest) DO NOTHING RETURNING digest"
    )
    try:
        return await conn.fetchval(sql, digest, int(user_id), expires_at) is not None
    except Exception as err:
        raise SecurityStateError(f"confirmation record failed: {type(err).__name__}") from err


async def confirmation_recorded(conn: Any, digest: str) -> bool:
    """Return whether ``digest`` has a committed (or same-transaction) consumption marker."""
    try:
        return await conn.fetchval(f"SELECT 1 FROM {_CONSUMPTION_TABLE} WHERE digest = $1", digest) is not None
    except Exception as err:
        raise SecurityStateError(f"confirmation read failed: {type(err).__name__}") from err


async def generation_matches(db_pool: Any, user_id: int, presented: int) -> bool:
    """Return whether ``presented`` equals the user's current generation.

    Raises:
        SecurityStateError: When generation storage cannot be read.
    """
    try:
        async with await db_pool.acquire() as conn:
            return await current_generation(conn, user_id) == int(presented)
    except SecurityStateError:
        raise
    except Exception as err:
        raise SecurityStateError(f"generation validation failed: {type(err).__name__}") from err
