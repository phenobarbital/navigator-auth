"""Migration catalog — which SQL files navigator-auth applies, and in what order (FEAT-110).

Every schema change lives in ``navigator_auth/migrations/sql/<set>/NNN_description.sql``.
Files are discovered from the filesystem: a correctly named file dropped into a set
directory is registered by being there.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE

SQL_ROOT: Path = Path(__file__).parent / "sql"
MIGRATION_SETS: tuple[str, ...] = ("vault", "identity", "passkey", "mfa", "oauth2")
FILENAME_PATTERN: re.Pattern[str] = re.compile(r"^\d{3}_[a-z0-9_]+\.sql$")


class MigrationCatalogError(Exception):
    """The files on disk do not form a valid catalog."""


class MigrationFile(BaseModel):
    """One SQL migration file.

    Attributes:
        migration_set: Set name, one of ``MIGRATION_SETS``.
        filename: File name, e.g. ``004_identity_base_columns.sql``.
        path: Absolute path of the file.
        checksum: sha256 hex digest of the raw file bytes.
    """

    model_config = ConfigDict(frozen=True)

    migration_set: str
    filename: str
    path: Path
    checksum: str


def set_dir(migration_set: str) -> Path:
    """Return the directory of a migration set.

    Raises:
        MigrationCatalogError: when ``migration_set`` is not in ``MIGRATION_SETS``.
    """
    if migration_set not in MIGRATION_SETS:
        raise MigrationCatalogError(f"Unknown migration set: {migration_set!r}")
    return SQL_ROOT / migration_set


def set_filenames(migration_set: str) -> tuple[str, ...]:
    """Sorted filenames of one set; an empty tuple when the set directory does not exist."""
    return tuple(file.filename for file in discover([migration_set]))


def discover(sets: Iterable[str] | None = None) -> tuple[MigrationFile, ...]:
    """Return every migration file, ordered by ``MIGRATION_SETS`` then filename.

    Args:
        sets: Restrict to these set names; ``None`` means all sets.

    Raises:
        MigrationCatalogError: a requested set is unknown; a directory under
            ``SQL_ROOT`` is not in ``MIGRATION_SETS``; a ``.sql`` file does not
            match ``FILENAME_PATTERN``; two files in one set share the numeric prefix.
    """
    selected_sets = tuple(MIGRATION_SETS if sets is None else sets)
    unknown_sets = set(selected_sets).difference(MIGRATION_SETS)
    if unknown_sets:
        raise MigrationCatalogError(f"Unknown migration set: {sorted(unknown_sets)!r}")

    if SQL_ROOT.exists():
        unknown_directories = sorted(
            directory.name
            for directory in SQL_ROOT.iterdir()
            if directory.is_dir()
            and directory.name not in MIGRATION_SETS
            and not directory.name.startswith((".", "__"))
        )
        if unknown_directories:
            raise MigrationCatalogError(f"Unknown migration set directories: {unknown_directories!r}")

    files: list[MigrationFile] = []
    for migration_set in MIGRATION_SETS:
        if migration_set not in selected_sets:
            continue
        directory = set_dir(migration_set)
        if not directory.exists():
            continue

        prefixes: set[str] = set()
        for path in sorted(directory.glob("*.sql")):
            if not FILENAME_PATTERN.fullmatch(path.name):
                raise MigrationCatalogError(f"Invalid migration filename: {path.name!r}")
            prefix = path.name[:3]
            if prefix in prefixes:
                raise MigrationCatalogError(f"Duplicate migration prefix in {migration_set!r}: {prefix}")
            prefixes.add(prefix)
            files.append(
                MigrationFile(
                    migration_set=migration_set,
                    filename=path.name,
                    path=path,
                    checksum=hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
    return tuple(files)


def render_sql(sql: str) -> str:
    """Replace ``{schema}`` and ``{users_table}``; other text is returned unchanged."""
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)
