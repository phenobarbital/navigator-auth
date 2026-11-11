"""navigator-auth database migrations (FEAT-110): catalog, runner and the ``navauth`` CLI."""

from .catalog import (
    MIGRATION_SETS,
    MigrationCatalogError,
    MigrationFile,
    discover,
    render_sql,
)

__all__ = [
    "MIGRATION_SETS",
    "MigrationCatalogError",
    "MigrationFile",
    "discover",
    "render_sql",
]
