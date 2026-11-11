"""navigator-auth database migrations (FEAT-110): catalog, runner and the ``navauth`` CLI."""

from .catalog import (
    MIGRATION_SETS,
    MigrationCatalogError,
    MigrationFile,
    discover,
    render_sql,
)
from .runner import (
    MigrationError,
    MigrationResult,
    MigrationState,
    MigrationStatus,
    UpgradeReport,
    get_status,
)

__all__ = [
    "MIGRATION_SETS",
    "MigrationCatalogError",
    "MigrationError",
    "MigrationFile",
    "MigrationResult",
    "MigrationState",
    "MigrationStatus",
    "UpgradeReport",
    "discover",
    "get_status",
    "render_sql",
]
