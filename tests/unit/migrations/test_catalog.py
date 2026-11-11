"""Unit tests for the migration catalog."""

from pathlib import Path

import pytest

from navigator_auth.migrations import catalog
from navigator_auth.migrations.catalog import (
    MIGRATION_SETS,
    MigrationCatalogError,
    discover,
    render_sql,
    set_dir,
    set_filenames,
)

RELEASED = {
    ("vault", "001_create_vault_tables.sql"): "def230b640fbd385c7fadd42586bc0db9ba2f7e8256d22132b9baf7b4edb7c38",
    ("vault", "002_vault_crypto_hardening.sql"): "7e0482573142e4fc9249079306bdecc29d2eff6f8ae2b61addaeee16a6002b18",
    ("identity", "001_identity_credentials.sql"): "8f94156c97e195fb592c398f773f60764e1d9fd6dff2f645bbf4f383415d8dce",
    ("identity", "002_identity_id_token.sql"): "12a6359ed7e518511c7071e289f73a4e54ac412cb02f3e48157771d76dea847c",
    (
        "identity",
        "003_identity_key_version_integer.sql",
    ): "4207ee7f2d25c61d71525664fb172a947d2d41a010fe6ee84ad21c2395a8bc0c",
    ("identity", "004_identity_base_columns.sql"): "d83d2f0501c61fc48b31d98e87a0b6ccd2ffca0e1eefbfc2166f99c9499ec44b",
    (
        "identity",
        "005_identity_legacy_uid_default.sql",
    ): "e77db04d4756984f092f3438d7ceacc515cc5769744c2f7ad747cd36c9d29d25",
    (
        "identity",
        "006_identity_drop_legacy_uid.sql",
    ): "77d5293158802e84de00a854cc744eca30b503747dfd14b9cf9e46af0eb22a1f",
    ("passkey", "001_passkey_credentials.sql"): "56ec735aed75c85101da1ef9e60ca3f227ce8a1a135f0c9a0a4e0ae8eef3c710",
}

# Sets whose files shipped before FEAT-110; newer sets (oauth2, mfa) are covered by their own tests.
RELEASED_SETS = ["vault", "identity", "passkey"]

MFA = {
    ("mfa", "001_mfa_tables.sql"): "0f1211a10d13c7a3a6dc6118d12a9e423fe75bfe08cc4e867bfc0f0b3dda776d",
    ("mfa", "002_mfa_secrets.sql"): "6a2f97527369ea862e09b83f07eb3b27d90dc74aeb4b71a7f455f7a4990e78a9",
}


def test_discover_orders_sets_then_files() -> None:
    """Real catalog: vault → identity → passkey, with ascending names."""
    found = [(file.migration_set, file.filename) for file in discover(RELEASED_SETS)]
    assert found == list(RELEASED)


def test_discover_orders_tmp_catalog(tmp_catalog: Path) -> None:
    """Vault comes before identity regardless of filesystem ordering."""
    found = [(file.migration_set, file.filename) for file in discover()]
    assert found == [
        ("vault", "001_first.sql"),
        ("vault", "002_second.sql"),
        ("identity", "001_third.sql"),
    ]


def test_every_sql_dir_is_registered() -> None:
    """Every non-private directory under SQL_ROOT is a registered set."""
    directories = [
        path.name for path in catalog.SQL_ROOT.iterdir() if path.is_dir() and not path.name.startswith((".", "__"))
    ]
    assert set(directories).issubset(MIGRATION_SETS)


def test_discover_rejects_bad_filename_and_duplicate_prefix(tmp_catalog: Path) -> None:
    """Invalid names, duplicated prefixes, and unknown directories fail closed."""
    (tmp_catalog / "vault" / "1_bad.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationCatalogError, match="Invalid migration filename"):
        discover()

    (tmp_catalog / "vault" / "1_bad.sql").unlink()
    (tmp_catalog / "vault" / "001_duplicate.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationCatalogError, match="Duplicate migration prefix"):
        discover()

    (tmp_catalog / "vault" / "001_duplicate.sql").unlink()
    (tmp_catalog / "unknown").mkdir()
    with pytest.raises(MigrationCatalogError, match="Unknown migration set directories"):
        discover()


def test_released_files_are_byte_identical() -> None:
    """Released migrations retain the recorded raw-byte checksums."""
    found = {(file.migration_set, file.filename): file.checksum for file in discover(RELEASED_SETS)}
    assert found == RELEASED


def test_mfa_files_are_byte_identical() -> None:
    """MFA migrations retain their raw-byte checksums after catalog relocation."""
    found = {(file.migration_set, file.filename): file.checksum for file in discover(["mfa"])}
    assert found == MFA


def test_render_sql_leaves_hardcoded_schema_untouched() -> None:
    """Identity and vault released SQL does not contain catalog placeholders."""
    for file in discover(["vault", "identity"]):
        sql = file.path.read_text()
        assert render_sql(sql) == sql


def test_new_file_is_discovered_without_code_change(tmp_catalog: Path) -> None:
    """A valid newly-written file appears in discovery and set filenames."""
    (tmp_catalog / "identity" / "002_new.sql").write_text("SELECT 2;")
    assert [(file.migration_set, file.filename) for file in discover()] == [
        ("vault", "001_first.sql"),
        ("vault", "002_second.sql"),
        ("identity", "001_third.sql"),
        ("identity", "002_new.sql"),
    ]
    assert set_filenames("identity") == ("001_third.sql", "002_new.sql")


def test_set_dir_rejects_unknown_set_and_missing_dir_is_empty(tmp_catalog: Path) -> None:
    """Unknown set names fail, while a known absent directory has no files."""
    with pytest.raises(MigrationCatalogError, match="Unknown migration set"):
        set_dir("nope")
    assert set_filenames("passkey") == ()


def test_old_sql_dirs_are_gone() -> None:
    """Released SQL no longer remains in legacy subsystem directories."""
    package_root = Path(__file__).parents[3] / "navigator_auth"
    for migration_set in ("identity", "vault", "passkey", "mfa"):
        assert not (package_root / migration_set / "sql").exists()
