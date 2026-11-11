"""Shared fixtures for the FEAT-110 migration tests."""
from pathlib import Path

import pytest

from navigator_auth.migrations import catalog


@pytest.fixture
def tmp_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``catalog.SQL_ROOT`` at a temporary tree with two sets and three files.

    Layout: ``vault/001_first.sql``, ``vault/002_second.sql``, ``identity/001_third.sql``.
    """
    vault_dir = tmp_path / "vault"
    identity_dir = tmp_path / "identity"
    vault_dir.mkdir()
    identity_dir.mkdir()
    (vault_dir / "001_first.sql").write_text("SELECT 1;")
    (vault_dir / "002_second.sql").write_text("SELECT 2;")
    (identity_dir / "001_third.sql").write_text("SELECT '{schema}';")
    monkeypatch.setattr(catalog, "SQL_ROOT", tmp_path)
    return tmp_path
