"""The migrations README indexes every catalog file (FEAT-110, spec M7)."""

from pathlib import Path

from navigator_auth.migrations.catalog import discover

ROOT = Path(__file__).resolve().parents[3]
README = ROOT / "docs" / "migrations" / "README.md"


def test_readme_index_lists_every_sql_file():
    """Every discover() filename appears in docs/migrations/README.md."""
    text = README.read_text(encoding="utf-8")
    missing = [f"{f.migration_set}/{f.filename}" for f in discover() if f.filename not in text]
    assert not missing, f"docs/migrations/README.md does not index: {missing}"


def test_docs_wire_the_page_and_changelog():
    """docs/index.rst toctree lists `migrations`; CHANGELOG `# Unreleased` mentions `navauth self upgrade`."""
    index_lines = (ROOT / "docs" / "index.rst").read_text(encoding="utf-8").splitlines()
    assert "   migrations" in index_lines
    assert (ROOT / "docs" / "migrations.rst").is_file()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog.startswith("# Unreleased")
    unreleased = changelog.split("\n# ", 1)[0]
    assert "navauth self upgrade" in unreleased
