"""Doc contract for the FEAT-106 review fixes (spec §10 Documentation).

Fails when docs/two_factor_auth.rst or CHANGELOG.md misses a review-fix behaviour
change, or still states behaviour the fixes removed.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "two_factor_auth.rst"
CHANGELOG = ROOT / "CHANGELOG.md"

REQUIRED_TERMS = (
    "AUTH_MFA_RETRY_INTERVAL",
    "AUTH_MFA_LOCK_TIMEOUT",
    "/oauth2/login/mfa",
    "user_mfa_secrets",
    "002_mfa_secrets.sql",
    "navigator_session.vault_targets",
    "navigator_auth.mfa.targets:factory",
    "strong_factor_proof_required",
    "amr",
    "introspect",
    "userinfo",
    "refresh",
    "oauth_user_generation",
    "recovery_confirm_consumptions",
    "password_reset",
    "mfa_unavailable",
    "credentials_changed",
)
STALE_STATEMENTS = (
    "TOTP seeds are sealed by the vault kernel in ``auth.user_vault_secrets``",
    "regenerated only with password re-authentication.",
    "Startup still succeeds so the deployment can be repaired without masking the outage",
)


def _normalized(path: Path) -> str:
    """Return the file text with every whitespace run collapsed to one space."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_guide_documents_every_review_fix():
    """Every spec §10 topic is named in the 2FA guide."""
    text = _normalized(GUIDE)
    missing = [term for term in REQUIRED_TERMS if term not in text]
    assert not missing, f"docs/two_factor_auth.rst is missing: {missing}"


def test_guide_has_vault_reinstall_note():
    """The mfa vault target is visible to navigator-vault only after reinstalling the package."""
    text = _normalized(GUIDE)
    assert re.search(r"reinstall|uv pip install -e", text)


def test_guide_drops_stale_statements():
    """Statements the review fixes made false are gone."""
    text = _normalized(GUIDE)
    stale = [sentence for sentence in STALE_STATEMENTS if sentence in text]
    assert not stale, f"stale statements remain: {stale}"


def test_changelog_has_0_30_0_entry():
    """CHANGELOG.md names the 0.30.0 review-fix release."""
    text = _normalized(CHANGELOG)
    assert "0.30.0" in text
    assert "FEAT-106 review fixes" in text
