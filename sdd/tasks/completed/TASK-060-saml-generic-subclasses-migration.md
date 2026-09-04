# TASK-060: Generic SAMLAuth / SAMLIdentityProvider subclasses, legacy settings translation, package exports

**Feature**: FEAT-097 saml-backend-abstract
**Spec**: `sdd/specs/saml-backend-abstract.spec.md` (Module 6)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-057, TASK-059
**Assigned-to**: unassigned

---

## Context

Delivers the reference subclasses that make the abstract bases usable out of the box, keeps
the `SAMLAuth` import path stable, translates the known `python3-saml` settings keys, and
removes the legacy module (spec §3 Module 6, §6 Known Risks "Breaking settings change").

---

## Scope

- `navigator_auth/backends/saml/__init__.py`:
  - `SAMLAuth(AbstractSAMLBackend)`: `get_idp_metadata` → `SAML_METADATA` (path or URL; if
    unset and `SAML_PATH` is set, look for `<SAML_PATH>/idp-metadata.xml` then
    `<SAML_PATH>/certs/idp.crt` + legacy settings for endpoints); `get_attribute_mapping` →
    `SAML_MAPPING`; `resolve_user_identifier` → mapped `username`, else `email`, else
    `name_id`; `get_settings` → translated `SAML_SETTINGS`.
  - `SAMLIdentityProvider(AbstractSAMLIdentityProvider)`: `get_service_providers` →
    `SAML_IDP_SERVICE_PROVIDERS` via `ServiceProviderConfig.from_dict`; `build_attributes` →
    inverse of `SAML_MAPPING` restricted to `sp.attribute_map` when non-empty (values as
    single-element lists).
  - Re-export `AbstractSAMLBackend`, `AbstractSAMLIdentityProvider`, `SAMLCore`, types,
    errors.
- Legacy translation `translate_legacy_settings(settings: dict) -> dict` in `saml/legacy.py`:
  map `strict`, `sp.entityId`, `sp.assertionConsumerService.url`,
  `sp.singleLogoutService.url`, `sp.x509cert`/`sp.privateKey`, `idp.entityId`,
  `idp.singleSignOnService.url`, `idp.singleLogoutService.url`, `idp.x509cert`,
  `security.wantAssertionsSigned`, `security.wantMessagesSigned`,
  `security.authnRequestsSigned`, `security.nameIdEncrypted` (reject: unsupported) to the
  pysaml2 config shape. Unknown keys → `ConfigError` listing them (OQ6 default: hard fail).
- `navigator_auth/backends/__init__.py`: export `SAMLAuth`, `SAMLIdentityProvider`,
  `AbstractSAMLBackend`, `AbstractSAMLIdentityProvider` from the package; remove the
  try/except guard added in TASK-054.
- Delete `navigator_auth/backends/_legacy_saml.py`.
- `navigator_auth/version.py`: bump to `0.26.0` (spec target).

**NOT in scope**: docs (TASK-061); round-trip tests (TASK-061).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/saml/__init__.py` | MODIFY | Reference subclasses + exports |
| `navigator_auth/backends/saml/legacy.py` | CREATE | Settings translator |
| `navigator_auth/backends/__init__.py` | MODIFY | Exports |
| `navigator_auth/backends/_legacy_saml.py` | DELETE | Legacy python3-saml backend |
| `navigator_auth/version.py` | MODIFY | `0.26.0` |
| `tests/test_saml_generic.py` | CREATE | M6 rows: config, legacy translation, exports |

---

## Implementation Notes

### Key Constraints
- `from navigator_auth.backends import SAMLAuth` must keep working (used in
  `AUTHENTICATION_BACKENDS` strings in deployments).
- The translator is pure and unit-tested without pysaml2 objects.
- `grep -rn onelogin navigator_auth/` must return nothing after this task.

### References in Codebase
- `navigator_auth/backends/__init__.py:18,35` — current export
- `documentation/saml.md` — the legacy `settings.json` keys users have today (source of the translation table)

---

## Acceptance Criteria

- [ ] `pytest tests/test_saml_generic.py tests/test_saml_*.py -v` passes
- [ ] `python -c "from navigator_auth.backends import SAMLAuth, SAMLIdentityProvider, AbstractSAMLBackend, AbstractSAMLIdentityProvider"` succeeds
- [ ] No `onelogin` import remains; `_legacy_saml.py` deleted
- [ ] Unknown legacy keys fail at startup with a message listing them

---

## Test Specification

```python
# tests/test_saml_generic.py
import pytest
from navigator_auth.backends.saml.legacy import translate_legacy_settings
from navigator_auth.exceptions import ConfigError

def test_legacy_settings_translation():
    cfg = translate_legacy_settings({"strict": True, "idp": {"entityId": "urn:idp",
        "singleSignOnService": {"url": "https://idp/sso"}, "x509cert": "MIIB..."}})
    assert cfg["metadata"]["inline"][0]  # inline IdP metadata generated

def test_legacy_settings_unknown_key():
    with pytest.raises(ConfigError, match="security.unknownFlag"):
        translate_legacy_settings({"security": {"unknownFlag": True}})

def test_generic_samlauth_config(monkeypatch, saml_keys): ...
def test_backend_exports():
    from navigator_auth.backends import SAMLAuth, SAMLIdentityProvider
```
---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-<NNN>-<slug>.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: sdd-worker (Claude Sonnet 5, session_01KS7E6KxYXnkgzMnYHaJC2U)
**Date**: 2026-09-05
**Notes**: `SAMLAuth`/`SAMLIdentityProvider` added to
`navigator_auth/backends/saml/__init__.py` exactly per spec's hook
mapping (`get_idp_metadata`'s `SAML_METADATA` → `SAML_PATH` fallback
chain, `resolve_user_identifier`'s username→email→NameID fallback,
`get_settings` → `translate_legacy_settings(SAML_SETTINGS)`;
`SAMLIdentityProvider.build_attributes` as the inverse of `SAML_MAPPING`
restricted to `sp.attribute_map`'s keys). New
`navigator_auth/backends/saml/legacy.py`:
`translate_legacy_settings(settings) -> dict` walks the flattened
dotted-path keys, translates the documented `python3-saml` keys into a
`pysaml2` config shape, and raises `ConfigError` naming every key not in
the known set (`grep -rn onelogin navigator_auth/` now returns nothing).
`backends/__init__.py`'s TASK-054 guard is removed (unconditional import,
matching every other backend); `backends/_legacy_saml.py` deleted.
`version.py` → `0.26.0`. `tests/test_saml_generic.py` (15 tests) covers
every M6 row; full SAML suite (96 incl. `test_oauth2_upstream_idp.py`)
and a broader adfs/redirect/identity regression check (145 passed, 1
pre-existing unrelated failure) both green.

**Deviations from spec**: the legacy translator's IdP-metadata generation
is a hand-templated XML string (`_build_idp_metadata_xml`), not built via
`saml2.metadata.entity_descriptor`/`IdPConfig` (as every other metadata
renderer in this feature does) — deliberate, not an oversight: Key
Constraints says "The translator is pure and unit-tested without pysaml2
objects," and `entity_descriptor()` actually *parses and validates* the
certificate file it's given, which breaks on the placeholder cert content
(`"MIIB..."`) the task's own `test_legacy_settings_translation` pseudocode
uses. Legacy `sp.x509cert`/`sp.privateKey`/`idp.x509cert` values are raw
PEM *content* (per `documentation/saml.md`'s example), not file paths;
spilled to `tempfile.NamedTemporaryFile` for the SP key/cert (`pysaml2`'s
`key_file`/`cert_file` config wants paths) and string-embedded directly
for the IdP's `<X509Certificate>` (no file needed since the hand-built
metadata doesn't go through `pysaml2`'s file-reading validation path).
`build_attributes`'s "inverse restricted to `sp.attribute_map`" reading:
the spec's own field comment for `ServiceProviderConfig.attribute_map` is
`saml_attr -> user_field` (opposite direction from `SAML_MAPPING`'s
`user_field -> saml_attr`), so "restricted to `sp.attribute_map`" is
implemented as restricting the inverse-mapping's *keys* (SAML attribute
names) to `sp.attribute_map`'s own keys, using `sp.attribute_map`'s value
as a per-attribute user-field override when given — documented in the
method's docstring since the one-line spec text underspecifies this.
