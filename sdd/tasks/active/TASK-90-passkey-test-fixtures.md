# TASK-90: Software-authenticator and RP-config test fixtures

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 9, §4 Test Data / Fixtures)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-86
**Assigned-to**: unassigned

---

## Context

Part of serial stage S0. Every live ceremony test in TASKS 94 to 96 needs real WebAuthn
attestation and assertion payloads, without a browser. This task builds a software authenticator:
an ES256 key, plus hand-built `authenticatorData`, `clientDataJSON` and a "none"-format
attestation. Its output must pass py_webauthn's real verifiers.

---

## Scope

- Create `tests/fixtures/passkey.py` with two fixtures:
  - `soft_authenticator` returns a helper object with `make_attestation(...)` and `make_assertion(...)`.
  - `passkey_rp_config(monkeypatch)` sets up two RPs: `https://a.test` (rp_id `a.test`, org 5,
    client 1) and `https://b.test` (rp_id `b.test`, org 7, client 2). It patches
    `navigator_auth.conf.PASSKEY_RELYING_PARTIES` and returns the list.
- The output is py_webauthn-compatible JSON: base64url fields, `type: "public-key"`, `id`/`rawId`,
  `response.{clientDataJSON, attestationObject | authenticatorData, signature, userHandle}`.
- Flag support: UV on or off, a chosen `sign_count`, an optional `user_handle`, and an overridable
  `origin` for the origin-mismatch tests.
- Write `tests/test_passkey_fixtures.py`, which self-checks the fixture against
  `webauthn.verify_registration_response` and `verify_authentication_response`, using the API that
  TASK-86 verified.

**NOT in scope**: the ceremony tests themselves (TASKS 94 to 96), and Playwright (TASK-97).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/fixtures/passkey.py` | CREATE | Fixtures and `SoftAuthenticator` helper |
| `tests/test_passkey_fixtures.py` | CREATE | Round-trip self-check through py_webauthn |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
from cryptography.hazmat.primitives.asymmetric import ec      # cryptography>=41.0 (pyproject dependency)
from cryptography.hazmat.primitives import hashes
import hashlib, json, os, struct, base64
# py_webauthn (installed by TASK-86) — use the names TASK-86 recorded in spec §6 "verified":
#   webauthn.helpers.bytes_to_base64url / base64url_to_bytes
#   webauthn.verify_registration_response / verify_authentication_response
# CBOR: confirm whether py_webauthn depends on `cbor2` (it does in 2.x) and reuse it for the
# attestationObject and COSE key; do not add a new dependency.
```

### Existing Signatures to Use
- `tests/` is a package (`tests/__init__.py`), but `tests/fixtures/` has no `__init__.py` (only
  `saml/` data). Import the module as the namespace package `tests.fixtures.passkey`.
- `tests/conftest.py` is not the rootdir conftest, so pytest refuses `pytest_plugins` there.
  Consumers import the fixtures explicitly:
  `from tests.fixtures.passkey import soft_authenticator, passkey_rp_config  # noqa: F401`.

### Does NOT Exist
- No WebAuthn test helpers anywhere in `tests/`.
- No `cbor2` usage in navigator_auth. It comes in only as a py_webauthn dependency.

---

## Implementation Blueprint

### Steps (in order)
1. Build `authenticatorData`: `sha256(rp_id)`, then the flags byte (UP=0x01, UV=0x04, AT=0x40),
   then the big-endian 32-bit `sign_count`. Registration also appends the attested credential data:
   AAGUID (16 zero bytes), then the credential-id length, the credential id, and the COSE EC2 key.
2. Build `clientDataJSON` as `{"type": "webauthn.create"|"webauthn.get", "challenge": b64url, "origin": origin, "crossOrigin": false}`.
3. Registration: `attestationObject = cbor({"fmt": "none", "attStmt": {}, "authData": ...})`.
4. Assertion: sign `authenticatorData + sha256(clientDataJSON)` with ECDSA-SHA256, DER-encoded.
5. Prove it with the self-check test before anything depends on it. A fixture bug otherwise shows
   up as baffling 401s in TASKS 94 and 95.

### `tests/fixtures/passkey.py` — CREATE
```python
"""Software WebAuthn authenticator for FEAT-101 passkey tests (no browser)."""
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40

RP_CONFIG = [
    {"origin": "https://a.test", "rp_id": "a.test", "rp_name": "A", "org_id": 5, "client_id": 1},
    {"origin": "https://b.test", "rp_id": "b.test", "rp_name": "B", "org_id": 7, "client_id": 2},
]


@dataclass
class SoftAuthenticator:
    """ES256 software authenticator producing py_webauthn-compatible JSON."""

    private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))

    def cose_public_key(self) -> bytes:
        """COSE_Key (kty=2, alg=-7, crv=1, x, y) CBOR-encoded."""
        # FILL IN: numbers = public_key().public_numbers(); x/y 32-byte big-endian; cbor encode.
        raise NotImplementedError

    def _auth_data(self, rp_id: str, sign_count: int, uv: bool, attested: bool) -> bytes:
        flags = FLAG_UP | (FLAG_UV if uv else 0) | (FLAG_AT if attested else 0)
        data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)
        if attested:
            # FILL IN: AAGUID (16 zero bytes) + len(credential_id) as >H + credential_id + cose key.
            pass
        return data

    def make_attestation(
        self, rp_id: str, origin: str, challenge: bytes, user_handle: bytes, uv: bool = True
    ) -> dict:
        """RegistrationCredential JSON for register/verify (fmt "none")."""
        # FILL IN: clientDataJSON type webauthn.create; attestationObject; base64url fields;
        #          include transports ["internal"] and clientExtensionResults {}.
        raise NotImplementedError

    def make_assertion(
        self,
        rp_id: str,
        origin: str,
        challenge: bytes,
        sign_count: int = 0,
        uv: bool = True,
        user_handle: Optional[bytes] = None,
    ) -> dict:
        """AuthenticationCredential JSON for POST /api/v1/login (X-Auth-Method: PasskeyAuth)."""
        # FILL IN: clientDataJSON type webauthn.get; signature over authData + sha256(cdj);
        #          userHandle base64url or omitted when None.
        raise NotImplementedError


@pytest.fixture
def soft_authenticator() -> SoftAuthenticator:
    """A fresh ES256 software authenticator per test."""
    return SoftAuthenticator()


@pytest.fixture
def passkey_rp_config(monkeypatch) -> list[dict]:
    """Two RPs: https://a.test (org 5) and https://b.test (org 7)."""
    import navigator_auth.conf as conf

    monkeypatch.setattr(conf, "PASSKEY_RELYING_PARTIES", RP_CONFIG, raising=False)
    # PasskeyAuth (TASK-93) reads every PASSKEY_* setting as `auth_conf.<NAME>` at call time
    # (`from .. import conf as auth_conf`), so patching navigator_auth.conf is enough.
    return RP_CONFIG
```
**Why**: A dataclass keeps one key and credential pair per test. Tests then re-use the same
authenticator across register → login → login (sign count) flows.

### `tests/test_passkey_fixtures.py` — CREATE
```python
"""FEAT-101 TASK-90 — the software authenticator passes py_webauthn's real verifiers."""
import os

import pytest

webauthn = pytest.importorskip("webauthn")

from tests.fixtures.passkey import soft_authenticator  # noqa: F401,E402


def test_attestation_roundtrip(soft_authenticator):
    """verify_registration_response accepts make_attestation output."""
    # FILL IN: challenge = os.urandom(32); verify with expected_rp_id "a.test",
    #          expected_origin "https://a.test"; assert credential_id matches.


def test_assertion_roundtrip(soft_authenticator):
    """verify_authentication_response accepts make_assertion output (UV on, count 1)."""


def test_assertion_without_uv_rejected_when_required(soft_authenticator):
    """require_user_verification=True rejects uv=False."""
```

### FILL IN checklist
- [ ] COSE key and CBOR encoding.
- [ ] Attested credential data.
- [ ] Both `make_*` helpers.
- [ ] Three round-trip tests.

---

## Acceptance Criteria

- [ ] `pytest tests/test_passkey_fixtures.py -v` passes: py_webauthn accepts the soft authenticator's attestation and assertion.
- [ ] Without `webauthn` installed, those tests skip and nothing else breaks.
- [ ] `ruff check tests/fixtures/passkey.py tests/test_passkey_fixtures.py` is clean.

---

## Test Specification

See the blueprint above (spec §4 Test Data / Fixtures).

---

## Agent Instructions

1. Read the spec (§4 Test Data / Fixtures) and TASK-86's verified py_webauthn block in spec §6.
2. Confirm TASK-86 is in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
