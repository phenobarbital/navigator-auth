"""FEAT-099 (TASK-077): context-bound identity credentials and the identity vault target."""
import copy
import importlib
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from asyncdb.exceptions import NoDataFound
from navigator_session.vault import KeyRing, open_sealed, read_header
from navigator_session.vault.registry import ProtectedTarget, VaultRow

from navigator_auth.identity.crypto import IdentityCipher
from navigator_auth.identity.store import IdentityCredentialError, IdentityStore
from navigator_auth.identity.targets import IdentityTarget, factory
from navigator_auth.identity.types import TokenResponse

ROOT = Path(__file__).resolve().parents[3]
MASTER_KEYS = {1: b"\x05" * 32, 2: b"\x06" * 32}


@pytest.fixture
def cipher(monkeypatch):
    return IdentityCipher(keyring=KeyRing(MASTER_KEYS, 1))


@pytest.fixture
def store(cipher):
    return IdentityStore(MagicMock(), cipher=cipher)


class FakeMeta:
    connection = None


class FakeUserIdentity:
    Meta = FakeMeta
    existing = None

    def __init__(self, **kwargs):
        self.__dict__.update({"refresh_token": None, "id_token": None, "provider_user_id": None})
        self.__dict__.update(kwargs)

    @classmethod
    async def get(cls, **kwargs):
        if cls.existing is None:
            raise NoDataFound("miss")
        return cls.existing

    async def insert(self):
        return self

    async def update(self):
        return self


@pytest.fixture(autouse=True)
def fake_model():
    FakeUserIdentity.existing = None
    pool = MagicMock()

    @asynccontextmanager
    async def ctx():
        yield MagicMock()

    async def acquire():
        return ctx()

    pool.acquire = acquire
    with patch("navigator_auth.identity.store.UserIdentity", FakeUserIdentity):
        yield pool


def _row(identity, pk=None):
    return VaultRow(
        ref="r", pk=pk or uuid.uuid4(),
        identity={"user_id": identity.user_id, "auth_provider": identity.auth_provider,
                  "provider_user_id": identity.provider_user_id},
        values={f: getattr(identity, f) for f in ("access_token", "refresh_token", "id_token")},
    )


class TestStoreContextBinding:
    @pytest.mark.asyncio
    async def test_saved_tokens_bound_to_row_and_column(self, cipher, fake_model):
        store = IdentityStore(fake_model, cipher=cipher)
        token = TokenResponse(access_token="at", refresh_token="rt", id_token="idt", provider_user_id="acc-1")
        row = await store.save_linked_identity(user_id=7, provider="google", token=token)
        assert all(getattr(row, f)[0] == 0xA2 for f in ("access_token", "refresh_token", "id_token"))
        assert store.decrypt_credential(row).refresh_token == "rt"

        swapped = copy.copy(row)
        swapped.access_token, swapped.refresh_token = row.refresh_token, row.access_token
        with pytest.raises(IdentityCredentialError) as err:
            store.decrypt_credential(swapped)
        assert err.value.field == "access_token" and err.value.reason == "VaultIntegrityError"

        other_user = copy.copy(row)
        other_user.user_id = 8
        with pytest.raises(IdentityCredentialError):
            store.decrypt_credential(other_user)

        other_account = copy.copy(row)
        other_account.provider_user_id = "acc-2"
        with pytest.raises(IdentityCredentialError):
            store.decrypt_credential(other_account)

    @pytest.mark.asyncio
    async def test_relink_reseals_kept_tokens(self, cipher, fake_model):
        """A legacy row without provider_user_id gets one: kept tokens are re-sealed."""
        store = IdentityStore(fake_model, cipher=cipher)
        legacy = FakeUserIdentity(
            user_id=7, auth_provider="google", provider_user_id=None,
            refresh_token=store._seal("old-rt", 7, "google", None, "refresh_token"),
            id_token=store._seal("old-id", 7, "google", None, "id_token"),
        )
        FakeUserIdentity.existing = legacy
        token = TokenResponse(access_token="new-at", provider_user_id="acc-1")
        row = await store.save_linked_identity(user_id=7, provider="google", token=token)
        assert row.provider_user_id == "acc-1"
        credential = store.decrypt_credential(row)
        assert (credential.access_token, credential.refresh_token, credential.id_token) == (
            "new-at", "old-rt", "old-id",
        )

    @pytest.mark.asyncio
    async def test_resave_same_account_keeps_blobs(self, cipher, fake_model):
        store = IdentityStore(fake_model, cipher=cipher)
        kept = store._seal("old-rt", 7, "google", "acc-1", "refresh_token")
        FakeUserIdentity.existing = FakeUserIdentity(
            user_id=7, auth_provider="google", provider_user_id="acc-1", refresh_token=kept,
        )
        row = await store.save_linked_identity(
            user_id=7, provider="google", token=TokenResponse(access_token="at", provider_user_id="acc-1")
        )
        assert row.refresh_token == kept

    @pytest.mark.asyncio
    async def test_relink_with_tampered_kept_token_fails(self, cipher, fake_model):
        store = IdentityStore(fake_model, cipher=cipher)
        FakeUserIdentity.existing = FakeUserIdentity(
            user_id=7, auth_provider="google", provider_user_id=None,
            refresh_token=store._seal("rt", 99, "google", None, "refresh_token"),  # another user's
        )
        with pytest.raises(IdentityCredentialError):
            await store.save_linked_identity(
                user_id=7, provider="google", token=TokenResponse(access_token="at", provider_user_id="acc-1")
            )

    @pytest.mark.asyncio
    async def test_update_tokens_uses_row_context(self, cipher, fake_model):
        store = IdentityStore(fake_model, cipher=cipher)
        identity = FakeUserIdentity(user_id="7", auth_provider="github", provider_user_id="gh-1",
                                    token_type="Bearer", expires_at=None, scopes=[])
        await store.update_tokens(identity, TokenResponse(access_token="at2", refresh_token="rt2"))
        credential = store.decrypt_credential(identity)
        assert (credential.access_token, credential.refresh_token) == ("at2", "rt2")
        assert identity.key_version == 1

    def test_error_message_has_no_secret(self):
        err = IdentityCredentialError("google", "refresh_token", "VaultIntegrityError")
        assert str(err) == "google: stored refresh_token cannot be decrypted (VaultIntegrityError)"


class TestIdentityTarget:
    def test_context_matches_store_sealing(self, store):
        identity = FakeUserIdentity(user_id="12", auth_provider="azure", provider_user_id=None)
        identity.access_token = store._seal("at", 12, "azure", None, "access_token")
        identity.id_token = store._seal("idt", "12", "azure", None, "id_token")
        target = IdentityTarget(db_pool=object())
        row = _row(identity)
        for field in ("access_token", "id_token"):
            assert open_sealed(getattr(identity, field), target.context_for(row, field), store._cipher.keyring)
        ctx = target.context_for(row, "id_token")
        assert ctx.purpose == "identity" and ctx.fields[-1] == ("field", "id_token")

    def test_declaration(self):
        target = IdentityTarget(db_pool=object(), schema="tenant_auth")
        assert target.name == target.table == "tenant_auth.user_identities"
        assert isinstance(target, ProtectedTarget)
        assert target.encrypted_fields == ("access_token", "refresh_token", "id_token")
        assert factory({}) is None and isinstance(factory({"db_pool": object()}), IdentityTarget)
        assert target.pk_from_json(str(uuid.UUID(int=1))) == uuid.UUID(int=1)
        assert target.state_from_json("enabled", 0) is False

    def test_entry_point_declared(self):
        tomllib = pytest.importorskip("tomllib")
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        spec = data["project"]["entry-points"]["navigator_session.vault_targets"]["identity"]
        module, attr = spec.split(":")
        assert getattr(importlib.import_module(module), attr) is factory


class RecordingConn:
    """Interprets the statements IdentityTarget issues (select / update)."""

    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    def transaction(self):
        conn = self

        class Tx:
            async def start(self):
                self.snapshot = copy.deepcopy(conn.rows)

            async def commit(self):
                pass

            async def rollback(self):
                conn.rows[:] = self.snapshot

        return Tx()

    async def fetch(self, sql, *args):
        sql = " ".join(sql.replace('"', "").split())
        self.statements.append(sql)
        cols = [c.strip() for c in re.match(r"SELECT (.+?) FROM", sql).group(1).split(",")]
        rows = sorted(self.rows, key=lambda r: r["identity_id"])
        if "WHERE identity_id > $1" in sql:
            rows = [r for r in rows if r["identity_id"] > args[0]]
        return [{c: r[c] for c in cols} for r in rows[: args[-1]]]

    async def execute(self, sql, *args):
        sql = " ".join(sql.replace('"', "").split())
        self.statements.append(sql)
        match = re.match(r"UPDATE (\S+) SET (.+) WHERE identity_id = \$(\d+)$", sql)
        pk = args[int(match.group(3)) - 1]
        count = 0
        for row in self.rows:
            if row["identity_id"] != pk:
                continue
            for col, expr in re.findall(r"(\w+) = (\$\d+|false)", match.group(2)):
                row[col] = False if expr == "false" else args[int(expr[1:]) - 1]
            count += 1
        return f"UPDATE {count}"


class RecordingPool:
    def __init__(self, rows):
        self.conn = RecordingConn(rows)

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


@pytest.mark.asyncio
class TestIdentityTargetStorage:
    async def test_iterate_quarantine_export_restore(self, store):
        rows = []
        for i in range(3):
            pk = uuid.UUID(int=i + 1)
            rows.append({
                "identity_id": pk, "user_id": 10 + i, "auth_provider": "google", "provider_user_id": f"acc-{i}",
                "access_token": store._seal("at", 10 + i, "google", f"acc-{i}", "access_token"),
                "refresh_token": None if i == 1 else store._seal("rt", 10 + i, "google", f"acc-{i}", "refresh_token"),
                "id_token": None, "key_version": 1, "enabled": True,
            })
        before = copy.deepcopy(rows)
        pool = RecordingPool(rows)
        target = IdentityTarget(pool)

        batches = [b async for b in target.iter_batches(2)]
        assert [len(b) for b in batches] == [2, 1]
        first = batches[0][0]
        assert read_header(first.values["access_token"]).key_id == 1

        records = []

        class Sink:
            async def write(self, name, record):
                records.append(record)

        class Source:
            async def read(self, name):
                for record in records:
                    yield record

        assert await target.export_raw(Sink()) == 3
        await target.quarantine(first, "VaultIntegrityError", run_id="r1")
        assert rows[0]["enabled"] is False and rows[0]["access_token"] == before[0]["access_token"]
        await target.write(batches[0][1], {"access_token": b"\xa2new"}, 2)
        assert await target.restore_raw(Source()) == 3
        assert rows == before
