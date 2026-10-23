"""Unit tests for the allowlist redaction primitives (FEAT-105, TASK-118)."""

from navigator_auth.handlers.redaction import (
    redact_row,
    redact_rows,
    redact_schema,
    safe_fields,
)

IDENTITY_PUBLIC = frozenset(
    {
        "identity_id",
        "user_id",
        "display_name",
        "title",
        "nickname",
        "email",
        "phone",
        "short_bio",
        "avatar",
        "auth_provider",
        "provider_user_id",
        "scopes",
        "token_type",
        "expires_at",
        "refreshed_at",
        "created_at",
        "enabled",
        "auth_data",
        "attributes",
    }
)
IDENTITY_CREDENTIALS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "key_version",
    }
)


class _Row:
    """Attribute-style row double."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _full_dict():
    d = {c: f"v-{c}" for c in IDENTITY_PUBLIC}
    d.update({c: "SECRET" for c in IDENTITY_CREDENTIALS})
    return d


class TestSafeFields:
    def test_none_stays_none(self):
        assert safe_fields(None, IDENTITY_PUBLIC) is None

    def test_intersects_never_unions(self):
        assert safe_fields(["access_token", "email"], IDENTITY_PUBLIC) == ["email"]
        res = safe_fields(["access_token"], IDENTITY_PUBLIC)
        assert res == [] and res is not None

    def test_preserves_caller_order(self):
        assert safe_fields(["email", "phone"], IDENTITY_PUBLIC) == ["email", "phone"]
        assert safe_fields(["phone", "email"], IDENTITY_PUBLIC) == ["phone", "email"]


class TestRedactRow:
    def test_drops_everything_outside_allowlist(self):
        out = redact_row(_Row(**_full_dict()), IDENTITY_PUBLIC)
        assert not (set(out) & IDENTITY_CREDENTIALS)
        assert out["email"] == "v-email"

    def test_drops_everything_outside_allowlist_dict(self):
        out = redact_row(_full_dict(), IDENTITY_PUBLIC)
        assert not (set(out) & IDENTITY_CREDENTIALS)
        assert out["email"] == "v-email"

    def test_fields_cannot_project_a_credential(self):
        out = redact_row(_full_dict(), IDENTITY_PUBLIC, fields=["access_token", "email"])
        assert out == {"email": "v-email"}

    def test_none_row_is_empty_dict(self):
        assert redact_row(None, IDENTITY_PUBLIC) == {}

    def test_absent_column_does_not_raise(self):
        out = redact_row({"email": "a@b"}, IDENTITY_PUBLIC)
        assert set(out) == set(IDENTITY_PUBLIC)
        assert out["email"] == "a@b" and out["phone"] is None

    def test_key_order_is_stable(self):
        a = redact_row(_full_dict(), IDENTITY_PUBLIC)
        b = redact_row(_full_dict(), IDENTITY_PUBLIC)
        assert list(a) == list(b)


class TestRedactRows:
    def test_preserves_list_vs_scalar_shape(self):
        assert isinstance(redact_rows([_full_dict()], IDENTITY_PUBLIC), list)
        assert isinstance(redact_rows(_full_dict(), IDENTITY_PUBLIC), dict)
        assert redact_rows(None, IDENTITY_PUBLIC) is None


class TestRedactSchema:
    def test_strips_credential_columns(self):
        from navigator_auth.models import UserIdentity

        out = redact_schema(UserIdentity.schema(as_dict=True), IDENTITY_CREDENTIALS)
        assert not (set(out["properties"]) & IDENTITY_CREDENTIALS)
        assert "email" in out["properties"]

    def test_strips_credentials_from_required(self):
        schema = {"properties": {"a": {}, "access_token": {}}, "required": ["a", "access_token"]}
        assert redact_schema(schema, IDENTITY_CREDENTIALS)["required"] == ["a"]

    def test_does_not_mutate_the_cached_schema(self):
        from navigator_auth.models import UserIdentity

        redact_schema(UserIdentity.schema(as_dict=True), IDENTITY_CREDENTIALS)
        assert "access_token" in UserIdentity.schema(as_dict=True)["properties"]

    def test_tolerates_a_schema_without_the_keys(self):
        assert redact_schema({}, IDENTITY_CREDENTIALS) == {}
        assert redact_schema({"properties": {"a": {}}}, IDENTITY_CREDENTIALS) == {"properties": {"a": {}}}
