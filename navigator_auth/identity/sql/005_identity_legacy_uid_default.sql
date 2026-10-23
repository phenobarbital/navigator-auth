-- Identity Vault: make the legacy `uid` column self-filling (FEAT-103 Module 0)
--
-- Migration 004 added the base columns the `UserIdentity` model requires, but
-- a legacy `auth.user_identities` ALSO carries `uid VARCHAR NOT NULL` with no
-- default, and `uid` is half of the legacy primary key `(user_id, uid)`. The
-- model (`models.py:77`) has no `uid` field, so every `IdentityStore` insert
-- omits the column and Postgres rejects the row with
--
--     null value in column "uid" violates not-null constraint
--
-- i.e. G2 (the ciphered vault write) is STILL unreachable on a legacy
-- database after 004. Measured on the `navigator` dev database on 2026-10-23:
-- `uid` is `character varying`, `is_nullable = NO`, `column_default = NULL`,
-- and the primary key is `(user_id, uid)`.
--
-- SUPERSEDED IN PART (FEAT-104): the claim below that the model can simply
-- ignore `uid` is wrong. asyncdb's `Model.filter()` / `Model.all()` issue
-- `SELECT *` and pass every column to the dataclass constructor, so the column
-- made hydration raise `TypeError: UserIdentity.__init__() got an unexpected
-- keyword argument 'uid'` on every legacy database.
-- `006_identity_drop_legacy_uid.sql` therefore drops the column after this
-- migration has run. This file stays as it is: it is what lets an insert
-- succeed in the window before 006 completes, and on a database where 006
-- has to skip because something else depends on `uid`.
--
-- Why a DEFAULT and not a drop: `uid` has no reader. The canonical DDL
-- (`examples/sql/identity_vault_schema.sql:57`) has no such column at all, and
-- nothing in `navigator_auth` selects or writes it. On a legacy table it is a
-- vestigial surrogate, so a surrogate DEFAULT is enough to let the model write
-- while leaving every existing row, the column and the legacy primary key
-- exactly as they are. Provider-account uniqueness does not depend on `uid`:
-- it is enforced by `uq_user_identities_provider_account` (001).
--
-- `uid` is an unbounded varchar on the legacy table, so a 36-character UUID
-- text fits without truncation.
--
-- Additive, idempotent and a no-op against a canonical database (the column
-- guard below skips it) and after the first run (the `column_default IS NULL`
-- guard), so a steady-state startup takes no ACCESS EXCLUSIVE lock. Nothing is
-- dropped and no existing row is rewritten.

DO $$
BEGIN
    IF to_regclass('auth.user_identities') IS NULL THEN
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'auth'
           AND table_name = 'user_identities'
           AND column_name = 'uid'
           AND column_default IS NULL
    ) THEN
        ALTER TABLE auth.user_identities
            ALTER COLUMN uid SET DEFAULT gen_random_uuid()::varchar;
    END IF;
END $$;
