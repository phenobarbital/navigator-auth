-- Identity Vault: base columns on auth.user_identities (FEAT-103 Module 0)
--
-- Migrations 001-003 added the credential columns, but the BASE columns the
-- `UserIdentity` model requires (models.py:77) were only ever written into
-- examples/sql/identity_vault_schema.sql. A database created before that file
-- therefore has no `identity_id`, and every IdentityStore write fails with
-- `column "identity_id" does not exist`.
--
-- Additive and idempotent -- re-run on every startup, and a no-op against a
-- database already built from the canonical DDL. The legacy (user_id, uid)
-- primary key and the `uid` column are deliberately LEFT IN PLACE: the model
-- ignores `uid`, and dropping anything in a migration that also runs against
-- healthy databases is the riskier choice.

ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS identity_id  UUID DEFAULT gen_random_uuid(),
    ADD COLUMN IF NOT EXISTS display_name VARCHAR(254),
    ADD COLUMN IF NOT EXISTS title        VARCHAR(120),
    ADD COLUMN IF NOT EXISTS nickname     VARCHAR(120),
    ADD COLUMN IF NOT EXISTS email        VARCHAR(254),
    ADD COLUMN IF NOT EXISTS phone        VARCHAR(50),
    ADD COLUMN IF NOT EXISTS short_bio    TEXT,
    ADD COLUMN IF NOT EXISTS avatar       TEXT;

-- Backfill rows that predate the default (no-op when none are NULL).
UPDATE auth.user_identities
   SET identity_id = gen_random_uuid()
 WHERE identity_id IS NULL;

-- Make identity_id addressable as the model's key, guarded on every axis:
--  * table absent            -> skipped (to_regclass IS NULL)
--  * identity_id already PK  -> skipped (canonical DDL; a second ADD PRIMARY
--                               KEY would raise 42P16)
--  * legacy (user_id, uid) PK -> the legacy key is LEFT IN PLACE and a UNIQUE
--                               index on identity_id is added instead, which
--                               is all UserIdentity.get(identity_id=...) needs.
DO $$
DECLARE
    current_pk text;
BEGIN
    IF to_regclass('auth.user_identities') IS NULL THEN
        RETURN;
    END IF;

    SELECT string_agg(a.attname, ',' ORDER BY k.ord)
      INTO current_pk
      FROM pg_constraint c
      JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
     WHERE c.conrelid = 'auth.user_identities'::regclass
       AND c.contype = 'p';

    IF current_pk IS DISTINCT FROM 'identity_id' THEN
        CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_identity_id
            ON auth.user_identities (identity_id);
    END IF;
END $$;
