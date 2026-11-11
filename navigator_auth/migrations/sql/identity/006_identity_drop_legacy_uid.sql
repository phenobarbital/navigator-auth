-- Identity Vault: drop the legacy `uid` column from auth.user_identities
--
-- This is the ONE migration in this directory that removes something, and it
-- is deliberate. Migration 005 kept `uid` on the premise that "the model
-- ignores it" — it does not. asyncdb's `Model.filter()` / `Model.all()` issue
-- `SELECT *` and hand every returned column to the dataclass `__init__`, so
-- the vestigial column makes hydration raise
--
--     TypeError: UserIdentity.__init__() got an unexpected keyword argument 'uid'
--
-- `navigator_auth/identity/store.py` now projects the model's own columns and
-- no longer depends on this, but `UserIdentityHandler`
-- (`/api/v1/user_identity`) goes through navigator-api's `ModelHandler`, which
-- calls `Model.filter()` / `Model.all()` inside the library. On a legacy table
-- that route cannot work while the column exists, so the column goes.
--
-- `uid` has no reader anywhere: the canonical DDL
-- (`examples/sql/identity_vault_schema.sql`) has no such column, nothing in
-- `navigator_auth` selects or writes it, and 005 had already reduced it to a
-- `gen_random_uuid()` surrogate. **Dropping it is irreversible** — the
-- surrogate values are not preserved.
--
-- Order of operations (one DO block = one statement = one transaction, so a
-- failure anywhere leaves the table exactly as it was):
--
--   1. Table absent, or no `uid` column (a canonical database) -> no-op, and
--      no lock is taken. This is also what every startup after the first one
--      does.
--   2. A view, a rule, or a constraint other than the legacy primary key
--      depends on `uid` -> WARNING and skip. Removing the column would
--      require CASCADE, and CASCADE would take that object with it. Never.
--   3. `identity_id` is completed (backfill + NOT NULL); when it is not the
--      primary key yet, the legacy `(user_id, uid)` key is dropped and
--      `identity_id` takes its place, reusing the UNIQUE index that 004
--      created so no new index is built. Duplicate `identity_id` values ->
--      WARNING and skip.
--   4. `uid` is dropped.
--
-- The `(user_id, auth_provider)` index below replaces the user_id lookup the
-- legacy primary key used to serve: `uq_user_identities_provider_account`
-- (001) is partial (`WHERE provider_user_id IS NOT NULL`), so it cannot cover
-- `list_for_user`. It is the same index the canonical DDL declares, so it is a
-- no-op on a healthy database.

DO $$
DECLARE
    uid_attnum  smallint;
    pk_oid      oid;
    pk_name     text;
    pk_columns  text;
    dependents  bigint;
BEGIN
    IF to_regclass('auth.user_identities') IS NULL THEN
        RETURN;
    END IF;

    SELECT a.attnum
      INTO uid_attnum
      FROM pg_attribute a
     WHERE a.attrelid = 'auth.user_identities'::regclass
       AND a.attname = 'uid'
       AND NOT a.attisdropped;

    IF uid_attnum IS NULL THEN
        -- Canonical table: there is nothing to drop.
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_attribute a
         WHERE a.attrelid = 'auth.user_identities'::regclass
           AND a.attname = 'identity_id'
           AND NOT a.attisdropped
    ) THEN
        RAISE WARNING
            'auth.user_identities has no identity_id column; run 004 first. '
            'Legacy uid column left in place.';
        RETURN;
    END IF;

    SELECT c.oid,
           c.conname,
           (
               SELECT string_agg(att.attname, ',' ORDER BY k.ord)
                 FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
                 JOIN pg_attribute att
                   ON att.attrelid = c.conrelid
                  AND att.attnum = k.attnum
           )
      INTO pk_oid, pk_name, pk_columns
      FROM pg_constraint c
     WHERE c.conrelid = 'auth.user_identities'::regclass
       AND c.contype = 'p';

    -- Objects that would make a plain DROP COLUMN fail: a view or rule
    -- selecting `uid`, and any constraint over it other than the legacy
    -- primary key this migration drops itself (an incoming foreign key, a
    -- composite CHECK). Column defaults (`pg_attrdef` — 005 created one) and
    -- indexes are dropped by Postgres together with the column, so they are
    -- not blockers. Postgres itself is the final judge: there is no CASCADE
    -- below, and the whole block is one transaction.
    SELECT count(*)
      INTO dependents
      FROM pg_depend d
     WHERE d.refclassid = 'pg_class'::regclass
       AND d.refobjid = 'auth.user_identities'::regclass
       AND d.refobjsubid = uid_attnum
       AND d.deptype <> 'i'
       AND (
           d.classid = 'pg_rewrite'::regclass
           OR (
               d.classid = 'pg_constraint'::regclass
               AND (pk_oid IS NULL OR d.objid <> pk_oid)
           )
       );

    IF dependents > 0 THEN
        RAISE WARNING
            'auth.user_identities.uid has % dependent object(s) besides the '
            'legacy primary key (a view, a rule or a constraint). Dropping it '
            'would need CASCADE, so it is left in place; /api/v1/user_identity '
            'will keep failing on this database until they are removed.',
            dependents;
        RETURN;
    END IF;

    UPDATE auth.user_identities
       SET identity_id = gen_random_uuid()
     WHERE identity_id IS NULL;

    IF EXISTS (
        SELECT 1
          FROM auth.user_identities
         GROUP BY identity_id
        HAVING count(*) > 1
    ) THEN
        RAISE WARNING
            'auth.user_identities has duplicate identity_id values; it cannot '
            'become the primary key. Legacy uid column left in place.';
        RETURN;
    END IF;

    ALTER TABLE auth.user_identities
        ALTER COLUMN identity_id SET NOT NULL;

    IF pk_columns IS DISTINCT FROM 'identity_id' THEN
        IF pk_name IS NOT NULL THEN
            EXECUTE format(
                'ALTER TABLE auth.user_identities DROP CONSTRAINT %I', pk_name
            );
        END IF;

        IF EXISTS (
            SELECT 1
              FROM pg_class i
              JOIN pg_index x ON x.indexrelid = i.oid
             WHERE i.relname = 'uq_user_identities_identity_id'
               AND i.relnamespace = 'auth'::regnamespace
               AND x.indisunique
               AND x.indisvalid
               AND NOT x.indisprimary
        ) THEN
            -- Reuses 004's index instead of building a second one.
            ALTER TABLE auth.user_identities
                ADD CONSTRAINT user_identities_pkey
                PRIMARY KEY USING INDEX uq_user_identities_identity_id;
        ELSE
            ALTER TABLE auth.user_identities
                ADD CONSTRAINT user_identities_pkey PRIMARY KEY (identity_id);
        END IF;
    END IF;

    ALTER TABLE auth.user_identities DROP COLUMN uid;

    RAISE NOTICE
        'auth.user_identities: legacy uid column dropped, identity_id is now '
        'the primary key.';
END $$;

-- Replaces the user_id lookup the legacy (user_id, uid) primary key served;
-- identical to the canonical DDL, so a no-op on a healthy database.
DO $$
BEGIN
    IF to_regclass('auth.user_identities') IS NULL THEN
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_attribute a
         WHERE a.attrelid = 'auth.user_identities'::regclass
           AND a.attname = 'auth_provider'
           AND NOT a.attisdropped
    ) THEN
        CREATE INDEX IF NOT EXISTS idx_user_identities_user
            ON auth.user_identities (user_id, auth_provider);
    ELSE
        CREATE INDEX IF NOT EXISTS idx_user_identities_user
            ON auth.user_identities (user_id);
    END IF;
END $$;
