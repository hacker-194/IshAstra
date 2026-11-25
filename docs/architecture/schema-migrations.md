# Schema migrations

IshAstra documents its schema-migration equivalent rather than depending on
Alembic. This is the deliberate choice for a self-contained deployment: no
migration toolchain to pin, no separate `alembic upgrade` step to forget.

## How the schema is versioned

- `settings('schema_version')` holds the schema version for the active
  database (`store.schema_version()` reads it).
- Schema creation is idempotent (`CREATE TABLE IF NOT EXISTS`) and runs at
  startup, so a fresh database and an existing one go through the same path.
- Row Level Security has its own version marker (`RLS_SCHEMA_VERSION` in
  `core/pg_rls.py`); it is re-applied when the stored marker differs.
- `ishastra backup --verify` reports the schema version and table list of a
  backup file, which is the supported way to check a backup before restoring.

## Upgrading a deployment

1. Take a verified backup (`ishastra backup --out ./backups`).
2. Deploy the new version. Startup applies any missing tables/indexes and RLS
   changes inside the normal startup path; a failure there stops the API from
   serving rather than half-migrating it.
3. Check `ishastra backup --verify` on the live database path and confirm the
   schema version advanced.

## What this does not do

- It does not rewrite or backfill existing rows. Destructive changes require a
  written migration note and a restore from backup if they go wrong.
- It does not diff a schema against the code. The test suite exercises schema
  creation against a fresh database, which is the guard we rely on.

If a future change needs ordered, reversible migrations with data backfills,
Alembic can be introduced then — with a baseline stamped at the current
`schema_version`, so existing deployments are not re-created.
