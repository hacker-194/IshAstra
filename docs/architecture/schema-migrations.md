# Schema migrations

IshAstra keeps its schema migrations in the application (`MIGRATIONS` and
`MIGRATIONS_PG`) instead of depending on Alembic. Run `ishastra migrate` with a
DDL-capable role; the long-running API and workers need no schema privileges
and do not execute DDL.

## How the schema is versioned

- `settings('schema_version')` holds the schema version for the active
  database (`store.schema_version()` reads it).
- `ishastra migrate` applies every missing migration up to the current version
  (34) and is idempotent, so a fresh database and an existing one go through the
  same path. Run it once with the database owner, then start the service with a
  non-owner role.
- Row Level Security has its own version marker (`RLS_SCHEMA_VERSION` in
  `core/pg_rls.py`); it is re-applied when the stored marker differs.
- `ishastra backup --verify` reports the schema version and table list of a
  backup file, which is the supported way to check a backup before restoring.

## Upgrading a deployment

1. Take a verified backup (`ishastra backup --out ./backups`).
2. Run `ishastra migrate` with the owner DSN. A failure stops before the new
   version serves rather than half-migrating the database.
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
