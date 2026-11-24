# Backup and recovery

The goal is a verified backup you can restore, not a copy you hope works.

## Take a backup

```bash
ishastra backup --out ./backups            # sqlite (ISHASTRA_DB)
ishastra backup --db "$ISHASTRA_DATABASE_URL" --out ./backups   # PostgreSQL
```

Each backup is written and then verified in place: the schema version, table
list and audit-chain entry count are read back from the file. A backup that
fails verification exits non-zero and must not be shipped anywhere.

## Verify later

```bash
ishastra backup --verify ./backups/ishastra-2026-11-24.db
```

Run this on the copy that actually arrived at the backup host, not only on the
one you produced.

## Restore

- SQLite: stop the API and workers, replace the database file with the verified
  backup, start again. Startup re-checks the audit chain.
- PostgreSQL: use the restore runbook in `docs/runbooks/restore.md` (`pg_restore`
  into a fresh database, then start the API and workers).

Point-in-time recovery for PostgreSQL is covered by `ishastra dr pitr` (base
backup plus WAL replay) and described in the same runbook.

## Warm standby

```bash
ishastra standby-promote \
  --backup-dir ./backups \
  --db-path "$ISHASTRA_DATABASE_URL" \
  --scope-file scope.json

ishastra standby-promote --backup-dir ./backups --db-path ./ishastra.db --dry-run
```

Promotion verifies the newest backup, restores it, takes the worker lease and
runs readiness checks (scope, API keys, audit chain) before reporting an RTO.
`--dry-run` performs only the backup verification.

## Targets

- RPO: the interval between backups; a verified backup is the only accepted
  unit of recovery.
- RTO: measured by `standby-promote`, which prints per-step timings in ms.
- Keep the audit-chain HMAC key with the backup, or the restored chain cannot
  be verified — but store it separately from the backup itself.
