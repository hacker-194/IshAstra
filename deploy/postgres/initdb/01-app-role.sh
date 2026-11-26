#!/bin/bash
# Create the least-privilege runtime role on first database initialization.
# The owner role (POSTGRES_USER) runs migrations; the app role only gets DML.
set -euo pipefail

: "${ISHASTRA_APP_PASSWORD:?ISHASTRA_APP_PASSWORD is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v app_password="$ISHASTRA_APP_PASSWORD" \
  -v owner="$POSTGRES_USER" \
  -v db_name="$POSTGRES_DB" <<'SQL'
CREATE ROLE ishastra_app
    LOGIN PASSWORD :'app_password'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE :"db_name" TO ishastra_app;
GRANT USAGE ON SCHEMA public TO ishastra_app;

ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ishastra_app;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO ishastra_app;
SQL
