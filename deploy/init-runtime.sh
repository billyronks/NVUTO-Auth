#!/bin/sh
(
set -eu
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=runtime_password="$AUTH_DATABASE_PASSWORD" --set=ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE auth_runtime LOGIN PASSWORD :'runtime_password';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE auth TO auth_runtime;
SQL
)
