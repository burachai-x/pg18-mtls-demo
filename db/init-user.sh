#!/bin/bash
set -euo pipefail

# This script runs after init.sql during first container startup
# (00-init-user.sh runs before 01-init.sql and 02-seed.sql alphabetically)

# Create appuser — use psql variable to prevent SQL injection from config
# Validate POSTGRES_DB to prevent identifier injection (only alphanumeric + underscore)
if ! [[ "$POSTGRES_DB" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    echo "[init-user] FATAL: POSTGRES_DB contains invalid characters — refusing to use as SQL identifier"
    exit 1
fi
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_pass="$APP_USER_PASSWORD" <<-EOSQL
    CREATE USER appuser WITH PASSWORD :'app_pass';
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO appuser;
EOSQL

# Write crypto key as a psql variable file for seed.sql to include
# Key comes from PGCRYPTO_KEY env var (set in .env, passed to db container)
if [ -z "${PGCRYPTO_KEY:-}" ]; then
    echo "[init-user] FATAL: PGCRYPTO_KEY env var is not set — refusing to use default"
    exit 1
fi
CRYPTO_KEY="$PGCRYPTO_KEY"

# Escape single quotes for psql \set (which uses single-quote semantics)
ESCAPED_KEY="${CRYPTO_KEY//\'/\'\'}"
echo "\set crypto_key '${ESCAPED_KEY}'" > /tmp/crypto_key_var.sql
chmod 600 /tmp/crypto_key_var.sql

echo "[init-user] Crypto key written to /tmp/crypto_key_var.sql"
echo "[init-user] Key hash (SHA-256): $(echo -n "$CRYPTO_KEY" | sha256sum | cut -d' ' -f1)"
