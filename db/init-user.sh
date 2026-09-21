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
# Roles:
#   appuser        — holds the table privileges, cannot log in
#   webapp, apiapp — login roles, one per service, named after their client
#                    certificate CN (pg_hba uses clientcert=verify-full, which
#                    requires CN == role name) and each with its own password
for var in WEB_DB_PASSWORD API_DB_PASSWORD; do
    if [ -z "${!var:-}" ]; then
        echo "[init-user] FATAL: $var is not set — refusing to create a passwordless login role"
        exit 1
    fi
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v web_pass="$WEB_DB_PASSWORD" -v api_pass="$API_DB_PASSWORD" <<-EOSQL
    CREATE ROLE appuser NOLOGIN;
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO appuser;

    CREATE ROLE webapp LOGIN PASSWORD :'web_pass';
    CREATE ROLE apiapp LOGIN PASSWORD :'api_pass';

    -- both services inherit exactly the privileges granted to appuser in init.sql
    GRANT appuser TO webapp;
    GRANT appuser TO apiapp;
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
