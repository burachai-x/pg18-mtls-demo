#!/bin/bash
set -e

# Copy certs to a writable location and fix ownership/permissions
# PostgreSQL requires server.key to be owned by the postgres user or root
CERT_SRC="/var/lib/postgresql/certs"
CERT_DST="/var/lib/postgresql/certs-runtime"

mkdir -p "$CERT_DST"
cp "$CERT_SRC/ca.crt"      "$CERT_DST/ca.crt"
cp "$CERT_SRC/server.crt"  "$CERT_DST/server.crt"
cp "$CERT_SRC/server.key"  "$CERT_DST/server.key"

chown postgres:postgres "$CERT_DST"/*
chmod 600 "$CERT_DST/server.key"
chmod 644 "$CERT_DST/ca.crt" "$CERT_DST/server.crt"

# Update postgresql.conf to point to the runtime cert paths
export POSTGRES_SSL_CA_FILE="$CERT_DST/ca.crt"
export POSTGRES_SSL_CERT_FILE="$CERT_DST/server.crt"
export POSTGRES_SSL_KEY_FILE="$CERT_DST/server.key"

# Token file cleanup is done synchronously in seed.sql (sleep 60 + rm)
# to avoid background process zombie under runuser.
# Token also has one-time use (used_at) + 10-minute expiry in DB as backup.

# Execute the original entrypoint
exec docker-entrypoint.sh "$@"
