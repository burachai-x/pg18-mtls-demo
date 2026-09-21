#!/bin/sh
set -e

# Copy the API's own client cert (CN=apiapp) to a writable location for php-fpm.
# Kept separate from the web portal's /tmp/pg-certs even though /tmp is a shared
# volume — each service connects to PostgreSQL with its own identity.
CERT_SRC="/etc/api-certs"
CERT_DST="/tmp/api-pg-certs"
mkdir -p "$CERT_DST"
cp "$CERT_SRC/ca.crt"     "$CERT_DST/ca.crt"
cp "$CERT_SRC/client.crt" "$CERT_DST/client.crt"
cp "$CERT_SRC/client.key" "$CERT_DST/client.key"
chown www-data:www-data "$CERT_DST"/*
chmod 600 "$CERT_DST/client.key"
chmod 644 "$CERT_DST/ca.crt" "$CERT_DST/client.crt"
export PGSSLMODE=verify-full

# Session dir (PHP session files must not collide with the web portal's)
mkdir -p /tmp/api-sessions
chown www-data:www-data /tmp/api-sessions
chmod 700 /tmp/api-sessions

# Seed the crypto key only if the shared /tmp volume has none yet.
# The web portal's key rotation rewrites /tmp/.crypto_key atomically and this
# service picks the new key up on the next request — never overwrite it here.
if [ -n "$PGCRYPTO_KEY" ] && [ ! -f /tmp/.crypto_key ]; then
    echo "$PGCRYPTO_KEY" > /tmp/.crypto_key
    chmod 600 /tmp/.crypto_key
    chown www-data:www-data /tmp/.crypto_key
    echo "[api-entrypoint] Crypto key seeded from env var."
fi

php-fpm -D

echo "[api-entrypoint] API listening on :443 (TLS, CN=api)"
exec nginx -g 'daemon off;'
