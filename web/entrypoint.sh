#!/bin/sh
set -e

# Copy client certs to writable location and fix permissions for www-data
CERT_SRC="/etc/postgresql-certs"
CERT_DST="/tmp/pg-certs"
mkdir -p "$CERT_DST"
cp "$CERT_SRC/ca.crt"      "$CERT_DST/ca.crt"
cp "$CERT_SRC/client.crt"  "$CERT_DST/client.crt"
cp "$CERT_SRC/client.key"  "$CERT_DST/client.key"
chown www-data:www-data "$CERT_DST"/*
chmod 600 "$CERT_DST/client.key"
chmod 644 "$CERT_DST/ca.crt" "$CERT_DST/client.crt"
export PGSSLMODE=verify-full

# Generate self-signed certificate if not exists
if [ ! -f /etc/nginx/ssl/selfsigned.crt ]; then
    echo "[entrypoint] Generating self-signed SSL certificate..."
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/selfsigned.key \
        -out /etc/nginx/ssl/selfsigned.crt \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=Demo/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    echo "[entrypoint] SSL certificate generated."
fi

# Start php-fpm in background
php-fpm -D

# Seed crypto key from env var to runtime file (owned by www-data for PHP-FPM)
if [ -n "$PGCRYPTO_KEY" ] && [ ! -f /tmp/.crypto_key ]; then
    echo "$PGCRYPTO_KEY" > /tmp/.crypto_key
    chmod 600 /tmp/.crypto_key
    chown www-data:www-data /tmp/.crypto_key
    echo "[entrypoint] Crypto key seeded from env var."
fi

# Ensure /run/app-data exists for persistent key backup (webrun volume may be empty)
mkdir -p /run/app-data
chown www-data:www-data /run/app-data

# Wait for Garage to be ready, then init bucket + key
echo "[entrypoint] Waiting for Garage S3..."
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "http://garage:3903/health" 2>/dev/null; then
        echo "[entrypoint] Garage is ready, running init..."
        su-exec www-data php /var/www/html/garage-init.php 2>/dev/null || echo "[entrypoint] Garage init skipped (may already exist)"
        break
    fi
    sleep 2
done

# Start nginx in foreground
exec nginx -g 'daemon off;'
