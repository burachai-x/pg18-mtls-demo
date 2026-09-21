#!/bin/sh
set -e

GARAGE_BIN="garage"
CONFIG="/etc/garage.toml"

echo "[garage-init] Waiting for Garage to be ready..."
sleep 10
for i in $(seq 1 30); do
    if $GARAGE_BIN -c $CONFIG status 2>&1 | grep -q "HEALTHY NODES"; then
        echo "[garage-init] Garage is healthy!"
        break
    fi
    echo "[garage-init] Waiting... ($i/30)"
    sleep 3
done

# Assign node role and apply layout
NODE_ID=$($GARAGE_BIN -c $CONFIG node id 2>/dev/null | head -1 | cut -d@ -f1)
echo "[garage-init] Node ID: ${NODE_ID}"

if [ -n "$NODE_ID" ]; then
    echo "[garage-init] Assigning role to node..."
    $GARAGE_BIN -c $CONFIG layout assign -z dc1 -c 1G "$NODE_ID" 2>/dev/null || true
    $GARAGE_BIN -c $CONFIG layout apply --version 1 2>/dev/null || true

    # Create bucket
    echo "[garage-init] Creating bucket: app-files"
    $GARAGE_BIN -c $CONFIG bucket create app-files >/dev/null 2>&1 || true

    # Create key (suppress output — contains secret key)
    echo "[garage-init] Creating S3 key: app-key"
    $GARAGE_BIN -c $CONFIG key create app-key >/dev/null 2>&1 || true

    # Grant permissions
    echo "[garage-init] Granting permissions..."
    $GARAGE_BIN -c $CONFIG bucket allow --read --write --owner app-files --key app-key >/dev/null 2>&1 || true

    # Extract key info (suppress output — contains secret key)
    KEY_ID=$($GARAGE_BIN -c $CONFIG key info app-key 2>/dev/null | grep "Key ID:" | awk '{print $3}')
    SECRET_KEY=$($GARAGE_BIN -c $CONFIG key info app-key --show-secret 2>/dev/null | grep "Secret key:" | awk '{print $3}')
    echo "[garage-init] Key ID: ${KEY_ID}"
    echo "[garage-init] Secret key: [REDACTED — written to credentials file only]"

    # Write credentials to shared volume for web container to read
    # File is on internal Docker volume — web container's www-data needs read access
    if [ -n "$KEY_ID" ] && [ -n "$SECRET_KEY" ]; then
        echo "s3_key_id=${KEY_ID}" > /var/lib/garage/s3-credentials.env
        echo "s3_secret_key=${SECRET_KEY}" >> /var/lib/garage/s3-credentials.env
        chmod 644 /var/lib/garage/s3-credentials.env
        echo "[garage-init] Credentials written to /var/lib/garage/s3-credentials.env"
    fi
fi

echo "[garage-init] Done!"
