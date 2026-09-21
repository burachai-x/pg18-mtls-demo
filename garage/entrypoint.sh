#!/bin/sh
set -e

# Start garage server in background
/garage -c /etc/garage.toml server &
GARAGE_PID=$!

# Wait for garage to be ready
echo "[garage-entrypoint] Waiting for Garage to start..."
for i in $(seq 1 30); do
    if /garage -c /etc/garage.toml status 2>/dev/null | grep -q "HEALTHY NODES"; then
        echo "[garage-entrypoint] Garage is healthy!"
        break
    fi
    sleep 1
done

# Assign node role and apply layout
NODE_ID=$(/garage -c /etc/garage.toml node id 2>/dev/null | head -1 | cut -d@ -f1)
if [ -n "$NODE_ID" ]; then
    echo "[garage-entrypoint] Assigning role to node ${NODE_ID}..."
    /garage -c /etc/garage.toml layout assign -z dc1 -c 1G "$NODE_ID" 2>/dev/null || true
    /garage -c /etc/garage.toml layout apply --version 1 2>/dev/null || true

    # Create bucket
    echo "[garage-entrypoint] Creating bucket: app-files"
    /garage -c /etc/garage.toml bucket create app-files 2>/dev/null || true

    # Create key
    echo "[garage-entrypoint] Creating S3 key: app-key"
    /garage -c /etc/garage.toml key create app-key 2>/dev/null || true

    # Grant permissions
    echo "[garage-entrypoint] Granting permissions..."
    /garage -c /etc/garage.toml bucket allow --read --write --owner app-files --key app-key 2>/dev/null || true

    echo "[garage-entrypoint] Initialization complete!"
fi

# Wait for garage process
wait $GARAGE_PID
