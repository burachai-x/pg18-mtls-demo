#!/bin/bash
set -euo pipefail

# Certificates for the Garage TLS sidecar.
#
# Deliberately a SEPARATE certificate authority from certs/generate-certs.sh:
# the object-storage path is its own trust domain, so a compromised database CA
# does not let anyone impersonate the S3 endpoint (and vice versa).
#   - web nginx verifies the sidecar with garage/tls/certs/ca.crt
#   - PostgreSQL mTLS uses the DemoCA from certs/generate-certs.sh

TLS_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$TLS_DIR/work"
CERT_DIR="$TLS_DIR/certs"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$CERT_DIR"
cd "$WORK_DIR"

echo "==> Generating Garage internal CA..."
openssl req -new -x509 -days 3650 -nodes \
  -keyout ca.key \
  -out ca.crt \
  -subj "/CN=GarageInternalCA/O=Demo-Internal/C=TH"

echo "==> Generating Garage TLS sidecar server cert..."
openssl req -new -nodes \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=garage-tls/O=Demo-Internal/C=TH"

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in server.csr \
  -out server.crt \
  -extfile <(printf "subjectAltName=DNS:garage-tls,DNS:localhost\nextendedKeyUsage=serverAuth\n")

cp ca.crt     "$CERT_DIR/ca.crt"
cp server.crt "$CERT_DIR/server.crt"
cp server.key "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
chmod 600 "$CERT_DIR/server.key"

echo "==> Done!"
echo "    Garage CA:     $CERT_DIR/ca.crt            (CN=GarageInternalCA)"
echo "    Sidecar cert:  $CERT_DIR/server.crt        (CN=garage-tls)"

# Never leave the CA private key on disk
rm -rf "$WORK_DIR"
echo "    Cleaned up: $WORK_DIR (CA private key removed)"
