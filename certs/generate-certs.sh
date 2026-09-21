#!/bin/bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$CERT_DIR/work"
DB_CERTS="$CERT_DIR/../db/certs"
WEB_CERTS="$CERT_DIR/../web/certs"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

cd "$WORK_DIR"

echo "==> Generating CA..."
openssl req -new -x509 -days 3650 -nodes \
  -keyout ca.key \
  -out ca.crt \
  -subj "/CN=DemoCA/O=Demo/C=TH"

echo "==> Generating PostgreSQL server cert..."
openssl req -new -nodes \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=db/O=Demo/C=TH"

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in server.csr \
  -out server.crt \
  -extfile <(printf "subjectAltName=DNS:db,DNS:localhost\nextendedKeyUsage=serverAuth\n")

echo "==> Generating PHP client cert..."
openssl req -new -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=webapp/O=Demo/C=TH"

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in client.csr \
  -out client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth\n")

echo "==> Copying certs to db/ and web/..."
mkdir -p "$DB_CERTS" "$WEB_CERTS"

cp ca.crt "$DB_CERTS/ca.crt"
cp server.crt "$DB_CERTS/server.crt"
cp server.key "$DB_CERTS/server.key"
chmod 600 "$DB_CERTS/server.key"

cp ca.crt "$WEB_CERTS/ca.crt"
cp client.crt "$WEB_CERTS/client.crt"
cp client.key "$WEB_CERTS/client.key"
chmod 600 "$WEB_CERTS/client.key"

echo "==> Done!"
echo "    CA:         $DB_CERTS/ca.crt (also in web/certs)"
echo "    Server cert: $DB_CERTS/server.crt"
echo "    Client cert: $WEB_CERTS/client.crt"

# Clean up working directory — never leave CA private key on disk
rm -rf "$WORK_DIR"
echo "    Cleaned up: $WORK_DIR (CA private key removed)"
