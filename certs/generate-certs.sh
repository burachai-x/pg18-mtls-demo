#!/bin/bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$CERT_DIR/work"
DB_CERTS="$CERT_DIR/../db/certs"
WEB_CERTS="$CERT_DIR/../web/certs"
API_CERTS="$CERT_DIR/../api/certs"

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

echo "==> Generating PHP client cert (web portal)..."
openssl req -new -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=webapp/O=Demo/C=TH"

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in client.csr \
  -out client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth\n")

echo "==> Generating PHP client cert (API app)..."
# API app has its own DB identity — CN=apiapp, mapped to appuser in db/pg_ident.conf
openssl req -new -nodes \
  -keyout api-client.key \
  -out api-client.csr \
  -subj "/CN=apiapp/O=Demo/C=TH"

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in api-client.csr \
  -out api-client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth\n")

echo "==> Generating API server cert (nginx TLS on the API container)..."
openssl req -new -nodes \
  -keyout api-server.key \
  -out api-server.csr \
  -subj "/CN=api/O=Demo/C=TH"

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in api-server.csr \
  -out api-server.crt \
  -extfile <(printf "subjectAltName=DNS:api,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")

echo "==> Copying certs to db/, web/ and api/..."
mkdir -p "$DB_CERTS" "$WEB_CERTS" "$API_CERTS"

cp ca.crt "$DB_CERTS/ca.crt"
cp server.crt "$DB_CERTS/server.crt"
cp server.key "$DB_CERTS/server.key"
chmod 600 "$DB_CERTS/server.key"

cp ca.crt "$WEB_CERTS/ca.crt"
cp client.crt "$WEB_CERTS/client.crt"
cp client.key "$WEB_CERTS/client.key"
chmod 600 "$WEB_CERTS/client.key"

cp ca.crt "$API_CERTS/ca.crt"
cp api-client.crt "$API_CERTS/client.crt"
cp api-client.key "$API_CERTS/client.key"
cp api-server.crt "$API_CERTS/server.crt"
cp api-server.key "$API_CERTS/server.key"
chmod 600 "$API_CERTS/client.key" "$API_CERTS/server.key"

echo "==> Done!"
echo "    CA:              $DB_CERTS/ca.crt (also in web/certs and api/certs)"
echo "    DB server cert:  $DB_CERTS/server.crt          (CN=db)"
echo "    Web client cert: $WEB_CERTS/client.crt         (CN=webapp)"
echo "    API client cert: $API_CERTS/client.crt         (CN=apiapp)"
echo "    API server cert: $API_CERTS/server.crt         (CN=api)"

# Clean up working directory — never leave CA private key on disk
rm -rf "$WORK_DIR"
echo "    Cleaned up: $WORK_DIR (CA private key removed)"
