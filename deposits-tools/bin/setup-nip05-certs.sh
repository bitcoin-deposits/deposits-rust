#!/bin/bash
# Generate self-signed TLS certs for the test NIP-05 server.
# The verifier trusts these via VERIFY_TLS_CERT.
#
# Usage: ./bin/setup-nip05-certs.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERT_DIR"

# Skip if already generated
if [ -f "$CERT_DIR/nip05.crt" ] && [ -f "$CERT_DIR/nip05.key" ]; then
    echo "NIP-05 certs already exist at $CERT_DIR/nip05.{crt,key}"
    exit 0
fi

echo "Generating NIP-05 test certs..."

# Generate CA if it doesn't exist
if [ ! -f "$CERT_DIR/ca.key" ]; then
    openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>/dev/null
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
        -sha256 -days 3650 -out "$CERT_DIR/ca.crt" \
        -subj "/CN=Deposits Test CA" 2>/dev/null
    echo "  Generated test CA"
fi

# Generate cert for nip05 server (valid for the docker hostname and IP)
openssl genrsa -out "$CERT_DIR/nip05.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/nip05.key" \
    -subj "/CN=nip05" \
    -out "$CERT_DIR/nip05.csr" 2>/dev/null

cat > "$CERT_DIR/nip05.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName=@alt_names

[alt_names]
DNS.1 = nip05
DNS.2 = localhost
IP.1 = 172.21.0.50
EOF

openssl x509 -req -in "$CERT_DIR/nip05.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/nip05.crt" -days 3650 -sha256 \
    -extfile "$CERT_DIR/nip05.ext" 2>/dev/null

rm -f "$CERT_DIR/nip05.csr" "$CERT_DIR/nip05.ext" "$CERT_DIR/ca.srl"

echo "  Generated nip05.crt (SAN: nip05, localhost, 172.21.0.50)"
echo "  CA cert: $CERT_DIR/ca.crt (add to verifier with VERIFY_CA_CERT)"
