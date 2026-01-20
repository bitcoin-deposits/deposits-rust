#!/bin/bash
# Pay 10000 msat from Charlie to Amber's deposit
# Uses ldk-server-cli for protobuf API

cd "$(dirname "$0")/.."
. ./bin/_common.sh

# ldk-server-cli binary and common options
LDK_CLI="cargo run --manifest-path /Users/vinnyfiano/workspace/ldk-server/Cargo.toml --bin ldk-server-cli --"
API_KEY="test_api_key"

echo "Creating invoice on Alice (amber's operator)..."
# Amber's deposit is on Alice's node, so create invoice there
INVOICE=$($LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt bolt11-receive --amount-msat 10000 -d "payment to amber" 2>/dev/null | jq -r '.invoice // empty')

if [ -z "$INVOICE" ] || [ "$INVOICE" = "null" ]; then
    echo "Failed to create invoice"
    # Try again with more verbose output
    $LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt bolt11-receive --amount-msat 10000 -d "payment to amber"
    exit 1
fi

echo "Invoice: ${INVOICE:0:60}..."

echo "Paying invoice from Charlie..."
$LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt bolt11-send --invoice "$INVOICE"

sleep 3
./bin/updates.sh --verbose
