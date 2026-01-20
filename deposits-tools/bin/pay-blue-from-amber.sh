#!/bin/bash
# Pay 1000 msat from Amber (on Alice) to Blue's deposit (on Bob)
# Uses ldk-server-cli for protobuf API

cd "$(dirname "$0")/.."
. ./bin/_common.sh

# ldk-server-cli binary and common options
LDK_CLI="cargo run --manifest-path /Users/vinnyfiano/workspace/ldk-server/Cargo.toml --bin ldk-server-cli --"
API_KEY="test_api_key"

echo "Creating invoice on Bob (blue's operator)..."
# Blue's deposit is on Bob's node, so create invoice there
INVOICE=$($LDK_CLI -b localhost:3012 -a "$API_KEY" -t certs/bob.crt bolt11-receive --amount-msat 1000 -d "payment to blue" 2>/dev/null | jq -r '.invoice // empty')

if [ -z "$INVOICE" ] || [ "$INVOICE" = "null" ]; then
    echo "Failed to create invoice"
    $LDK_CLI -b localhost:3012 -a "$API_KEY" -t certs/bob.crt bolt11-receive --amount-msat 1000 -d "payment to blue"
    exit 1
fi

echo "Invoice: ${INVOICE:0:60}..."

echo "Paying invoice from Alice (amber's operator)..."
$LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt bolt11-send --invoice "$INVOICE"

sleep 3
./bin/updates.sh --verbose
