#!/bin/bash
# Pay 1000 msat from Amber (on Alice) to Blue's deposit (on Bob)
# Uses ldk-server-cli deposit-invoice to create an invoice that will credit Blue's deposit

cd "$(dirname "$0")/.."
. ./bin/_common.sh

# ldk-server-cli binary and common options
LDK_CLI="cargo run --manifest-path /Users/vinnyfiano/workspace/ldk-server/Cargo.toml --bin ldk-server-cli --"
API_KEY="test_api_key"

# Get Blue's deposit pubkey from wallet file
BLUE_WALLET="wallet/blue.json"
if [ ! -f "$BLUE_WALLET" ]; then
    echo "ERROR: Blue wallet file not found: $BLUE_WALLET"
    echo "Run make-a-wallet.sh first"
    exit 1
fi
DEPOSIT_PUBKEY=$(jq -r '.deposit_pubkey // empty' "$BLUE_WALLET")
if [ -z "$DEPOSIT_PUBKEY" ]; then
    echo "ERROR: No deposit_pubkey in $BLUE_WALLET"
    exit 1
fi

# Get Charlie's node pubkey (Charlie is the partner for Blue's ledger)
# Blue was created with: bob charlie alice blue
# So Charlie is partner1 (the validator)
echo "Getting Charlie's node pubkey..."
CHARLIE_PUBKEY=$($LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt get-node-info 2>/dev/null | jq -r '.node_id // empty')
if [ -z "$CHARLIE_PUBKEY" ]; then
    echo "ERROR: Could not get Charlie's node pubkey"
    $LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt get-node-info
    exit 1
fi
echo "Charlie's pubkey: ${CHARLIE_PUBKEY:0:20}..."

echo ""
echo "Creating deposit invoice on Bob (blue's operator)..."
echo "  Partner (validator): Charlie"
echo "  Deposit pubkey: ${DEPOSIT_PUBKEY:0:20}..."

# Create a deposit invoice - this invoice will credit Blue's deposit when paid
RESULT=$($LDK_CLI -b localhost:3012 -a "$API_KEY" -t certs/bob.crt \
    deposit-invoice \
    --partner-node-id "$CHARLIE_PUBKEY" \
    --deposit-pubkey "$DEPOSIT_PUBKEY" \
    --amount-msat 1000 \
    -D "payment to blue" 2>/dev/null)

INVOICE=$(echo "$RESULT" | jq -r '.invoice // empty')
PAYMENT_HASH=$(echo "$RESULT" | jq -r '.payment_hash // empty')

if [ -z "$INVOICE" ] || [ "$INVOICE" = "null" ]; then
    echo "Failed to create deposit invoice"
    # Try again with more verbose output
    $LDK_CLI -b localhost:3012 -a "$API_KEY" -t certs/bob.crt \
        deposit-invoice \
        --partner-node-id "$CHARLIE_PUBKEY" \
        --deposit-pubkey "$DEPOSIT_PUBKEY" \
        --amount-msat 1000 \
        -D "payment to blue"
    exit 1
fi

echo "Invoice: ${INVOICE:0:60}..."
echo "Payment hash: $PAYMENT_HASH"

echo ""
echo "Paying invoice from Alice (amber's operator)..."
$LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt bolt11-send --invoice "$INVOICE"

sleep 3
./bin/updates.sh
