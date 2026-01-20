#!/bin/bash
# Pay 10000 msat from Charlie to Amber's deposit
# Uses ldk-server-cli deposit-invoice to create an invoice that will credit Amber's deposit

cd "$(dirname "$0")/.."
. ./bin/_common.sh

# ldk-server-cli binary and common options
LDK_CLI="cargo run --manifest-path /Users/vinnyfiano/workspace/ldk-server/Cargo.toml --bin ldk-server-cli --"
API_KEY="test_api_key"

# Get Amber's deposit pubkey from wallet file
AMBER_WALLET="wallet/amber.json"
if [ ! -f "$AMBER_WALLET" ]; then
    echo "ERROR: Amber wallet file not found: $AMBER_WALLET"
    echo "Run make-a-wallet.sh first"
    exit 1
fi
DEPOSIT_PUBKEY=$(jq -r '.deposit_pubkey // empty' "$AMBER_WALLET")
if [ -z "$DEPOSIT_PUBKEY" ]; then
    echo "ERROR: No deposit_pubkey in $AMBER_WALLET"
    exit 1
fi

# Get Charlie's node pubkey (Charlie is the partner for Amber's ledger)
echo "Getting Charlie's node pubkey..."
CHARLIE_PUBKEY=$($LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt get-node-info 2>/dev/null | jq -r '.node_id // empty')
if [ -z "$CHARLIE_PUBKEY" ]; then
    echo "ERROR: Could not get Charlie's node pubkey"
    $LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt get-node-info
    exit 1
fi
echo "Charlie's pubkey: ${CHARLIE_PUBKEY:0:20}..."

echo ""
echo "Creating deposit invoice on Alice (amber's operator)..."
echo "  Partner (validator): Charlie"
echo "  Deposit pubkey: ${DEPOSIT_PUBKEY:0:20}..."

# Create a deposit invoice - this invoice will credit Amber's deposit when paid
RESULT=$($LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt \
    deposit-invoice \
    --partner-node-id "$CHARLIE_PUBKEY" \
    --deposit-pubkey "$DEPOSIT_PUBKEY" \
    --amount-msat 10000 \
    -D "payment to amber" 2>/dev/null)

INVOICE=$(echo "$RESULT" | jq -r '.invoice // empty')
PAYMENT_HASH=$(echo "$RESULT" | jq -r '.payment_hash // empty')

if [ -z "$INVOICE" ] || [ "$INVOICE" = "null" ]; then
    echo "Failed to create deposit invoice"
    # Try again with more verbose output
    $LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt \
        deposit-invoice \
        --partner-node-id "$CHARLIE_PUBKEY" \
        --deposit-pubkey "$DEPOSIT_PUBKEY" \
        --amount-msat 10000 \
        -D "payment to amber"
    exit 1
fi

echo "Invoice: ${INVOICE:0:60}..."
echo "Payment hash: $PAYMENT_HASH"

echo ""
echo "Paying invoice from Charlie..."
$LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt bolt11-send --invoice "$INVOICE"

sleep 3
./bin/updates.sh
