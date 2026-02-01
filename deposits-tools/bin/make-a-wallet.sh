#!/bin/bash

cd "$(dirname "$0")/.."
set -eo pipefail
. ./bin/_common.sh

# Usage: ./bin/make-a-wallet.sh <operator> <partner1> <partner2> <wallet_name>
# Example: ./bin/make-a-wallet.sh alice charlie bob amber
#          ./bin/make-a-wallet.sh bob charlie alice blue

usage() {
    echo "Usage: $0 <operator> <partner1> <partner2> <wallet_name>"
    echo ""
    echo "Sets up a deposit wallet with 100%+100% collateral model."
    echo "Network is read from .network config (set via ./bin/use-network.sh)"
    echo ""
    echo "Arguments:"
    echo "  operator     Node that operates the wallet (alice, bob, charlie, etc.)"
    echo "  partner1     First partner node for ledger"
    echo "  partner2     Second partner node (provides collateral for partner1)"
    echo "  wallet_name  Name for the wallet file (e.g., amber, blue)"
    echo ""
    echo "Examples:"
    echo "  $0 alice charlie bob amber    # Alice operates, Charlie+Bob validate"
    echo "  $0 bob charlie alice blue     # Bob operates, Charlie+Alice validate"
    exit 1
}

# Check arguments
if [ $# -ne 4 ]; then
    usage
fi

NETWORK=$(get_network) || exit 1
validate_network "$NETWORK" || exit 1
RELAY_URL=$(get_relay_url "$NETWORK")

NODE_NAME=$1
PARTNER1_NAME=$2
PARTNER2_NAME=$3
DEPOSIT_NAME=$4

# Use deposits-admin CLI - it handles node alias resolution internally
ADMIN="cargo_quiet run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin deposits-admin --"

echo "Setting up 100%+100% collateral model for $NODE_NAME..."

echo ""
echo "Step 1: Initialize ledger ${NODE_NAME}->${PARTNER1_NAME} ($NODE_NAME operates, $PARTNER1_NAME validates)..."
$ADMIN -p "$NODE_NAME" add-ledger "$PARTNER1_NAME" || {
    # Check if it's an "already exists" error (exit code may vary)
    echo "   (Ledger may already exist - continuing)"
}

echo ""
echo "Step 2: Initialize ledger ${NODE_NAME}->${PARTNER2_NAME} ($NODE_NAME operates, $PARTNER2_NAME validates)..."
echo "   This second operator ledger provides collateral backing for the first."
$ADMIN -p "$NODE_NAME" add-ledger "$PARTNER2_NAME" || {
    echo "   (Ledger may already exist - continuing)"
}

echo ""
echo "Step 2a: Initialize partner-side ledger ${PARTNER1_NAME}->${NODE_NAME} (for validation tracking)..."
$ADMIN -p "$PARTNER1_NAME" add-ledger "$NODE_NAME" || {
    echo "   (Ledger may already exist - continuing)"
}

echo ""
echo "Step 2b: Initialize partner-side ledger ${PARTNER2_NAME}->${NODE_NAME} (for validation tracking)..."
$ADMIN -p "$PARTNER2_NAME" add-ledger "$NODE_NAME" || {
    echo "   (Ledger may already exist - continuing)"
}

echo ""
echo "Waiting for ledger handshakes to complete..."
sleep 3

echo ""
echo "Step 3: Add ${PARTNER2_NAME} as quorum member for ledger ${NODE_NAME}->${PARTNER1_NAME}..."
echo "   ${PARTNER2_NAME}'s reserves in ${NODE_NAME}->${PARTNER2_NAME} back deposits in ${NODE_NAME}->${PARTNER1_NAME}."
$ADMIN -p "$NODE_NAME" add-quorum-member "$PARTNER1_NAME" "$PARTNER2_NAME" || {
    echo "   (Quorum member may already exist - continuing)"
}

echo ""
echo "Step 4: Add ${PARTNER1_NAME} as quorum member for ledger ${NODE_NAME}->${PARTNER2_NAME}..."
echo "   ${PARTNER1_NAME}'s reserves in ${NODE_NAME}->${PARTNER1_NAME} back deposits in ${NODE_NAME}->${PARTNER2_NAME}."
$ADMIN -p "$NODE_NAME" add-quorum-member "$PARTNER2_NAME" "$PARTNER1_NAME" || {
    echo "   (Quorum member may already exist - continuing)"
}

echo ""
echo "Two OPERATOR ledgers initialized for $NODE_NAME with symmetric quorum members."
sleep 1
mkdir -p wallet

# Step 5: Create the deposit wallet using protobuf API
echo ""
echo "Step 5: Creating deposit '$DEPOSIT_NAME' on ledger ${NODE_NAME}->${PARTNER1_NAME} via protobuf API..."

# Generate a deposit keypair using deposits-admin gen-keypair
KEYPAIR=$($ADMIN gen-keypair 2>/dev/null)
DEPOSIT_PRIVATE_KEY=$(echo "$KEYPAIR" | cut -d' ' -f1)
DEPOSIT_PUBKEY=$(echo "$KEYPAIR" | cut -d' ' -f2)

if [ -z "$DEPOSIT_PRIVATE_KEY" ] || [ -z "$DEPOSIT_PUBKEY" ]; then
    echo "   ERROR: Failed to generate keypair"
    exit 1
fi

echo "   Generated deposit keypair"
echo "   Deposit pubkey: ${DEPOSIT_PUBKEY:0:20}..."

# Add the deposit via protobuf API
echo "   Adding deposit to ledger..."
$ADMIN -p "$NODE_NAME" add-deposit "$PARTNER1_NAME" "$DEPOSIT_PUBKEY" || {
    echo "   ERROR: Failed to add deposit"
    exit 1
}

# Get NWC credentials for the deposit
echo "   Getting NWC credentials..."
NWC_CREDS=$($ADMIN -p "$NODE_NAME" deposit-nwc "$DEPOSIT_PUBKEY" 2>/dev/null)
if [ -z "$NWC_CREDS" ] || [ "$NWC_CREDS" = "null" ]; then
    echo "   ERROR: Failed to get NWC credentials"
    exit 1
fi

# Create wallet file with both deposit keypair and NWC credentials
rm -f "wallet/${DEPOSIT_NAME}.json"
echo "$NWC_CREDS" | jq --arg deposit_secret "$DEPOSIT_PRIVATE_KEY" \
    '. + {deposit_secret: $deposit_secret}' > "wallet/${DEPOSIT_NAME}.json"

echo "   ✅ Wallet file created: wallet/${DEPOSIT_NAME}.json"

echo ""
echo "✅ Deposit wallet '$DEPOSIT_NAME' set up successfully!"
echo "   Operator: $NODE_NAME"
echo "   Partner: $PARTNER1_NAME"
echo "   Collateral: $PARTNER2_NAME"
