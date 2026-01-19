#!/bin/bash

cd "$(dirname "$0")/.."
set -eo pipefail

# Usage: ./bin/make-a-wallet.sh <network> <operator> <partner1> <partner2> <wallet_name>
# Example: ./make-a-wallet.sh regtest alice charlie bob amber
#          ./make-a-wallet.sh mutinynet bob charlie alice blue

usage() {
    echo "Usage: $0 <network> <operator> <partner1> <partner2> <wallet_name>"
    echo ""
    echo "Sets up a deposit wallet with 100%+100% collateral model."
    echo ""
    echo "Arguments:"
    echo "  network      Network type: regtest or mutinynet"
    echo "  operator     Node that operates the wallet (alice, bob, charlie, etc.)"
    echo "  partner1     First partner node for ledger"
    echo "  partner2     Second partner node (provides collateral for partner1)"
    echo "  wallet_name  Name for the wallet file (e.g., amber, blue)"
    echo ""
    echo "Examples:"
    echo "  $0 regtest alice charlie bob amber    # Alice operates, Charlie+Bob validate"
    echo "  $0 mutinynet bob charlie alice blue   # Bob operates, Charlie+Alice validate"
    exit 1
}

# Get relay URL for network
get_relay_url() {
    local network=$1
    case "$network" in
        regtest)   echo "ws://localhost:7777" ;;
        mutinynet) echo "ws://localhost:7777" ;;
        *)
            echo "ERROR: Unknown network '$network'. Valid networks: regtest, mutinynet" >&2
            exit 1
            ;;
    esac
}

# Check arguments
if [ $# -ne 5 ]; then
    usage
fi

NETWORK=$1
NODE_NAME=$2
PARTNER1_NAME=$3
PARTNER2_NAME=$4
DEPOSIT_NAME=$5

# Get relay URL for network
RELAY_URL=$(get_relay_url "$NETWORK")

# Use deposits-admin CLI - it handles node alias resolution internally
ADMIN="cargo run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin deposits-admin --"

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
echo "Waiting for ledger handshakes to complete..."
sleep 3

echo ""
echo "Step 3: Add ${PARTNER2_NAME} as collateral partner for ledger ${NODE_NAME}->${PARTNER1_NAME}..."
echo "   ${PARTNER2_NAME}'s reserves in ${NODE_NAME}->${PARTNER2_NAME} back deposits in ${NODE_NAME}->${PARTNER1_NAME}."
$ADMIN -p "$NODE_NAME" add-collateral-partner "$PARTNER1_NAME" "$PARTNER2_NAME" || {
    echo "   (Collateral partner may already exist - continuing)"
}

echo ""
echo "Step 4: Add ${PARTNER1_NAME} as collateral partner for ledger ${NODE_NAME}->${PARTNER2_NAME}..."
echo "   ${PARTNER1_NAME}'s reserves in ${NODE_NAME}->${PARTNER1_NAME} back deposits in ${NODE_NAME}->${PARTNER2_NAME}."
$ADMIN -p "$NODE_NAME" add-collateral-partner "$PARTNER2_NAME" "$PARTNER1_NAME" || {
    echo "   (Collateral partner may already exist - continuing)"
}

echo ""
echo "Two OPERATOR ledgers initialized for $NODE_NAME with symmetric collateral partners."
sleep 1
mkdir -p wallet

# Check if wallet already exists with a deposit_pubkey
if [ -f "wallet/$DEPOSIT_NAME.json" ]; then
    EXISTING_PUBKEY=$(jq -r '.deposit_pubkey // empty' "wallet/$DEPOSIT_NAME.json" 2>/dev/null)
    if [ -n "$EXISTING_PUBKEY" ]; then
        echo "INFO: Wallet $DEPOSIT_NAME already exists with deposit pubkey $EXISTING_PUBKEY"
        echo "      Skipping deposit creation to avoid orphaned deposits on ledger."
        exit 0
    fi
fi

# Create deposit wallet - the system will auto-select an available channel
echo "Creating deposit wallet on ${NODE_NAME} (auto-selecting channel)..."
if ! cargo run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin nwc-client -- -w "wallet/$DEPOSIT_NAME.json" -t "$NODE_NAME" -r "$RELAY_URL" init-deposit; then
    echo "ERROR: Failed to create deposit wallet for $DEPOSIT_NAME"
    exit 1
fi

echo "Wallet $DEPOSIT_NAME created successfully"
