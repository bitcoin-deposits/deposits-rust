#!/bin/bash

set -eo pipefail

# Usage: ./make-a-wallet.sh <network> <operator> <partner1> <partner2> <wallet_name>
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

# Map node name to port index
get_port_index() {
    local name=$1
    case "$name" in
        alice)   echo "1" ;;
        bob)     echo "2" ;;
        charlie) echo "3" ;;
        diana)   echo "4" ;;
        eve)     echo "5" ;;
        frank)   echo "6" ;;
        grace)   echo "7" ;;
        *)
            echo "ERROR: Unknown node '$name'. Valid nodes: alice, bob, charlie, diana, eve, frank, grace" >&2
            exit 1
            ;;
    esac
}

# Helper function for API calls with error checking
api_call() {
    local method=$1
    local url=$2
    local data="${3:-}"
    local description="${4:-API call}"

    local response
    if [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H 'Content-Type: application/json' \
            -d "$data")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url")
    fi

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    # 409 Conflict means "already exists" - treat as idempotent success
    if [ "$http_code" -eq 409 ]; then
        echo "INFO: $description - already exists (OK)" >&2
        # Return a success response for callers that parse the result
        echo '{"success":true,"data":{"message":"already exists"},"error":null}'
        return 0
    fi

    # Check HTTP status code
    if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
        echo "ERROR: $description failed with HTTP $http_code" >&2
        echo "Response: $body" >&2
        exit 1
    fi

    # Check if response is valid JSON
    if ! echo "$body" | jq -e . >/dev/null 2>&1; then
        echo "ERROR: $description returned invalid JSON" >&2
        echo "Response: $body" >&2
        exit 1
    fi

    # Check for API-level error
    local success=$(echo "$body" | jq -r '.success')
    if [ "$success" = "false" ]; then
        local error=$(echo "$body" | jq -r '.error // "unknown error"')
        echo "ERROR: $description failed: $error" >&2
        exit 1
    fi

    echo "$body"
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

# Get port indices
NODE_INDEX=$(get_port_index "$NODE_NAME")
PARTNER1_INDEX=$(get_port_index "$PARTNER1_NAME")
PARTNER2_INDEX=$(get_port_index "$PARTNER2_NAME")

capitalize() {
    echo "$1"
}

NODE_DISPLAY=$(capitalize "$NODE_NAME")
PARTNER1_DISPLAY=$(capitalize "$PARTNER1_NAME")
PARTNER2_DISPLAY=$(capitalize "$PARTNER2_NAME")

echo "Fetching node IDs..."
NODE_ID=$(api_call GET "http://localhost:301${NODE_INDEX}/info" "" "get $NODE_NAME info" | jq -r '.data.node_id')
PARTNER1_ID=$(api_call GET "http://localhost:301${PARTNER1_INDEX}/info" "" "get $PARTNER1_NAME info" | jq -r '.data.node_id')
PARTNER2_ID=$(api_call GET "http://localhost:301${PARTNER2_INDEX}/info" "" "get $PARTNER2_NAME info" | jq -r '.data.node_id')

if [ -z "$NODE_ID" ] || [ "$NODE_ID" = "null" ]; then
    echo "ERROR: Failed to get node ID for $NODE_NAME"
    exit 1
fi
if [ -z "$PARTNER1_ID" ] || [ "$PARTNER1_ID" = "null" ]; then
    echo "ERROR: Failed to get node ID for $PARTNER1_NAME"
    exit 1
fi
if [ -z "$PARTNER2_ID" ] || [ "$PARTNER2_ID" = "null" ]; then
    echo "ERROR: Failed to get node ID for $PARTNER2_NAME"
    exit 1
fi

echo "Setting up 100%+100% collateral model for $NODE_DISPLAY..."
echo "   $NODE_DISPLAY: $NODE_ID"
echo "   $PARTNER1_DISPLAY: $PARTNER1_ID"
echo "   $PARTNER2_DISPLAY: $PARTNER2_ID"

echo ""
echo "Step 1: Initialize ledger ${NODE_DISPLAY}->${PARTNER1_DISPLAY} ($NODE_DISPLAY operates, $PARTNER1_DISPLAY validates)..."
result=$(api_call POST "http://localhost:301${NODE_INDEX}/bitcoin-deposits/ledger/init" \
    "{\"partner_pubkey\":\"$PARTNER1_ID\"}" \
    "init ledger $NODE_NAME->$PARTNER1_NAME")
echo "$result" | jq .

echo ""
echo "Step 2: Initialize ledger ${NODE_DISPLAY}->${PARTNER2_DISPLAY} ($NODE_DISPLAY operates, $PARTNER2_DISPLAY validates)..."
echo "   This second operator ledger provides collateral backing for the first."
result=$(api_call POST "http://localhost:301${NODE_INDEX}/bitcoin-deposits/ledger/init" \
    "{\"partner_pubkey\":\"$PARTNER2_ID\"}" \
    "init ledger $NODE_NAME->$PARTNER2_NAME")
echo "$result" | jq .

echo ""
echo "Waiting for ledger handshakes to complete..."
sleep 3

echo ""
echo "Step 3: Add ${PARTNER2_DISPLAY} as collateral partner for ledger ${NODE_DISPLAY}->${PARTNER1_DISPLAY}..."
echo "   ${PARTNER2_DISPLAY}'s reserves in ${NODE_DISPLAY}->${PARTNER2_DISPLAY} back deposits in ${NODE_DISPLAY}->${PARTNER1_DISPLAY}."
result=$(api_call POST "http://localhost:301${NODE_INDEX}/bitcoin-deposits/collateral-partner/add" \
    "{\"partner_node_id\":\"$PARTNER1_ID\", \"collateral_partner\":\"$PARTNER2_ID\"}" \
    "add collateral partner $PARTNER2_NAME for $NODE_NAME->$PARTNER1_NAME")
echo "$result" | jq .

echo ""
echo "Step 4: Add ${PARTNER1_DISPLAY} as collateral partner for ledger ${NODE_DISPLAY}->${PARTNER2_DISPLAY}..."
echo "   ${PARTNER1_DISPLAY}'s reserves in ${NODE_DISPLAY}->${PARTNER1_DISPLAY} back deposits in ${NODE_DISPLAY}->${PARTNER2_DISPLAY}."
result=$(api_call POST "http://localhost:301${NODE_INDEX}/bitcoin-deposits/collateral-partner/add" \
    "{\"partner_node_id\":\"$PARTNER2_ID\", \"collateral_partner\":\"$PARTNER1_ID\"}" \
    "add collateral partner $PARTNER1_NAME for $NODE_NAME->$PARTNER2_NAME")
echo "$result" | jq .

echo ""
echo "Two OPERATOR ledgers initialized for $NODE_DISPLAY with symmetric collateral partners."
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

# Get channel_id for partner1 ledger to ensure deterministic deposit placement
# Deposits should always go on the partner1 ledger (the primary validation partner)
echo "Finding channel_id for ${NODE_DISPLAY}->${PARTNER1_DISPLAY} ledger..."
CHANNEL_ID=$(curl -s "http://localhost:301${NODE_INDEX}/bitcoin-deposits/ledgers" | \
    jq -r ".data.ledgers[] | select(.partner_node_id == \"$PARTNER1_ID\" and .operator_node_id == \"$(curl -s http://localhost:301${NODE_INDEX}/info | jq -r '.data.node_id')\") | .channel_id" | head -1)

if [ -z "$CHANNEL_ID" ] || [ "$CHANNEL_ID" = "null" ]; then
    echo "ERROR: Could not find channel_id for ${NODE_DISPLAY}->${PARTNER1_DISPLAY} ledger"
    exit 1
fi
echo "   Channel ID: $CHANNEL_ID"

echo "Creating deposit wallet on ${NODE_DISPLAY}->${PARTNER1_DISPLAY} ledger..."
if ! cargo run --bin nwc-client -- -w "wallet/$DEPOSIT_NAME.json" -t "$NODE_NAME" -r "$RELAY_URL" init-deposit "$CHANNEL_ID"; then
    echo "ERROR: Failed to create deposit wallet for $DEPOSIT_NAME"
    exit 1
fi

echo "Wallet $DEPOSIT_NAME created successfully"
