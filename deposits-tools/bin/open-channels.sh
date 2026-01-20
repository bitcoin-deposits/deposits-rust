#!/bin/bash
#
# Open Lightning channels between nodes that need them
# This is useful after dropping ledgers (which may have force-closed channels)
#
# Usage: ./bin/open-channels.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1

CHANNEL_AMOUNT=5000000  # 5M sats = 0.05 BTC

# Bitcoin RPC configuration (regtest only)
BITCOIN_RPC_HOST="localhost"
BITCOIN_RPC_PORT="18443"
BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASSWORD="pass"

# Helper to call ldk-cli.sh
ldk_cli() {
    ./bin/ldk-cli.sh "$@"
}

bitcoin_rpc() {
    local wallet="${1:-}"
    local method="$2"
    shift 2
    local params=""
    if [ $# -gt 0 ]; then
        # Build params, keeping numbers as numbers and strings as quoted strings
        local items=""
        for arg in "$@"; do
            if [[ "$arg" =~ ^[0-9]+$ ]]; then
                # Numeric - don't quote
                items="${items}${arg},"
            else
                # String - quote it
                items="${items}\"${arg}\","
            fi
        done
        params="[${items%,}]"
    else
        params="[]"
    fi

    local url="http://$BITCOIN_RPC_HOST:$BITCOIN_RPC_PORT/"
    if [ -n "$wallet" ]; then
        url="${url}wallet/${wallet}"
    fi

    curl -s -u "$BITCOIN_RPC_USER:$BITCOIN_RPC_PASSWORD" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "$url" | jq -r '.result'
}

# Ensure a miner wallet exists
ensure_miner_wallet() {
    # Check if miner wallet exists
    local wallets=$(bitcoin_rpc "" "listwallets")
    if echo "$wallets" | grep -q "miner"; then
        return 0
    fi

    # Try to load it first (in case it exists but isn't loaded)
    bitcoin_rpc "" "loadwallet" "miner" 2>/dev/null || \
    bitcoin_rpc "" "createwallet" "miner" >/dev/null 2>&1 || true
}

echo "Opening Lightning channels..."
echo ""

# Get node pubkeys using ldk-cli
ALICE_PUBKEY=$(ldk_cli alice get-node-info | jq -r '.node_id')
BOB_PUBKEY=$(ldk_cli bob get-node-info | jq -r '.node_id')
CHARLIE_PUBKEY=$(ldk_cli charlie get-node-info | jq -r '.node_id')

echo "Node pubkeys:"
echo "  alice:   ${ALICE_PUBKEY:0:16}..."
echo "  bob:     ${BOB_PUBKEY:0:16}..."
echo "  charlie: ${CHARLIE_PUBKEY:0:16}..."
echo ""

CHANNELS_CREATED=0

open_channel() {
    local from_name=$1
    local to_name=$2
    local to_pubkey=$3
    local to_host=$4
    local to_p2p_port=$5

    # Check if channel already exists
    existing=$(ldk_cli "$from_name" list-channels | jq -r ".channels[] | select(.counterparty_node_id == \"$to_pubkey\") | .channel_id" 2>/dev/null || echo "")

    if [ -n "$existing" ]; then
        echo "  $from_name -> $to_name: channel already exists"
        return 0
    fi

    # Open channel with 50/50 balance (open-channel auto-connects to peer)
    push_msat=$((CHANNEL_AMOUNT * 500))  # 50% in millisats
    echo "  $from_name -> $to_name: opening channel (${CHANNEL_AMOUNT} sats)..."

    # Use ldk-cli to open channel
    response=$(ldk_cli "$from_name" open-channel \
        --node-pubkey "$to_pubkey" \
        --address "${to_host}:${to_p2p_port}" \
        --channel-amount-sats "$CHANNEL_AMOUNT" \
        --push-to-counterparty-msat "$push_msat" \
        --announce-channel 2>&1) || true

    # Check if we got a user_channel_id back (success)
    user_channel_id=$(echo "$response" | jq -r '.user_channel_id // empty' 2>/dev/null || echo "")
    if [ -n "$user_channel_id" ]; then
        echo "  $from_name -> $to_name: channel opening (user_channel_id: ${user_channel_id:0:16}...)"
        CHANNELS_CREATED=$((CHANNELS_CREATED + 1))
    else
        # Check for error message
        error=$(echo "$response" | grep -i "error" || echo "$response")
        echo "  $from_name -> $to_name: failed: $error"
        return 1
    fi
}

# Open channels for full mesh: alice <-> bob, alice <-> charlie, bob <-> charlie
# Using localhost since we're running from host machine
echo "Opening full mesh (3 channels for 3 nodes)..."
open_channel "alice" "bob" "$BOB_PUBKEY" "localhost" 9736
sleep 2
open_channel "alice" "charlie" "$CHARLIE_PUBKEY" "localhost" 9737
sleep 2
open_channel "bob" "charlie" "$CHARLIE_PUBKEY" "localhost" 9737

echo ""
if [ "$CHANNELS_CREATED" -eq 0 ]; then
    echo "No new channels created, skipping confirmation wait."
elif [ "$NETWORK" = "regtest" ]; then
    echo "Mining blocks to confirm $CHANNELS_CREATED new channel(s)..."
    ensure_miner_wallet

    # Mine blocks until mempool is empty (ensures all funding txs are confirmed)
    for i in 1 2 3 4 5; do
        mempool_size=$(curl -s -u "$BITCOIN_RPC_USER:$BITCOIN_RPC_PASSWORD" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"getmempoolinfo","params":[],"id":1}' \
            "http://$BITCOIN_RPC_HOST:$BITCOIN_RPC_PORT/" | jq -r '.result.size')

        if [ "$mempool_size" = "0" ]; then
            echo "  Mempool empty after $i mining rounds"
            break
        fi

        echo "  Mining round $i (mempool: $mempool_size txs)..."
        new_address=$(bitcoin_rpc "miner" "getnewaddress")
        bitcoin_rpc "miner" "generatetoaddress" "6" "$new_address" > /dev/null
        sleep 2
    done

    # Mine a few extra blocks for good measure
    new_address=$(bitcoin_rpc "miner" "getnewaddress")
    bitcoin_rpc "miner" "generatetoaddress" "6" "$new_address" > /dev/null

    echo "Waiting for channel confirmations (30s)..."
    sleep 30
else
    # Mutinynet: wait for natural block confirmations (~30s per block, need 6)
    echo "Waiting for mutinynet block confirmations (6 blocks @ ~30s = ~3 min)..."
    sleep 200
fi

echo ""
echo "Channel status:"
for node in alice bob charlie; do
    channels_json=$(ldk_cli "$node" list-channels 2>/dev/null || echo '{"channels":[]}')
    count=$(echo "$channels_json" | jq -r '.channels | length')
    ready=$(echo "$channels_json" | jq -r '[.channels[] | select(.is_channel_ready == true)] | length')
    echo "  $node: $ready/$count channels ready"
done

echo ""
echo "Done. Channels should be ready for use."
