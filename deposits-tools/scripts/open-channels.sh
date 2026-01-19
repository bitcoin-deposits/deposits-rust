#!/bin/bash
#
# Open Lightning channels between nodes that need them
# This is useful after dropping ledgers (which may have force-closed channels)
#
# Usage: ./open-channels.sh <network>

cd "$(dirname "$0")"
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

CHANNEL_AMOUNT=5000000  # 5M sats = 0.05 BTC

# Bitcoin RPC configuration (regtest only)
BITCOIN_RPC_HOST="localhost"
BITCOIN_RPC_PORT="18443"
BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASSWORD="pass"

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

# Get node pubkeys
ALICE_PUBKEY=$(curl -s http://localhost:3011/info | jq -r '.data.node_id')
BOB_PUBKEY=$(curl -s http://localhost:3012/info | jq -r '.data.node_id')
CHARLIE_PUBKEY=$(curl -s http://localhost:3013/info | jq -r '.data.node_id')

echo "Node pubkeys:"
echo "  alice:   ${ALICE_PUBKEY:0:16}..."
echo "  bob:     ${BOB_PUBKEY:0:16}..."
echo "  charlie: ${CHARLIE_PUBKEY:0:16}..."
echo ""

CHANNELS_CREATED=0

open_channel() {
    local from_name=$1
    local from_port=$2
    local to_name=$3
    local to_pubkey=$4
    local to_host=$5
    local to_p2p_port=$6

    # Check if channel already exists
    existing=$(curl -s http://localhost:${from_port}/channels | jq -r ".data[] | select(.counterparty_node_id == \"$to_pubkey\") | .channel_id" 2>/dev/null || echo "")

    if [ -n "$existing" ]; then
        echo "  $from_name -> $to_name: channel already exists"
        return 0
    fi

    # Connect peers first
    echo "  $from_name -> $to_name: connecting..."
    curl -s -X POST http://localhost:${from_port}/peers/connect \
        -H "Content-Type: application/json" \
        -d "{\"pubkey\":\"$to_pubkey\",\"host\":\"$to_host\",\"port\":$to_p2p_port}" > /dev/null 2>&1 || true

    sleep 1

    # Open channel with 50/50 balance
    push_msat=$((CHANNEL_AMOUNT * 500))  # 50% in millisats
    echo "  $from_name -> $to_name: opening channel (${CHANNEL_AMOUNT} sats)..."
    response=$(curl -s -X POST http://localhost:${from_port}/channels/open \
        -H "Content-Type: application/json" \
        -d "{\"pubkey\":\"$to_pubkey\",\"amount_sat\":$CHANNEL_AMOUNT,\"push_to_counterparty_msat\":$push_msat,\"announce\":true}")

    success=$(echo "$response" | jq -r '.success')
    if [ "$success" = "true" ]; then
        channel_id=$(echo "$response" | jq -r '.data.channel_id')
        echo "  $from_name -> $to_name: ✅ channel created: ${channel_id:0:16}..."
        CHANNELS_CREATED=$((CHANNELS_CREATED + 1))
    else
        error=$(echo "$response" | jq -r '.error // "unknown error"')
        echo "  $from_name -> $to_name: ❌ failed: $error"
        return 1
    fi
}

# Open channels for full mesh: alice <-> bob, alice <-> charlie, bob <-> charlie
# Using localhost since we're running from host machine
echo "Opening full mesh (3 channels for 3 nodes)..."
open_channel "alice" 3011 "bob" "$BOB_PUBKEY" "localhost" 9736
sleep 2
open_channel "alice" 3011 "charlie" "$CHARLIE_PUBKEY" "localhost" 9737
sleep 2
open_channel "bob" 3012 "charlie" "$CHARLIE_PUBKEY" "localhost" 9737

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
for node in alice:3011 bob:3012 charlie:3013; do
    name=${node%:*}
    port=${node#*:}
    count=$(curl -s http://localhost:${port}/channels | jq -r '.data | length')
    ready=$(curl -s http://localhost:${port}/channels | jq -r '[.data[] | select(.is_channel_ready == true)] | length')
    echo "  $name: $ready/$count channels ready"
done

echo ""
echo "Done. Channels should be ready for use."
