#!/bin/bash
# CLI wrapper for the 8-node cluster.
#
# Usage:
#   ./cluster-cli.sh node1 ledger list
#   ./cluster-cli.sh node3 info
#   ./cluster-cli.sh node5 deposit ls <ledger_id>
#   ./cluster-cli.sh fund node1 10   # Fund node1 with 10 BTC

set -e

NODE_NAME="$1"
shift || true

if [ -z "$NODE_NAME" ] || [ $# -eq 0 ]; then
    echo "Usage: $0 <node1-node8|fund> <command> [args...]"
    echo ""
    echo "  $0 node1 info                    Show node info"
    echo "  $0 node1 ledger list             List ledgers"
    echo "  $0 node1 ledger open             Open a new ledger"
    echo "  $0 node1 deposit ls <lid>        List deposits"
    echo "  $0 node1 quorum add <lid> <pk> <mlid>  Add quorum member"
    echo "  $0 fund node1 10                 Send 10 BTC to node1"
    exit 1
fi

COMPOSE="docker compose -f $(dirname "$0")/docker-compose.cluster.yml"
NETWORK="regtest"

# Funding helper
if [ "$NODE_NAME" = "fund" ]; then
    TARGET="$1"
    AMOUNT="${2:-10}"
    ADDR=$($COMPOSE exec -T "$TARGET" deposits-node address \
        --seed "$(docker exec "$TARGET" printenv NODE_SEED)" \
        --network "$NETWORK" 2>/dev/null | tail -1)
    echo "Funding $TARGET at $ADDR with $AMOUNT BTC..."
    docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass \
        -rpcwallet=faucet sendtoaddress "$ADDR" "$AMOUNT"
    echo "Done. Mine blocks to confirm."
    exit 0
fi

# Get the node's seed from the running container
SEED=$(docker exec "$NODE_NAME" printenv NODE_SEED 2>/dev/null)
if [ -z "$SEED" ]; then
    echo "ERROR: Could not read seed from $NODE_NAME (is it running?)"
    exit 1
fi

# Build relay list: all 8 nodes + ledger relay
RELAY_ARGS="--relay ws://127.0.0.1:7777"
for i in 1 2 3 4 5 6 7 8; do
    peer="node${i}"
    if [ "$peer" != "$NODE_NAME" ]; then
        RELAY_ARGS="$RELAY_ARGS --relay ws://${peer}:7777"
    fi
done

docker exec -e RUST_LOG=error "$NODE_NAME" deposits-node \
    "$@" \
    --seed "$SEED" \
    --network "$NETWORK" \
    --electrum http://electrs:3000 \
    $RELAY_ARGS \
    --slow-relay ws://ledger-relay:7777 \
    --data-dir /data/node
