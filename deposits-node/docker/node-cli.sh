#!/bin/bash
# CLI wrapper for deposits-node in Docker containers.
#
# Usage:
#   ./node-cli.sh alice reserves create 1000000
#   ./node-cli.sh bob ledger open --annual-fee-bps 50
#   ./node-cli.sh charlie partner add <reserves_id> <member_pubkey> <member_ledger>
#   ./node-cli.sh diana info

set -e

NODE_NAME="$1"
shift

if [ -z "$NODE_NAME" ]; then
    echo "Usage: $0 <node-name> <command> [args...]"
    echo "  Nodes: alice, bob, charlie, diana"
    exit 1
fi

SEED_DIR="${DEPOSITS_SEED_DIR:-/mnt/bitcoind/deposits}"
NETWORK="${DEPOSITS_NETWORK:-bitcoin}"

SEED=$(cat "$SEED_DIR/$NODE_NAME/seed" 2>/dev/null)
if [ -z "$SEED" ]; then
    echo "ERROR: Could not read seed from $SEED_DIR/$NODE_NAME/seed"
    exit 1
fi

docker exec "$NODE_NAME" deposits-node \
    --seed "$SEED" \
    --network "$NETWORK" \
    --electrum http://electrs:3000 \
    --relay ws://127.0.0.1:7777 \
    --data-dir /data/node \
    "$@"
