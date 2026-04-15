#!/bin/bash
# CLI wrapper for deposits-node in Docker containers.
#
# Usage:
#   ./node-cli.sh alice reserves create 1000000
#   ./node-cli.sh bob ledger open --annual-fee-bps 50
#   ./node-cli.sh charlie quorum begin
#   ./node-cli.sh diana info
#   ./node-cli.sh alice address

set -e

NODE_NAME="$1"
shift || true

if [ -z "$NODE_NAME" ] || [ $# -eq 0 ]; then
    echo "Usage: $0 <node-name> <command> [subcommand] [args...]"
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

# Collect the user's command + subcommands + args, then append config flags.
# deposits-node expects: <command> [subcommand] [--flag value ...] [--seed ...]
# We pass everything through and let deposits-node parse it.
LEDGER_RELAY="${DEPOSITS_LEDGER_RELAY:-wss://relay.ynniv.com}"
ALL_NODES="${DEPOSITS_NODES:-alice bob charlie diana}"

# Build relay list: local relay + all other nodes' relays (for cross-node requests)
RELAY_ARGS="--relay ws://127.0.0.1:7777"
for peer in $ALL_NODES; do
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
    --slow-relay "$LEDGER_RELAY" \
    --data-dir /data/node
