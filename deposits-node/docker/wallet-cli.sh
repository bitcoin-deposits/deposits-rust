#!/bin/bash
# Lightweight deposits wallet CLI.
#
# A standalone wallet for depositors — not tied to any operator node.
# Uses a local seed file and connects to relays directly.
#
# Usage:
#   ./wallet-cli.sh --wallet /path/to/wallet <command> [args...]
#
# Commands:
#   init                      Generate a new wallet seed
#   pubkey [--index N]        Show deposit pubkey at key index
#   open <ledger_id>          Open a deposit on a ledger
#   deposit-id <ledger_id>    Show deposit ID for our key on a ledger
#
# The wallet directory contains:
#   seed          - 32-byte hex secret
#   deposits.json - tracked deposits (auto-created)
#
# Environment:
#   DEPOSITS_NETWORK       - bitcoin/testnet/regtest (default: bitcoin)
#   DEPOSITS_LEDGER_RELAY  - relay for advertisements + requests (default: wss://relay.ynniv.com)
#   DEPOSITS_RELAYS        - comma-separated operator relays

set -e

WALLET_DIR=""
NETWORK="${DEPOSITS_NETWORK:-bitcoin}"
LEDGER_RELAY="${DEPOSITS_LEDGER_RELAY:-wss://relay.ynniv.com}"
EXTRA_RELAYS="${DEPOSITS_RELAYS:-}"

# Parse global flags
ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --wallet|-w)
            WALLET_DIR="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --relay)
            LEDGER_RELAY="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${ARGS[@]}"

COMMAND="${1:-}"
shift || true

if [ -z "$WALLET_DIR" ]; then
    echo "Usage: $0 --wallet /path/to/wallet <command> [args...]"
    echo ""
    echo "Commands:"
    echo "  init                Generate a new wallet seed"
    echo "  pubkey [--index N]  Show deposit pubkey"
    echo "  open <ledger_id>   Open a deposit"
    exit 1
fi

mkdir -p "$WALLET_DIR"
SEED_FILE="$WALLET_DIR/seed"

case "$COMMAND" in

init)
    if [ -f "$SEED_FILE" ]; then
        echo "Wallet already exists at $WALLET_DIR"
        echo "Seed: $(cat "$SEED_FILE" | head -c 16)..."
    else
        openssl rand -hex 32 > "$SEED_FILE"
        echo "Created wallet at $WALLET_DIR"
        echo "Seed: $(cat "$SEED_FILE" | head -c 16)..."
    fi
    echo ""
    echo "Your deposit pubkey (index 0):"
    # Need deposits-node binary for key derivation — try docker
    CONTAINER=$(docker ps --format '{{.Names}}' | grep -E '^(alice|bob|charlie|diana)' | head -1)
    if [ -n "$CONTAINER" ]; then
        docker exec "$CONTAINER" deposits-node derive-deposit-key \
            --seed "$(cat "$SEED_FILE")" --network "$NETWORK" --index 0 2>&1 | grep pubkey
    else
        echo "(start a node container to derive keys)"
    fi
    ;;

pubkey)
    INDEX=0
    if [ "$1" = "--index" ] && [ -n "$2" ]; then
        INDEX="$2"
    fi
    SEED=$(cat "$SEED_FILE")
    CONTAINER=$(docker ps --format '{{.Names}}' | grep -E '^(alice|bob|charlie|diana)' | head -1)
    if [ -z "$CONTAINER" ]; then
        echo "ERROR: Need a running node container to derive keys"
        exit 1
    fi
    docker exec "$CONTAINER" deposits-node derive-deposit-key \
        --seed "$SEED" --network "$NETWORK" --index "$INDEX" 2>&1 | grep pubkey | awk '{print $2}'
    ;;

open)
    LEDGER_ID="$1"
    INDEX="${2:-0}"

    if [ -z "$LEDGER_ID" ]; then
        echo "Usage: $0 --wallet <dir> open <ledger_id> [key_index]"
        exit 1
    fi

    SEED=$(cat "$SEED_FILE")
    CONTAINER=$(docker ps --format '{{.Names}}' | grep -E '^(alice|bob|charlie|diana)' | head -1)
    if [ -z "$CONTAINER" ]; then
        echo "ERROR: Need a running node container"
        exit 1
    fi

    # Get pubkey
    KEY_OUTPUT=$(docker exec "$CONTAINER" deposits-node derive-deposit-key \
        --seed "$SEED" --network "$NETWORK" --index "$INDEX" 2>&1)
    PUBKEY=$(echo "$KEY_OUTPUT" | grep "^pubkey:" | awk '{print $2}')

    if [ -z "$PUBKEY" ]; then
        echo "ERROR: Failed to derive key"
        echo "$KEY_OUTPUT"
        exit 1
    fi

    echo "Opening deposit..."
    echo "  Ledger: ${LEDGER_ID:0:16}..."
    echo "  Pubkey: $PUBKEY"
    echo "  Index:  $INDEX"
    echo ""

    # Build relay args
    RELAY_ARGS="--relay $LEDGER_RELAY"
    if [ -n "$EXTRA_RELAYS" ]; then
        for r in $(echo "$EXTRA_RELAYS" | tr ',' ' '); do
            RELAY_ARGS="$RELAY_ARGS --relay $r"
        done
    fi

    # Send deposit_open via Nostr
    docker exec "$CONTAINER" deposits-node deposit open \
        "$LEDGER_ID" "$PUBKEY" \
        --seed "$SEED" \
        --network "$NETWORK" \
        --electrum http://electrs:3000 \
        $RELAY_ARGS \
        --data-dir /tmp/wallet-cli 2>&1 | grep -v INFO

    # Track the deposit locally
    python3 -c "
import json, os
path = '$WALLET_DIR/deposits.json'
deps = json.load(open(path)) if os.path.exists(path) else []
deps.append({
    'ledger_id': '$LEDGER_ID',
    'pubkey': '$PUBKEY',
    'key_index': $INDEX,
    'status': 'pending'
})
with open(path, 'w') as f:
    json.dump(deps, f, indent=2)
print('Deposit tracked in $WALLET_DIR/deposits.json')
" 2>/dev/null || true
    ;;

*)
    echo "Unknown command: $COMMAND"
    echo "Commands: init, pubkey, open"
    exit 1
    ;;

esac
