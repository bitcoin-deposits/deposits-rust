#!/bin/bash
# Broadcast ledger updates to Nostr relay
#
# Usage:
#   ./bin/nostr-broadcast.sh [NODE]              # Broadcast NODE's ledgers (default: alice)
#   ./bin/nostr-broadcast.sh [NODE] [LEDGER_ID]  # Broadcast specific ledger

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
NODE=""
LEDGER_ID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Usage: $0 [NODE] [LEDGER_ID]"
            echo ""
            echo "Broadcast ledger updates to Nostr relay."
            echo ""
            echo "Arguments:"
            echo "  NODE       Node to broadcast from: alice, bob, charlie (default: alice)"
            echo "  LEDGER_ID  Specific ledger to broadcast (format: operator:reserves_id)"
            echo ""
            echo "If no LEDGER_ID is given, broadcasts all ledgers from the node."
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            if [ -z "$NODE" ]; then
                NODE=$1
            elif [ -z "$LEDGER_ID" ]; then
                LEDGER_ID=$1
            fi
            shift
            ;;
    esac
done

# Default to alice
NODE=${NODE:-alice}

# Normalize node name
normalize_node() {
    local node=$1
    case "$node" in
        alice|bdk-alice)   echo "bdk-alice" ;;
        bob|bdk-bob)       echo "bdk-bob" ;;
        charlie|bdk-charlie) echo "bdk-charlie" ;;
        diana|bdk-diana)   echo "bdk-diana" ;;
        eve|bdk-eve)       echo "bdk-eve" ;;
        *)                 echo "$node" ;;
    esac
}

CONTAINER=$(normalize_node "$NODE")
DISPLAY_NAME=${CONTAINER#bdk-}

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    log_error "Container $CONTAINER is not running"
    log_info "Start the BDK environment with: ./bin/start.sh"
    exit 1
fi

SEED=$(get_node_seed "$CONTAINER")

log_info "Broadcasting ledger updates from $DISPLAY_NAME to Nostr relay..."
echo ""

# Run nostr export command
if [ -n "$LEDGER_ID" ]; then
    docker exec -e RUST_LOG=error "$CONTAINER" deposits-bdk nostr export "$LEDGER_ID" \
        --seed "$SEED" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://relay-alice:7777 \
        --data-dir /data 2>&1 | filter_logs
else
    docker exec -e RUST_LOG=error "$CONTAINER" deposits-bdk nostr export \
        --seed "$SEED" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://relay-alice:7777 \
        --data-dir /data 2>&1 | filter_logs
fi

echo ""
log_info "View updates with: ./bin/nostr-updates.sh"
