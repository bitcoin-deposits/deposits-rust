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

SEED=$(get_node_seed "$NODE")
DATA_DIR=$(get_node_data_dir "$NODE")

if [ -z "$SEED" ]; then
    log_error "Unknown node: $NODE"
    exit 1
fi

log_info "Broadcasting ledger updates from $NODE to Nostr relay..."
echo ""

# Run nostr export command
if [ -n "$LEDGER_ID" ]; then
    RUST_LOG=error "$DEPOSITS_NODE" nostr export "$LEDGER_ID" \
        --seed "$SEED" \
        --network regtest \
        --esplora "$ELECTRS_URL" \
        --relay "$RELAY_ALICE" \
        --data-dir "$DATA_DIR" 2>&1 | filter_logs
else
    RUST_LOG=error "$DEPOSITS_NODE" nostr export \
        --seed "$SEED" \
        --network regtest \
        --esplora "$ELECTRS_URL" \
        --relay "$RELAY_ALICE" \
        --data-dir "$DATA_DIR" 2>&1 | filter_logs
fi

echo ""
log_info "View updates with: ./bin/nostr-updates.sh"
