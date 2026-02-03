#!/bin/bash
# Show ledger updates from Nostr relay
#
# Usage:
#   ./bin/nostr-updates.sh              # List all ledgers, then show updates
#   ./bin/nostr-updates.sh list         # List all ledgers
#   ./bin/nostr-updates.sh events       # Show all events (updates, disputes, agreements)
#   ./bin/nostr-updates.sh <ledger_id>  # Show updates for specific ledger

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
LEDGER_ID=""
LIST_ONLY=false
SHOW_EVENTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Usage: $0 [list|events|LEDGER_ID]"
            echo ""
            echo "Fetch ledger data from Nostr relay."
            echo ""
            echo "Commands:"
            echo "  list              List all ledgers on the relay"
            echo "  events            Show all events (updates, disputes, agreements)"
            echo "  <ledger_id>       Show updates for a specific ledger"
            echo "                    Format: operator_pubkey:reserves_id"
            echo ""
            echo "If no argument is given, lists all ledgers then shows updates for each."
            exit 0
            ;;
        list|ls)
            LIST_ONLY=true
            shift
            ;;
        events|ev)
            SHOW_EVENTS=true
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            LEDGER_ID=$1
            shift
            ;;
    esac
done

# Use one of the BDK nodes to run the nostr commands
# We just need access to a node with the relay configured
CONTAINER="bdk-alice"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    log_error "Container $CONTAINER is not running"
    log_info "Start the BDK environment with: ./bin/start.sh"
    exit 1
fi

# Get a seed (we need one to parse config, but for read-only operations it doesn't matter which)
SEED=$(get_node_seed "$CONTAINER")

run_nostr_cmd() {
    local subcmd=$1
    shift
    docker exec -e RUST_LOG=error "$CONTAINER" deposits-bdk nostr "$subcmd" \
        "$@" \
        --seed "$SEED" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data 2>&1 | filter_logs
}

if [ "$LIST_ONLY" = true ]; then
    # Just list ledgers
    log_info "Listing ledgers from Nostr relay..."
    echo ""
    run_nostr_cmd list
elif [ "$SHOW_EVENTS" = true ]; then
    # Show all events
    log_info "Fetching all events from Nostr relay..."
    echo ""
    run_nostr_cmd events
elif [ -n "$LEDGER_ID" ]; then
    # Show updates for specific ledger
    log_info "Fetching updates for ledger: $LEDGER_ID"
    echo ""
    run_nostr_cmd import "$LEDGER_ID"
else
    # List all ledgers then show updates for each
    log_info "Fetching all ledger updates from Nostr relay..."
    echo ""

    # First list ledgers
    echo "=== Ledgers on Relay ==="
    run_nostr_cmd list

    echo ""
    echo "=== All Updates ==="
    run_nostr_cmd import
fi
