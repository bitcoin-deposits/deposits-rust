#!/bin/bash
# Show ledger updates for nodes (terse format)
#
# Usage:
#   ./bin/updates.sh              # Show updates for all nodes
#   ./bin/updates.sh alice        # Show updates for alice only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
SPECIFIC_NODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Usage: $0 [NODE]"
            echo ""
            echo "Show ledger updates for nodes."
            echo ""
            echo "NODE can be: alice, bob, charlie"
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            SPECIFIC_NODE=$1
            shift
            ;;
    esac
done

# Normalize node name
normalize_node() {
    local node=$1
    case "$node" in
        alice)   echo "alice" ;;
        bob)       echo "bob" ;;
        charlie)   echo "charlie" ;;
        diana)     echo "diana" ;;
        eve)       echo "eve" ;;
        *)                 echo "$node" ;;
    esac
}

# Get nodes to process
if [ -n "$SPECIFIC_NODE" ]; then
    NODES_TO_PROCESS=($(normalize_node "$SPECIFIC_NODE"))
else
    NODES_TO_PROCESS=("alice" "bob" "charlie")
fi

# Show updates for a node
show_updates() {
    local node=$1
    local display_name="$node"

    echo "=== Updates for $display_name ==="

    # Get ledger history and filter out log lines
    local output=$(run_node_cmd "$node" ledger history 2>&1 | filter_logs)

    if echo "$output" | grep -q "Updates for ledger"; then
        echo "$output"
    elif echo "$output" | grep -q "No ledger found"; then
        echo "(no ledger)"
    else
        echo "(not available)"
    fi
}

# Main
for node in "${NODES_TO_PROCESS[@]}"; do
    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
        display_name="$node"
        echo "=== Updates for $display_name ==="
        echo "(not running)"
        continue
    fi

    show_updates "$node"
done
