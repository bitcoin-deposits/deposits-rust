#!/bin/bash
# Show ledger health for all running operator nodes (or a specific one)
# Usage: health.sh [node] [ledger_id]
#   health.sh                    - all nodes, all ledgers
#   health.sh alice          - Alice's ledgers
#   health.sh alice <id>     - specific ledger on Alice

source "$(dirname "$0")/_common.sh"

NODE_FILTER="${1:-}"
LEDGER_ID="${2:-}"

# Determine which nodes to check
if [ -n "$NODE_FILTER" ]; then
    TARGET_NODES=("$NODE_FILTER")
else
    TARGET_NODES=("${NODES[@]}")
fi

for node in "${TARGET_NODES[@]}"; do
    # Skip nodes that aren't running
    if ! docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
        log_warn "$node not running, skipping"
        echo
        continue
    fi

    echo -e "${BLUE}=== $node ===${NC}"
    if [ -n "$LEDGER_ID" ]; then
        run_bdk_cmd "$node" ledger health "$LEDGER_ID" 2>&1 | filter_logs
    else
        run_bdk_cmd "$node" ledger health 2>&1 | filter_logs
    fi
    echo
done
