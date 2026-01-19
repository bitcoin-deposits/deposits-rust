#!/bin/bash
cd "$(dirname "$0")/.."
. ./bin/_common.sh

# Show ledger updates using protobuf API via deposits-admin
# Usage: ./bin/updates.sh [node]
#   No args: show updates for all nodes (alice, bob, charlie)
#   node:    show updates for specific node

ADMIN="cargo_quiet run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin deposits-admin --"

if [ $# -eq 0 ]; then
    # Show updates for all main nodes
    for node in alice bob charlie; do
        echo "=== Updates for $node ==="
        $ADMIN -p "$node" get-updates 2>/dev/null || echo "  (node not available)"
        echo ""
    done
else
    # Show updates for specific node
    $ADMIN -p "$1" get-updates
fi
