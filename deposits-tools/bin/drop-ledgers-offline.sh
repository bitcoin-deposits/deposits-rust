#!/bin/bash
#
# Drop deposits ledger data directly from SQLite when nodes won't start
# This is useful when kvstore deserialization errors prevent node startup
#
# Usage: ./drop-ledgers-offline.sh [node...]
#   If no nodes specified, drops for alice, bob, charlie on mutinynet
#
# Examples:
#   ./drop-ledgers-offline.sh                    # alice, bob, charlie mutinynet
#   ./drop-ledgers-offline.sh alice bob          # specific nodes on mutinynet
#   NETWORK=regtest ./drop-ledgers-offline.sh    # regtest nodes

cd "$(dirname "$0")/.."
set -e

NETWORK=${NETWORK:-mutiny}

# Default to mutinynet nodes if none specified
if [ $# -eq 0 ]; then
    NODES="alice bob charlie"
else
    NODES="$@"
fi

echo "Dropping deposits data directly from SQLite..."
echo "Network: $NETWORK"
echo "Nodes: $NODES"
echo ""

for node in $NODES; do
    # Determine volume name based on network
    if [ "$NETWORK" = "mutiny" ] || [ "$NETWORK" = "mutinynet" ]; then
        volume="ldk-node_${node}_mutiny_data"
    else
        volume="ldk-node_${node}_data"
    fi

    echo -n "  $node ($volume): "

    # Check if volume exists
    if ! docker volume inspect "$volume" >/dev/null 2>&1; then
        echo "SKIP - volume not found"
        continue
    fi

    # Count and delete deposits entries
    result=$(docker run --rm -v "${volume}:/data" alpine sh -c "
        apk add --quiet sqlite 2>/dev/null

        # Count entries before
        count_before=\$(sqlite3 /data/ldk_node_data.sqlite \"SELECT COUNT(*) FROM ldk_node_data WHERE primary_namespace='deposits'\" 2>/dev/null || echo 0)

        # Delete all deposits entries
        sqlite3 /data/ldk_node_data.sqlite \"DELETE FROM ldk_node_data WHERE primary_namespace='deposits'\" 2>/dev/null

        # Count entries after (should be 0)
        count_after=\$(sqlite3 /data/ldk_node_data.sqlite \"SELECT COUNT(*) FROM ldk_node_data WHERE primary_namespace='deposits'\" 2>/dev/null || echo 0)

        echo \"\$count_before deleted, \$count_after remaining\"
    " 2>/dev/null)

    if [ -n "$result" ]; then
        echo "$result"
    else
        echo "ERROR - could not access database"
    fi
done

echo ""
echo "Done. Restart nodes and recreate ledgers with make-a-wallet.sh"
