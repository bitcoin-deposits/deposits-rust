#!/bin/bash
# Lightning faucet — pays a BOLT11 invoice using an LDK node with capacity
#
# Automatically picks a node that isn't the invoice recipient and has
# outbound capacity. Falls back to trying each node in order.
#
# Usage:
#   ./bin/ln-faucet.sh <bolt11_invoice>
#   ./bin/ln-faucet.sh --from bob <bolt11_invoice>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NODE=""
INVOICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --from)
            NODE="$2"
            shift 2
            ;;
        *)
            INVOICE="$1"
            shift
            ;;
    esac
done

if [ -z "$INVOICE" ]; then
    echo "Usage: $0 [--from <node>] <bolt11_invoice>"
    echo "  Pays the invoice from an LDK sidecar with outbound capacity."
    echo "  Auto-selects the sender unless --from is specified."
    exit 1
fi

ldk_cli() {
    docker exec "${1}-ln" ldk-server-cli -b localhost:3000 -a test_api_key -t /ldk/tls.crt "${@:2}" 2>/dev/null
}

if [ -n "$NODE" ]; then
    # Explicit sender
    echo "Paying invoice from ${NODE}-ln..."
    result=$(ldk_cli "$NODE" bolt11-send --invoice "$INVOICE" 2>&1)
    echo "$result"
else
    # Try each node until one succeeds
    for try_node in alice bob charlie diana; do
        # Check if this node has outbound capacity
        out=$(ldk_cli "$try_node" list-channels | jq '[.channels[] | select(.is_usable==true) | .outbound_capacity_msat] | add // 0' 2>/dev/null)
        if [ "$out" -le 0 ] 2>/dev/null; then
            continue
        fi

        echo "Trying ${try_node}-ln (${out}msat outbound)..."
        result=$(ldk_cli "$try_node" bolt11-send --invoice "$INVOICE" 2>&1)

        payment_id=$(echo "$result" | jq -r '.payment_id // empty' 2>/dev/null)
        if [ -n "$payment_id" ]; then
            echo "Payment sent from ${try_node}-ln! ID: ${payment_id:0:32}..."
            exit 0
        fi
        echo "  ${try_node}-ln failed: $(echo "$result" | head -1)"
    done
    echo "All nodes failed to pay. Channels may not have enough capacity or routing."
    exit 1
fi
