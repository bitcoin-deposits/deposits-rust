#!/bin/bash
#
# Drop all ledgers on all nodes for quick test environment cycling
#
# Usage: ./bin/drop-ledgers.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1

echo "Dropping all ledgers on $NETWORK..."
echo ""

failed=0

for node in alice:3011 bob:3012 charlie:3013; do
    name=${node%:*}
    port=${node#*:}

    response=$(ldk_curl "$port" POST "/bitcoin-deposits/non-conforming/drop-ledgers")

    # Check if response is empty (endpoint doesn't exist)
    if [ -z "$response" ]; then
        echo "  $name: ERROR - endpoint not found (rebuild with bitcoin-deposits-non-conforming feature)"
        failed=1
        continue
    fi

    # Check if response is valid JSON
    if ! echo "$response" | jq -e . >/dev/null 2>&1; then
        echo "  $name: ERROR - invalid response: $response"
        failed=1
        continue
    fi

    success=$(echo "$response" | jq -r '.success')

    if [ "$success" = "true" ]; then
        dropped=$(echo "$response" | jq -r '.data.dropped_ledgers')
        echo "  $name: dropped $dropped ledgers"
    else
        error=$(echo "$response" | jq -r '.error // "unknown error"')
        echo "  $name: ERROR - $error"
        failed=1
    fi
done

echo ""

if [ $failed -eq 1 ]; then
    echo "FAILED: Some nodes could not drop ledgers."
    echo "Make sure nodes are rebuilt with: cargo build --release --features bitcoin-deposits-non-conforming,testing"
    exit 1
fi

echo "Done. Recreate ledgers with:"
echo "  ./bin/make-a-wallet.sh alice charlie bob amber"
echo "  ./bin/make-a-wallet.sh bob charlie alice blue"
