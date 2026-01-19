#!/bin/bash
#
# Create NWC wallets for Lightning nodes
#
# Usage: ./bin/make-node-wallets.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1
RELAY_URL=$(get_relay_url "$NETWORK")

mkdir -p wallet

# diana eve frank
for NODE_NAME in alice bob charlie; do
    rm -f "wallet/$NODE_NAME.json"
    ../target/release/nwc-client -r "$RELAY_URL" -w "wallet/$NODE_NAME.json" -t $NODE_NAME init-node
done
