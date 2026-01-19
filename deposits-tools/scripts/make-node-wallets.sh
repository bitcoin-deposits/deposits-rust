#!/bin/bash
#
# Create NWC wallets for Lightning nodes
#
# Usage: ./make-node-wallets.sh <network>

cd "$(dirname "$0")"
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

# Get relay URL for network
case "$NETWORK" in
    regtest)   RELAY_URL="ws://localhost:7777" ;;
    mutinynet) RELAY_URL="ws://localhost:7777" ;; #RELAY_URL="wss://relay.damus.io" ;;
    *)
        echo "ERROR: Unknown network '$NETWORK'. Valid networks: regtest, mutinynet"
        exit 1
        ;;
esac

SCRIPT_DIR="$(pwd)"
PROJECT_DIR="$(cd ".." && pwd)"
WORKSPACE_DIR="$(cd "../.." && pwd)"

mkdir -p "$PROJECT_DIR/wallet"

# diana eve frank
for NODE_NAME in alice bob charlie; do
    rm -f "$PROJECT_DIR/wallet/$NODE_NAME.json"
    "$WORKSPACE_DIR/target/release/nwc-client" -r "$RELAY_URL" -w "$PROJECT_DIR/wallet/$NODE_NAME.json" -t $NODE_NAME init-node
done
