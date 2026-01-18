#!/bin/bash
#
# Create NWC wallets for Lightning nodes
#
# Usage: ./make-node-wallets.sh <network>

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

mkdir -p wallet

# diana eve frank
for NODE_NAME in alice bob charlie; do
    rm -f wallet/$NODE_NAME.json
    target/release/nwc-client -r "$RELAY_URL" -w wallet/$NODE_NAME.json -t $NODE_NAME init-node
done
