#!/bin/bash
#
# Set the active network for deposits-tools scripts
#
# Usage: ./bin/use-network.sh <network>
#        ./bin/use-network.sh          # show current network

cd "$(dirname "$0")/.."

CONFIG_FILE=".network"

if [ $# -eq 0 ]; then
    # Show current network
    if [ -f "$CONFIG_FILE" ]; then
        echo "Current network: $(cat "$CONFIG_FILE")"
    else
        echo "No network configured. Run: ./bin/use-network.sh <regtest|mutinynet>"
    fi
    exit 0
fi

NETWORK=$1

case "$NETWORK" in
    regtest|mutinynet)
        echo "$NETWORK" > "$CONFIG_FILE"
        echo "Network set to: $NETWORK"
        ;;
    *)
        echo "ERROR: Unknown network '$NETWORK'"
        echo "Valid networks: regtest, mutinynet"
        exit 1
        ;;
esac
