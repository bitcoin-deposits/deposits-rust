#!/bin/bash
#
# Usage: ./test.sh <network>

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

LOGFILE=test-$(date +'%s').log
exec > >(tee -a "$LOGFILE") 2>&1

echo "Testing on network: $NETWORK"

./make-node-wallets.sh "$NETWORK"
./make-a-wallet.sh "$NETWORK" alice charlie bob amber
./make-a-wallet.sh "$NETWORK" bob charlie alice blue
./pay-amber-from-charlie.sh
./pay-blue-from-amber.sh
