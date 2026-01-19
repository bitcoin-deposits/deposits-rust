#!/bin/bash
#
# Usage: ./test.sh <network>

cd "$(dirname "$0")/.."
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

LOGFILE="log/test-$(date +'%s').log"
mkdir -p log
exec > >(tee -a "$LOGFILE") 2>&1

echo "Testing on network: $NETWORK"

./bin/make-node-wallets.sh "$NETWORK"
./bin/make-a-wallet.sh "$NETWORK" alice charlie bob amber
./bin/make-a-wallet.sh "$NETWORK" bob charlie alice blue
./bin/pay-amber-from-charlie.sh
./bin/pay-blue-from-amber.sh
