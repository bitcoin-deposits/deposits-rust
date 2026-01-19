#!/bin/bash
#
# Usage: ./test.sh <network>

cd "$(dirname "$0")"
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

SCRIPT_DIR="$(pwd)"

LOGFILE="$SCRIPT_DIR/test-$(date +'%s').log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Testing on network: $NETWORK"

"$SCRIPT_DIR/make-node-wallets.sh" "$NETWORK"
"$SCRIPT_DIR/make-a-wallet.sh" "$NETWORK" alice charlie bob amber
"$SCRIPT_DIR/make-a-wallet.sh" "$NETWORK" bob charlie alice blue
"$SCRIPT_DIR/pay-amber-from-charlie.sh"
"$SCRIPT_DIR/pay-blue-from-amber.sh"
