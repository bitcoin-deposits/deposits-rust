#!/bin/bash
#
# Usage: ./bin/test.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1

mkdir -p log
LOGFILE="log/test-$(date +'%s').log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Testing on network: $NETWORK"

./bin/make-a-wallet.sh alice charlie bob amber
./bin/make-a-wallet.sh bob charlie alice blue
./bin/pay-amber-from-charlie.sh
./bin/pay-blue-from-amber.sh
