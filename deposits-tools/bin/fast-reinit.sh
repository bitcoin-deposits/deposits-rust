#!/bin/bash
#
# Fast reinitialization of the test environment
# Drops all ledgers and recreates wallets without restarting containers
#
# Usage: ./fast-reinit.sh <network>

cd "$(dirname "$0")/.."
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

# 1. Drop all ledgers (clears in-memory + persisted data)
./bin/drop-ledgers.sh "$NETWORK"

# 2. Reopen channels if they were force-closed
./bin/open-channels.sh "$NETWORK"

# 3. Recreate ledgers
./bin/make-a-wallet.sh "$NETWORK" alice charlie bob amber
./bin/make-a-wallet.sh "$NETWORK" bob charlie alice blue
