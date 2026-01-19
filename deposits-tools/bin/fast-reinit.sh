#!/bin/bash
#
# Fast reinitialization of the test environment
# Drops all ledgers and recreates wallets without restarting containers
#
# Usage: ./bin/fast-reinit.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1

# 1. Drop all ledgers (clears in-memory + persisted data)
./bin/drop-ledgers.sh

# 2. Reopen channels if they were force-closed
./bin/open-channels.sh

# 3. Recreate ledgers
./bin/make-a-wallet.sh alice charlie bob amber
./bin/make-a-wallet.sh bob charlie alice blue

# 4. Ensure TLS certificates are available
copy_tls_certs alice bob charlie
