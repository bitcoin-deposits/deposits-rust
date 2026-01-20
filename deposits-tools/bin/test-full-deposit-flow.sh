#!/bin/bash

cd "$(dirname "$0")/.."
. ./bin/_common.sh

ADMIN="cargo_quiet run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin deposits-admin --"

echo "=== Testing Full Deposit Flow with Audit Updates ==="

# Get pubkeys using authenticated HTTPS
ALICE_PUBKEY=$(ldk_curl 3011 GET /node/info | jq -r '.node_id')
BOB_PUBKEY=$(ldk_curl 3012 GET /node/info | jq -r '.node_id')
CHARLIE_PUBKEY=$(ldk_curl 3013 GET /node/info | jq -r '.node_id')

echo "Alice: $ALICE_PUBKEY"
echo "Bob: $BOB_PUBKEY"
echo "Charlie: $CHARLIE_PUBKEY"

echo ""
echo "Initializing ledger between Alice and Charlie..."
$ADMIN -p alice add-ledger charlie || echo "  (ledger may already exist)"

sleep 2

# Check Diana's updates
echo ""
echo "Diana's audit view after initialization:"
$ADMIN -p diana list-ledgers || echo "(no ledgers)"

echo ""
echo "Done!"
