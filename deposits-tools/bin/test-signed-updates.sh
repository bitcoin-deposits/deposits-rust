#!/bin/bash

cd "$(dirname "$0")/.."
. ./bin/_common.sh

ADMIN="cargo_quiet run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin deposits-admin --"

echo "=== Testing Signed Audit Updates ==="

# Get Alice and Bob's pubkeys using authenticated HTTPS
ALICE_PUBKEY=$(ldk_curl 3011 GET /node/info | jq -r '.node_id')
BOB_PUBKEY=$(ldk_curl 3012 GET /node/info | jq -r '.node_id')

echo "Alice pubkey: $ALICE_PUBKEY"
echo "Bob pubkey: $BOB_PUBKEY"

# Initialize ledger between Alice and Bob
echo ""
echo "Step 1: Initialize ledger between Alice and Bob..."
$ADMIN -p alice add-ledger bob || echo "  (ledger may already exist)"

sleep 2

# Check Alice's ledgers
echo ""
echo "Step 2: Check Alice's ledgers..."
$ADMIN -p alice list-ledgers

# Check Diana's audit ledgers
echo ""
echo "Step 3: Check Diana's audit ledgers..."
$ADMIN -p diana list-ledgers || echo "(no ledgers)"

echo ""
echo "Done!"
