#!/bin/bash

cd "$(dirname "$0")"

echo "=== Testing Full Deposit Flow with Audit Updates ==="

# Get pubkeys
ALICE_PUBKEY=$(curl -s http://localhost:3011/info | jq -r '.data.node_id')
BOB_PUBKEY=$(curl -s http://localhost:3012/info | jq -r '.data.node_id')
CHARLIE_PUBKEY=$(curl -s http://localhost:3013/info | jq -r '.data.node_id')

echo "Initializing ledger between Alice and Charlie..."
curl -s -X POST http://localhost:3011/bitcoin-deposits/ledger/init \
  -H "Content-Type: application/json" \
  -d "{\"partner_pubkey\": \"$CHARLIE_PUBKEY\"}" > /dev/null

sleep 2

# Check Diana's updates
echo ""
echo "Diana's audit view after initialization:"
target/release/status ledger-updates diana

echo ""
echo "Done!"
