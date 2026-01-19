#!/bin/bash

cd "$(dirname "$0")"

echo "=== Testing Signed Audit Updates ==="

# Get Alice and Bob's pubkeys
ALICE_PUBKEY=$(curl -s http://localhost:3011/info | jq -r '.data.node_id')
BOB_PUBKEY=$(curl -s http://localhost:3012/info | jq -r '.data.node_id')

echo "Alice pubkey: $ALICE_PUBKEY"
echo "Bob pubkey: $BOB_PUBKEY"

# Initialize ledger between Alice and Bob
echo ""
echo "Step 1: Initialize ledger between Alice and Bob..."
curl -s -X POST http://localhost:3011/bitcoin-deposits/ledger/init \
  -H "Content-Type: application/json" \
  -d "{\"partner_pubkey\": \"$BOB_PUBKEY\"}" | jq '.'

sleep 2

# Check Alice's ledgers
echo ""
echo "Step 2: Check Alice's ledgers..."
curl -s http://localhost:3011/bitcoin-deposits/ledger-updates | jq '.data.ledgers[] | {role, updates: .update_count}'

# Check Diana's audit ledgers
echo ""
echo "Step 3: Check Diana's audit ledgers..."
curl -s http://localhost:3014/bitcoin-deposits/ledger-updates | jq '.data.ledgers[] | {role, operator: .operator_node_id[0:16], partner: .partner_node_id[0:16], updates: .update_count}'

echo ""
echo "Done!"
