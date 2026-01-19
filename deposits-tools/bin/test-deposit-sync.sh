#!/bin/bash

cd "$(dirname "$0")/.."

echo "Creating 5 deposits on Alice-Frank ledger..."

for i in {1..5}; do
    DEPOSIT_KEY=$(printf "02%062x%02x" 0 $i)
    echo "Creating deposit $i with pubkey: $DEPOSIT_KEY"
    curl -s -X POST 'http://localhost:3011/bitcoin-deposits/deposit/request' \
      -H 'Content-Type: application/json' \
      -d "{\"partner_node_id\":\"02f71b9e65db314e17e1ecabefda822e291683c62b70e87b9bea7e3d4e944fee39\",\"deposit_pubkey\":\"$DEPOSIT_KEY\"}"
    echo ""
    sleep 2
done

echo ""
echo "Waiting 5 seconds for message propagation..."
sleep 5

echo ""
echo "=== Alice's view of Alice->Frank ledger ==="
./target/release/status ledgers alice | grep -A 20 "Alice -> Frank"

echo ""
echo "=== Frank's view of Frank<-Alice ledger ==="
./target/release/status ledgers frank | grep -A 20 "Frank -> Alice"
