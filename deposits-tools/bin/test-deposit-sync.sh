#!/bin/bash

cd "$(dirname "$0")/.."
. ./bin/_common.sh

ADMIN="cargo_quiet run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin deposits-admin --"

echo "Creating 5 deposits on Alice-Frank ledger..."

for i in {1..5}; do
    DEPOSIT_KEY=$(printf "02%062x%02x" 0 $i)
    echo "Creating deposit $i with pubkey: $DEPOSIT_KEY"
    $ADMIN -p alice add-deposit frank "$DEPOSIT_KEY" || echo "  (deposit may already exist)"
    echo ""
    sleep 2
done

echo ""
echo "Waiting 5 seconds for message propagation..."
sleep 5

echo ""
echo "=== Alice's view of Alice->Frank ledger ==="
$ADMIN -p alice list-ledgers | grep -A 20 "frank" || echo "(no frank ledger)"

echo ""
echo "=== Frank's view of Frank<-Alice ledger ==="
$ADMIN -p frank list-ledgers | grep -A 20 "alice" || echo "(no alice ledger)"
