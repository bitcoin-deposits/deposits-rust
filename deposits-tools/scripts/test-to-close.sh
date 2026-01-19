#!/bin/bash
#
# Usage: ./test-to-close.sh <network>
#
# Full test cycle with complete teardown:
# 1. Create wallets (deposits on ledgers)
# 2. Run payments between wallets
# 3. Pay out balances (drain deposits)
# 4. Remove deposits
# 5. Reduce reserves to 0
# 6. Remove reserves outputs
# 7. Close ledgers

cd "$(dirname "$0")"
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1
NWC="./target/release/nwc-client"
ADMIN="./target/release/deposits-admin"

LOGFILE=test-to-close-$(date +'%s').log
exec > >(tee -a "$LOGFILE") 2>&1

echo "=========================================="
echo "Testing on network: $NETWORK"
echo "=========================================="

# Get node IDs
ALICE_ID=$(curl -s http://localhost:3011/info | jq -r '.data.node_id')
BOB_ID=$(curl -s http://localhost:3012/info | jq -r '.data.node_id')
CHARLIE_ID=$(curl -s http://localhost:3013/info | jq -r '.data.node_id')

echo "Alice:   $ALICE_ID"
echo "Bob:     $BOB_ID"
echo "Charlie: $CHARLIE_ID"
echo ""

# ============================================
# PHASE 1: Setup wallets and fund them
# ============================================
echo "=== PHASE 1: Creating wallets ==="

./make-node-wallets.sh "$NETWORK"
./make-a-wallet.sh "$NETWORK" alice charlie bob amber
./make-a-wallet.sh "$NETWORK" bob charlie alice blue

# ============================================
# PHASE 2: Run payments between wallets
# ============================================
echo ""
echo "=== PHASE 2: Running payments ==="

./pay-amber-from-charlie.sh
./pay-blue-from-amber.sh

# Show balances after payments (NWC returns balance in msat)
echo ""
echo "Balances after payments:"
AMBER_BALANCE=$($NWC -w wallet/amber.json balance 2>/dev/null | jq -r '.result.balance // 0')
BLUE_BALANCE=$($NWC -w wallet/blue.json balance 2>/dev/null | jq -r '.result.balance // 0')
echo "  amber: $AMBER_BALANCE msat"
echo "  blue:  $BLUE_BALANCE msat"

# Show ledger status
echo ""
echo "Ledger status after payments:"
./updates.sh

# ============================================
# PHASE 3: Drain deposits (pay out balances)
# ============================================
echo ""
echo "=== PHASE 3: Draining deposits ==="

# Create invoices on charlie for the exact amounts, then pay from wallets
# NOTE: NWC balance returns msats, not sats
if [ "$AMBER_BALANCE" -gt 0 ]; then
    echo "Draining amber ($AMBER_BALANCE msat) to charlie..."
    AMBER_INVOICE=$(curl -s -X POST http://localhost:3013/invoice -H "Content-Type: application/json" -d "{\"amount_msat\": $AMBER_BALANCE, \"description\": \"drain amber\"}" | jq -r '.data.bolt11_invoice')
    $NWC -w wallet/amber.json pay-invoice "$AMBER_INVOICE" 2>/dev/null || echo "amber payment failed"
    sleep 2
fi

if [ "$BLUE_BALANCE" -gt 0 ]; then
    echo "Draining blue ($BLUE_BALANCE msat) to charlie..."
    BLUE_INVOICE=$(curl -s -X POST http://localhost:3013/invoice -H "Content-Type: application/json" -d "{\"amount_msat\": $BLUE_BALANCE, \"description\": \"drain blue\"}" | jq -r '.data.bolt11_invoice')
    $NWC -w wallet/blue.json pay-invoice "$BLUE_INVOICE" 2>/dev/null || echo "blue payment failed"
    sleep 2
fi

# Verify balances are zero
echo ""
echo "Balances after drain:"
AMBER_BALANCE=$($NWC -w wallet/amber.json balance 2>/dev/null | jq -r '.result.balance // 0')
BLUE_BALANCE=$($NWC -w wallet/blue.json balance 2>/dev/null | jq -r '.result.balance // 0')
echo "  amber: $AMBER_BALANCE msat"
echo "  blue:  $BLUE_BALANCE msat"

# ============================================
# PHASE 4: Remove deposits
# ============================================
echo ""
echo "=== PHASE 4: Removing deposits ==="

# Generic retry function for operations that may timeout due to Charlie handling one request at a time
# Usage: run_with_retry <target> "<description>" <command> [args...]
run_with_retry() {
    local target=$1
    local description=$2
    shift 2
    local max_retries=3

    for i in $(seq 1 $max_retries); do
        echo "$description - attempt $i/$max_retries..."
        if TARGET=$target "$@" 2>&1; then
            return 0
        fi
        if [ $i -lt $max_retries ]; then
            echo "Attempt $i failed, waiting before retry..."
            sleep 5
        fi
    done
    echo "Failed: $description after $max_retries attempts"
    return 1
}

# Get deposit pubkeys from wallet files
AMBER_PUBKEY=$(jq -r '.deposit_pubkey' wallet/amber.json)
BLUE_PUBKEY=$(jq -r '.deposit_pubkey' wallet/blue.json)

# Deposits go on the PARTNER1 ledger (the first ledger initialized by make-a-wallet.sh):
#   - make-a-wallet alice charlie bob amber -> deposit on alice->charlie
#   - make-a-wallet bob charlie alice blue -> deposit on bob->charlie
run_with_retry alice "Removing amber deposit from alice->charlie" $ADMIN remove-deposit charlie "$AMBER_PUBKEY"
sleep 2

run_with_retry bob "Removing blue deposit from bob->charlie" $ADMIN remove-deposit charlie "$BLUE_PUBKEY"
sleep 2
echo ""
echo "Ledger status after deposit removal:"
./updates.sh

# ============================================
# PHASE 5: Reduce reserves to 0
# ============================================
echo ""
echo "=== PHASE 5: Reducing reserves ==="

# Get current reserves for the specific ledgers (alice->charlie, bob->charlie)
# Filter by partner_node_id to get the correct ledger
ALICE_RESERVES=$(curl -s http://localhost:3011/bitcoin-deposits/ledgers | \
    jq -r ".data.ledgers[] | select(.partner_node_id == \"$CHARLIE_ID\") | .local_reserves_sat // 0" | head -1)
BOB_RESERVES=$(curl -s http://localhost:3012/bitcoin-deposits/ledgers | \
    jq -r ".data.ledgers[] | select(.partner_node_id == \"$CHARLIE_ID\") | .local_reserves_sat // 0" | head -1)

# Default to 0 if empty
ALICE_RESERVES=${ALICE_RESERVES:-0}
BOB_RESERVES=${BOB_RESERVES:-0}

echo "Current reserves - Alice->Charlie: $ALICE_RESERVES, Bob->Charlie: $BOB_RESERVES"

if [ "$ALICE_RESERVES" -gt 0 ]; then
    run_with_retry alice "Reducing Alice's reserves ($ALICE_RESERVES sats)" $ADMIN reduce-reserves charlie "$ALICE_RESERVES"
    sleep 2
fi

if [ "$BOB_RESERVES" -gt 0 ]; then
    run_with_retry bob "Reducing Bob's reserves ($BOB_RESERVES sats)" $ADMIN reduce-reserves charlie "$BOB_RESERVES"
    sleep 2
fi

# ============================================
# PHASE 6: Remove reserves outputs
# ============================================
echo ""
echo "=== PHASE 6: Removing reserves outputs ==="

run_with_retry alice "Removing Alice's reserves output" $ADMIN remove-reserves charlie
sleep 2

run_with_retry bob "Removing Bob's reserves output" $ADMIN remove-reserves charlie
sleep 2

# ============================================
# PHASE 7: Close ledgers
# ============================================
echo ""
echo "=== PHASE 7: Closing ledgers ==="

run_with_retry alice "Closing Alice's ledger with Charlie" $ADMIN remove-ledger charlie
sleep 2

run_with_retry bob "Closing Bob's ledger with Charlie" $ADMIN remove-ledger charlie
sleep 2

# ============================================
# Final status
# ============================================
echo ""
echo "=========================================="
echo "=== FINAL STATUS ==="
echo "=========================================="

echo ""
echo "Alice ledgers:"
TARGET=alice $ADMIN list-ledgers || echo "(no ledgers)"

echo ""
echo "Bob ledgers:"
TARGET=bob $ADMIN list-ledgers || echo "(no ledgers)"

echo ""
echo "Charlie ledgers:"
TARGET=charlie $ADMIN list-ledgers || echo "(no ledgers)"

echo ""
echo "=========================================="
echo "Test complete! Log saved to: $LOGFILE"
echo "=========================================="
