#!/bin/bash
#
# Usage: ./bin/test-to-close.sh [network]
#
# Full test cycle with complete teardown:
# 1. Create wallets (deposits on ledgers)
# 2. Run payments between wallets
# 3. Pay out balances (drain deposits)
# 4. Remove deposits
# 5. Reduce reserves to 0
# 6. Remove reserves outputs
# 7. Close ledgers

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1

NWC="../target/release/nwc-client"
ADMIN="../target/release/deposits-admin"
LDK_CLI="cargo run -q --manifest-path /Users/vinnyfiano/workspace/ldk-server/Cargo.toml --bin ldk-server-cli --"
API_KEY="test_api_key"

# Helper: get deposit balance in msats using protobuf API
# Usage: get_deposit_balance <operator> <deposit_pubkey>
get_deposit_balance() {
    local operator=$1
    local deposit_pubkey=$2
    local balance_sat
    balance_sat=$(TARGET=$operator $ADMIN deposit-balance "$deposit_pubkey" 2>/dev/null)
    # Convert sats to msats
    echo $((balance_sat * 1000))
}

mkdir -p log
LOGFILE=log/test-to-close-$(date +'%s').log
exec > >(tee -a "$LOGFILE") 2>&1

echo "=========================================="
echo "Testing on network: $NETWORK"
echo "=========================================="

# Get node IDs using ldk-server-cli (protobuf API)
ALICE_ID=$($LDK_CLI -b localhost:3011 -a "$API_KEY" -t certs/alice.crt get-node-info 2>/dev/null | jq -r '.node_id')
BOB_ID=$($LDK_CLI -b localhost:3012 -a "$API_KEY" -t certs/bob.crt get-node-info 2>/dev/null | jq -r '.node_id')
CHARLIE_ID=$($LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt get-node-info 2>/dev/null | jq -r '.node_id')

echo "Alice:   $ALICE_ID"
echo "Bob:     $BOB_ID"
echo "Charlie: $CHARLIE_ID"
echo ""

# ============================================
# PHASE 1: Setup wallets and fund them
# ============================================
echo "=== PHASE 1: Creating wallets ==="

./bin/make-a-wallet.sh alice charlie bob amber
./bin/make-a-wallet.sh bob charlie alice blue

# ============================================
# PHASE 2: Run payments between wallets
# ============================================
echo ""
echo "=== PHASE 2: Running payments ==="

./bin/pay-amber-from-charlie.sh
./bin/pay-blue-from-amber.sh

# Show balances after payments (using protobuf API)
echo ""
echo "Balances after payments:"
AMBER_PUBKEY=$(jq -r '.deposit_pubkey' wallet/amber.json)
BLUE_PUBKEY=$(jq -r '.deposit_pubkey' wallet/blue.json)
AMBER_BALANCE=$(get_deposit_balance alice "$AMBER_PUBKEY")
BLUE_BALANCE=$(get_deposit_balance bob "$BLUE_PUBKEY")
echo "  amber: $AMBER_BALANCE msat"
echo "  blue:  $BLUE_BALANCE msat"

# Show ledger status
echo ""
echo "Ledger status after payments:"
./bin/updates.sh

# ============================================
# PHASE 3: Drain deposits (pay out balances)
# ============================================
echo ""
echo "=== PHASE 3: Draining deposits ==="

# Create invoices on charlie for the exact amounts, then pay from wallets
# NOTE: NWC balance returns msats, not sats
if [ "$AMBER_BALANCE" -gt 0 ]; then
    echo "Draining amber ($AMBER_BALANCE msat) to charlie..."
    AMBER_INVOICE=$($LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt bolt11-receive --amount-msat "$AMBER_BALANCE" -d "drain amber" | jq -r '.invoice')
    $NWC -w wallet/amber.json pay-invoice "$AMBER_INVOICE" || echo "amber payment failed"
    sleep 2
fi

if [ "$BLUE_BALANCE" -gt 0 ]; then
    echo "Draining blue ($BLUE_BALANCE msat) to charlie..."
    BLUE_INVOICE=$($LDK_CLI -b localhost:3013 -a "$API_KEY" -t certs/charlie.crt bolt11-receive --amount-msat "$BLUE_BALANCE" -d "drain blue" | jq -r '.invoice')
    $NWC -w wallet/blue.json pay-invoice "$BLUE_INVOICE" || echo "blue payment failed"
    sleep 2
fi

# Verify balances are zero (using protobuf API)
echo ""
echo "Balances after drain:"
AMBER_BALANCE=$(get_deposit_balance alice "$AMBER_PUBKEY")
BLUE_BALANCE=$(get_deposit_balance bob "$BLUE_PUBKEY")
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
./bin/updates.sh

# ============================================
# PHASE 5: Reduce reserves to 0
# ============================================
echo ""
echo "=== PHASE 5: Reducing reserves ==="

# Get current reserves for the specific ledgers (alice->charlie, bob->charlie)
# Use deposits-admin to list ledgers and parse reserves
# Output format: "    Reserves: 10000 sat" - extract field 2
# Note: grep for CHARLIE_ID (full pubkey), not the alias "charlie"
ALICE_RESERVES=$($ADMIN -p alice list-ledgers 2>/dev/null | grep -A5 "$CHARLIE_ID" | grep -i "reserves" | awk '{print $2}' | head -1)
BOB_RESERVES=$($ADMIN -p bob list-ledgers 2>/dev/null | grep -A5 "$CHARLIE_ID" | grep -i "reserves" | awk '{print $2}' | head -1)

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
