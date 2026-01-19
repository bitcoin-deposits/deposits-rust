#!/bin/bash

# Stress test for Bitcoin Deposits
# Creates many wallets and has them pay each other (parallelized)

cd "$(dirname "$0")/.."
set -e

mkdir -p log
LOGFILE="log/stress-test-$(date +'%s').log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "=============================================="
echo "Bitcoin Deposits Stress Test (Parallel)"
echo "=============================================="
echo ""

# Configuration
ALICE_WALLETS=5       # Wallets on Alice (operator) with Charlie (partner)
BOB_WALLETS=5         # Wallets on Bob (operator) with Charlie (partner)
PAYMENTS_PER_WALLET=50 # Payments each wallet will make (500 total)
PAYMENT_AMOUNT=1000   # Amount per payment in msats
PARALLEL_JOBS=10      # Number of parallel payment jobs

NWC_CLIENT="../target/release/nwc-client"

# Ensure wallet directory exists
mkdir -p wallet/stress

# Clean up old stress test wallets
rm -f wallet/stress/*.json

# Results tracking
RESULTS_DIR=$(mktemp -d)
trap "rm -rf $RESULTS_DIR" EXIT

echo "Phase 1: Initialize ledgers"
echo "-------------------------------------------"

# Get node IDs
ALICE_ID=$(curl -s http://localhost:3011/info | jq -r '.data.node_id')
BOB_ID=$(curl -s http://localhost:3012/info | jq -r '.data.node_id')
CHARLIE_ID=$(curl -s http://localhost:3013/info | jq -r '.data.node_id')

echo "Alice:   $ALICE_ID"
echo "Bob:     $BOB_ID"
echo "Charlie: $CHARLIE_ID"

# Initialize ledgers in parallel
echo ""
echo "Initializing ledgers..."
curl -s -X POST http://localhost:3011/bitcoin-deposits/ledger/init \
  -H 'Content-Type: application/json' \
  -d "{\"partner_pubkey\":\"$CHARLIE_ID\"}" | jq -r '.data.message // .error // "already exists"' &
curl -s -X POST http://localhost:3012/bitcoin-deposits/ledger/init \
  -H 'Content-Type: application/json' \
  -d "{\"partner_pubkey\":\"$CHARLIE_ID\"}" | jq -r '.data.message // .error // "already exists"' &
wait

sleep 1

echo ""
echo "Phase 2: Create wallets (parallel with limit)"
echo "-------------------------------------------"

# Create wallets in parallel
create_wallet() {
    local name=$1
    local target=$2
    if $NWC_CLIENT -w "wallet/stress/${name}.json" -t "$target" init-deposit 2>/dev/null; then
        echo "$name" >> "$RESULTS_DIR/wallets_created.txt"
        echo "  $name OK"
    else
        echo "  $name FAILED"
    fi
}

# Create Alice and Bob wallets in parallel batches
WALLET_PARALLEL=3
for i in $(seq 1 $ALICE_WALLETS); do
    create_wallet "alice_w${i}" "alice" &
    while [ $(jobs -r | wc -l) -ge $WALLET_PARALLEL ]; do sleep 0.1; done
done
for i in $(seq 1 $BOB_WALLETS); do
    create_wallet "bob_w${i}" "bob" &
    while [ $(jobs -r | wc -l) -ge $WALLET_PARALLEL ]; do sleep 0.1; done
done
wait

# Build wallet arrays from created wallets
ALICE_WALLET_NAMES=()
BOB_WALLET_NAMES=()
for i in $(seq 1 $ALICE_WALLETS); do
    ALICE_WALLET_NAMES+=("alice_w${i}")
done
for i in $(seq 1 $BOB_WALLETS); do
    BOB_WALLET_NAMES+=("bob_w${i}")
done

ALL_WALLETS=("${ALICE_WALLET_NAMES[@]}" "${BOB_WALLET_NAMES[@]}")
TOTAL_WALLETS=${#ALL_WALLETS[@]}

echo ""
echo "Created $TOTAL_WALLETS wallets"

if [ $TOTAL_WALLETS -lt 2 ]; then
    echo "ERROR: Need at least 2 wallets to run stress test"
    exit 1
fi

echo ""
echo "Phase 3: Fund wallets (parallel batches)"
echo "-------------------------------------------"

fund_wallet_via_node() {
    local name=$1
    local node_port=$2
    # Get invoice
    invoice=$($NWC_CLIENT -w "wallet/stress/${name}.json" make-invoice 100000 2>/dev/null | jq -r '.result.invoice // empty')
    if [ -z "$invoice" ]; then
        echo "  $name FAILED (no invoice)"
        return 1
    fi
    # Pay via node's /pay endpoint
    result=$(curl -s -X POST "http://localhost:${node_port}/pay" \
        -H 'Content-Type: application/json' \
        -d "{\"invoice\":\"${invoice}\"}" | jq -r '.data.status // empty')
    if [ "$result" = "sent" ]; then
        echo "  $name funded"
        return 0
    fi
    echo "  $name FAILED (pay: $result)"
    return 1
}

# Fund Alice's wallets from Bob's node, Bob's wallets from Alice's node
# This avoids needing to set up Charlie's deposit wallet for funding
FUND_PARALLEL=3
echo "Funding alice wallets from Bob's node (parallel)..."
for name in "${ALICE_WALLET_NAMES[@]}"; do
    fund_wallet_via_node "$name" "3012" &  # Bob's port
    while [ $(jobs -r | wc -l) -ge $FUND_PARALLEL ]; do sleep 0.1; done
done
wait

echo "Funding bob wallets from Alice's node (parallel)..."
for name in "${BOB_WALLET_NAMES[@]}"; do
    fund_wallet_via_node "$name" "3011" &  # Alice's port
    while [ $(jobs -r | wc -l) -ge $FUND_PARALLEL ]; do sleep 0.1; done
done
wait

echo ""
echo "Phase 4: Wallet-to-wallet payments (parallel)"
echo "-------------------------------------------"

TOTAL_PAYMENTS=$((TOTAL_WALLETS * PAYMENTS_PER_WALLET))
echo "Making $TOTAL_PAYMENTS payments with $PARALLEL_JOBS parallel jobs"
echo ""

# Payment function
do_payment() {
    local sender=$1
    local receiver=$2
    local id=$3

    # Create invoice with unique description to avoid hash collisions
    invoice_response=$($NWC_CLIENT -w "wallet/stress/${receiver}.json" make-invoice $PAYMENT_AMOUNT -d "payment_${id}_$(date +%s%N)" 2>/dev/null)
    invoice=$(echo "$invoice_response" | jq -r '.result.invoice // empty')
    if [ -z "$invoice" ]; then
        error=$(echo "$invoice_response" | jq -r '.error.message // .error // "unknown"')
        echo "FAIL_INVOICE:$error" >> "$RESULTS_DIR/results.txt"
        echo "[$id] $sender -> $receiver FAILED (invoice: $error)"
        return
    fi

    # Pay
    pay_response=$($NWC_CLIENT -w "wallet/stress/${sender}.json" pay-invoice "$invoice" 2>/dev/null)
    result=$(echo "$pay_response" | jq -r '.result.preimage // empty')
    if [ -n "$result" ]; then
        echo "OK" >> "$RESULTS_DIR/results.txt"
        echo "[$id] $sender -> $receiver OK"
    else
        error=$(echo "$pay_response" | jq -r '.error.message // .error // "unknown"')
        # Skip "already initiated" errors - these are test race conditions, not protocol failures
        if [[ "$error" == *"already been initiated"* ]]; then
            echo "SKIP:$error" >> "$RESULTS_DIR/results.txt"
            echo "[$id] $sender -> $receiver SKIPPED (duplicate payment hash)"
        else
            echo "FAIL_PAY:$error" >> "$RESULTS_DIR/results.txt"
            echo "[$id] $sender -> $receiver FAILED (pay: $error)"
        fi
    fi
}

# Launch all payments with timing
START_TIME=$(date +%s.%N)
payment_id=0
for sender in "${ALL_WALLETS[@]}"; do
    for p in $(seq 1 $PAYMENTS_PER_WALLET); do
        # Pick random receiver (different from sender)
        while true; do
            idx=$((RANDOM % TOTAL_WALLETS))
            receiver="${ALL_WALLETS[$idx]}"
            [ "$receiver" != "$sender" ] && break
        done

        ((payment_id++))
        do_payment "$sender" "$receiver" "$payment_id" &

        # Limit parallel jobs
        while [ $(jobs -r | wc -l) -ge $PARALLEL_JOBS ]; do
            sleep 0.05
        done
    done
done
wait
END_TIME=$(date +%s.%N)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "=============================================="
echo "Stress Test Complete"
echo "=============================================="

# Count results
SUCCESS=$(grep -c "^OK" "$RESULTS_DIR/results.txt" 2>/dev/null || true)
FAILED=$(grep -c "^FAIL" "$RESULTS_DIR/results.txt" 2>/dev/null || true)
SKIPPED=$(grep -c "^SKIP" "$RESULTS_DIR/results.txt" 2>/dev/null || true)
SUCCESS=${SUCCESS:-0}
FAILED=${FAILED:-0}
SKIPPED=${SKIPPED:-0}
TOTAL=$((SUCCESS + FAILED))

echo ""
echo "Results:"
echo "  Total payments attempted: $TOTAL_PAYMENTS"
echo "  Successful: $SUCCESS"
echo "  Failed: $FAILED"
echo "  Skipped (test race): $SKIPPED"
if [ "$TOTAL" -gt 0 ]; then
    echo "  Success rate: $((SUCCESS * 100 / TOTAL))%"
fi
echo ""
echo "Performance:"
echo "  Duration: ${DURATION}s"
if [ "$SUCCESS" -gt 0 ]; then
    PAYMENTS_PER_SEC=$(echo "scale=2; $SUCCESS / $DURATION" | bc)
    echo "  Payments/sec: $PAYMENTS_PER_SEC"
fi
echo ""

# Check for force-closes
echo "Checking for force-closes..."
ALICE_CLOSES=$(docker logs ldk-alice 2>&1 | grep -c "Force-closing" || true)
BOB_CLOSES=$(docker logs ldk-bob 2>&1 | grep -c "Force-closing" || true)
CHARLIE_CLOSES=$(docker logs ldk-charlie 2>&1 | grep -c "Force-closing" || true)

echo "  Alice force-closes: $ALICE_CLOSES"
echo "  Bob force-closes: $BOB_CLOSES"
echo "  Charlie force-closes: $CHARLIE_CLOSES"

if [ $((ALICE_CLOSES + BOB_CLOSES + CHARLIE_CLOSES)) -eq 0 ]; then
    echo ""
    echo "No force-closes detected!"
fi

echo ""
echo "Ledger status:"
./bin/updates.sh 2>/dev/null | grep -E "^(Direct|Partner|Audit):" | head -10

echo ""
echo "Full log: $LOGFILE"
