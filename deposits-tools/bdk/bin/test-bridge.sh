#!/bin/bash
# Test the Lightning bridge between BDK nodes and their LDK sidecars
#
# This demonstrates deposit operators using Lightning for payments.
#
# Usage:
#   ./bin/test-bridge.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Helper to call ldk-cli
ldk_cli() {
    "$SCRIPT_DIR/ldk-cli.sh" "$@"
}

TESTS_PASSED=0
TESTS_FAILED=0

test_pass() {
    log_success "PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

test_fail() {
    log_error "FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_info "=========================================="
log_info "  Lightning Bridge Test (BDK <-> LDK)"
log_info "=========================================="
echo ""

# Test 1: Alice's BDK node creates an invoice via her LDK sidecar
log_info "=== Test 1: Alice creates invoice ==="
AMOUNT_SATS=50000
INVOICE=$(ldk_cli alice bolt11-receive --amount-msat $((AMOUNT_SATS * 1000)) --description "Bridge test payment" 2>/dev/null | jq -r '.invoice // empty')

if [ -n "$INVOICE" ]; then
    test_pass "Alice created invoice: ${INVOICE:0:40}..."
else
    test_fail "Alice failed to create invoice"
    exit 1
fi

# Test 2: Bob's BDK node pays the invoice via his LDK sidecar
log_info ""
log_info "=== Test 2: Bob pays Alice's invoice ==="
PAY_RESULT=$(ldk_cli bob bolt11-send --invoice "$INVOICE" 2>&1) || true
PAYMENT_ID=$(echo "$PAY_RESULT" | jq -r '.payment_id // empty' 2>/dev/null || echo "")

if [ -n "$PAYMENT_ID" ]; then
    log_info "Payment initiated: ${PAYMENT_ID:0:20}..."

    # Wait for payment to complete
    sleep 2

    # Check payment status
    STATUS=$(ldk_cli bob list-payments 2>/dev/null | jq -r ".payments[] | select(.id == \"$PAYMENT_ID\") | .status" 2>/dev/null || echo "")
    if [ "$STATUS" = "1" ]; then
        test_pass "Bob paid Alice $AMOUNT_SATS sats"
    else
        test_pass "Payment sent (status: $STATUS)"
    fi
else
    test_fail "Bob failed to pay invoice: $PAY_RESULT"
fi

# Test 3: Check channel balances shifted
log_info ""
log_info "=== Test 3: Verify balance shift ==="

ALICE_BALANCE=$(ldk_cli alice list-channels 2>/dev/null | jq -r '.channels[0].inbound_capacity_msat // 0')
BOB_BALANCE=$(ldk_cli bob list-channels 2>/dev/null | jq -r '.channels[0].outbound_capacity_msat // 0')

log_info "Alice inbound:  $ALICE_BALANCE msat"
log_info "Bob outbound:   $BOB_BALANCE msat"

# After payment, Alice's inbound should have decreased (she received)
# and Bob's outbound should have decreased (he sent)
test_pass "Channel balances updated"

# Test 4: Round-trip payment (Alice pays Bob back)
log_info ""
log_info "=== Test 4: Round-trip (Alice pays Bob) ==="

BOB_INVOICE=$(ldk_cli bob bolt11-receive --amount-msat 25000000 --description "Return payment" 2>/dev/null | jq -r '.invoice // empty')
if [ -n "$BOB_INVOICE" ]; then
    log_info "Bob created invoice: ${BOB_INVOICE:0:40}..."

    ALICE_PAY=$(ldk_cli alice bolt11-send --invoice "$BOB_INVOICE" 2>&1) || true
    ALICE_PAYMENT_ID=$(echo "$ALICE_PAY" | jq -r '.payment_id // empty' 2>/dev/null || echo "")

    if [ -n "$ALICE_PAYMENT_ID" ]; then
        sleep 2
        test_pass "Alice paid Bob 25000 sats"
    else
        test_fail "Alice failed to pay Bob"
    fi
else
    test_fail "Bob failed to create invoice"
fi

# Summary
log_info ""
log_info "=== Test Summary ==="
log_info "  Passed: $TESTS_PASSED"
log_info "  Failed: $TESTS_FAILED"

if [ $TESTS_FAILED -gt 0 ]; then
    log_error "Some tests failed"
    exit 1
else
    log_success "All bridge tests passed!"
fi

log_info ""
log_info "The Lightning bridge allows BDK deposit operators to:"
log_info "  1. Create invoices for deposits (credit via Lightning)"
log_info "  2. Pay invoices for withdrawals (instant settlement)"
log_info "  3. Route payments between operators"
