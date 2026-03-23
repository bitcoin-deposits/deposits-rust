#!/bin/bash
# Lightning test script for shared LDK node + self-pay wrapper
#
# Tests:
# 1. Lightning node is reachable
# 2. Invoice creation and self-pay settlement
# 3. list-payments returns correct format
#
# Usage:
#   ./bin/test-lightning.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

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

# Helper: call ldk-server-cli in the lightning container
ldk_cli() {
    "$SCRIPT_DIR/ldk-cli.sh" "$@"
}

# ============================================================================
# Test: Lightning node is reachable
# ============================================================================

test_node_ready() {
    log_info "=== Test: Lightning node reachable ==="

    local info=$(ldk_cli get-node-info 2>/dev/null || echo "")
    local pubkey=$(echo "$info" | python3 -c "import json,sys; print(json.load(sys.stdin).get('node_id',''))" 2>/dev/null || echo "")

    if [ -n "$pubkey" ]; then
        test_pass "Lightning node ready: ${pubkey:0:20}..."
    else
        test_fail "Lightning node not reachable"
        return 1
    fi
}

# ============================================================================
# Test: Self-pay invoice round-trip
# ============================================================================

test_self_pay() {
    log_info ""
    log_info "=== Test: Self-pay invoice (create + pay + list) ==="

    # Set up wrapper env
    local LDK_REAL_CLI="${LDK_SERVER_CLI:-$HOME/ldk-server/target/release/ldk-server-cli}"
    local NETWORK=$(docker exec lightning printenv NETWORK 2>/dev/null || echo "regtest")
    local API_KEY=$(docker exec lightning sh -c "cat /ldk/${NETWORK}/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null)

    export LDK_REAL_CLI
    export LDK_HOST="localhost"
    export LDK_PORT="3111"
    export LDK_API_KEY="$API_KEY"
    export LDK_TLS_CERT="$TOOLS_DIR/certs/lightning.crt"
    export LDK_SELF_PAY_DIR="${DATA_ROOT}/self-pay"

    WRAPPER="$SCRIPT_DIR/ldk-cli-wrapper.sh"

    # Create invoice
    local amount_msat=100000
    log_info "  Creating invoice for $amount_msat msat..."
    local recv_output=$($WRAPPER bolt11-receive --amount-msat "$amount_msat" --description "test" 2>&1)
    local invoice=$(echo "$recv_output" | python3 -c "import json,sys; print(json.load(sys.stdin).get('invoice',''))" 2>/dev/null || echo "")
    local payment_hash=$(echo "$recv_output" | python3 -c "import json,sys; print(json.load(sys.stdin).get('payment_hash',''))" 2>/dev/null || echo "")

    if [ -z "$invoice" ]; then
        test_fail "Create invoice failed: $recv_output"
        return 1
    fi
    test_pass "Invoice created: ${invoice:0:40}..."

    # Pay invoice (self-pay via wrapper)
    log_info "  Paying invoice (self-pay)..."
    local pay_output=$($WRAPPER bolt11-send --invoice "$invoice" 2>&1)
    local payment_id=$(echo "$pay_output" | python3 -c "import json,sys; print(json.load(sys.stdin).get('payment_id',''))" 2>/dev/null || echo "")

    if [ -n "$payment_id" ]; then
        test_pass "Self-pay succeeded: ${payment_id:0:20}..."
    else
        test_fail "Self-pay failed: $pay_output"
        return 1
    fi

    # Verify list-payments includes the self-pay record
    log_info "  Checking list-payments..."
    local list_output=$($WRAPPER list-payments 2>&1)
    local found=$(echo "$list_output" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for p in d.get('payments', []):
    if p.get('id') == '$payment_hash' and p.get('status') == 1:
        print('found')
        break
" 2>/dev/null || echo "")

    if [ "$found" = "found" ]; then
        test_pass "Self-pay record in list-payments (status=1)"
    else
        test_fail "Self-pay record not found in list-payments"
    fi
}

# ============================================================================
# Test: Lightning node balance
# ============================================================================

test_balance() {
    log_info ""
    log_info "=== Test: Lightning balance ==="

    local balances=$(ldk_cli get-balances 2>/dev/null || echo "{}")
    local onchain=$(echo "$balances" | python3 -c "import json,sys; print(json.load(sys.stdin).get('spendable_onchain_balance_sats',0))" 2>/dev/null || echo "0")

    log_info "  On-chain balance: $onchain sats"
    if [ "$onchain" -gt 0 ] 2>/dev/null; then
        test_pass "Lightning node has funds"
    else
        test_fail "Lightning node has no funds"
    fi
}

# ============================================================================
# Main
# ============================================================================

log_info "=========================================="
log_info "  Lightning Test (shared node + self-pay)"
log_info "=========================================="
echo ""

test_node_ready
test_balance
test_self_pay

echo ""
log_info "=== Test Summary ==="
log_info "  Passed: $TESTS_PASSED"
log_info "  Failed: $TESTS_FAILED"

if [ $TESTS_FAILED -gt 0 ]; then
    log_error "Some tests failed"
    exit 1
else
    log_success "All tests passed!"
fi
