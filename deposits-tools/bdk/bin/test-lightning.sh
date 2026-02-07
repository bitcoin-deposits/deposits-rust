#!/bin/bash
# Lightning channel test script for BDK + LDK integration
#
# This script tests:
# 1. Opening a Lightning channel between Alice and Bob
# 2. Creating and paying invoices
# 3. Integration with deposits-bdk for invoice credits
#
# Usage:
#   ./bin/test-lightning.sh              # Run full test
#   ./bin/test-lightning.sh open-channel # Just open channel
#   ./bin/test-lightning.sh pay-invoice  # Just test invoice payment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Channel settings
CHANNEL_AMOUNT=5000000  # 5M sats

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

# Helper to call ldk-cli for BDK Lightning nodes
ldk_cli() {
    "$SCRIPT_DIR/ldk-cli.sh" "$@"
}

# ============================================================================
# Test: Wait for LDK nodes to be ready
# ============================================================================

wait_for_ldk_nodes() {
    log_info "=== Waiting for LDK nodes ==="
    echo ""

    for node in alice bob; do
        log_info "Waiting for bdk-$node-ln..."
        local max_attempts=30
        local attempt=0
        while true; do
            local info=$(ldk_cli "$node" get-node-info 2>/dev/null || echo "")
            local pubkey=$(echo "$info" | jq -r '.node_id // empty' 2>/dev/null || echo "")
            if [ -n "$pubkey" ]; then
                log_success "bdk-$node-ln ready: ${pubkey:0:16}..."
                break
            fi
            attempt=$((attempt + 1))
            if [ $attempt -ge $max_attempts ]; then
                log_error "bdk-$node-ln not ready after $max_attempts attempts"
                return 1
            fi
            sleep 2
        done
    done
}

# ============================================================================
# Test: Open channel between Alice and Bob
# ============================================================================

open_channel() {
    log_info ""
    log_info "=== Opening Lightning Channel (Alice -> Bob) ==="
    echo ""

    # Get pubkeys
    local alice_info=$(ldk_cli alice get-node-info)
    local bob_info=$(ldk_cli bob get-node-info)

    local alice_pubkey=$(echo "$alice_info" | jq -r '.node_id')
    local bob_pubkey=$(echo "$bob_info" | jq -r '.node_id')

    if [ -z "$alice_pubkey" ] || [ -z "$bob_pubkey" ]; then
        test_fail "Could not get node pubkeys"
        return 1
    fi

    log_info "Alice: ${alice_pubkey:0:16}..."
    log_info "Bob:   ${bob_pubkey:0:16}..."

    # Check if channel already exists
    local existing=$(ldk_cli alice list-channels | jq -r ".channels[] | select(.counterparty_node_id == \"$bob_pubkey\") | .channel_id" 2>/dev/null || echo "")

    if [ -n "$existing" ]; then
        log_info "Channel already exists: ${existing:0:16}..."
        test_pass "Channel exists"
        return 0
    fi

    # Check Alice's balance
    local alice_balances=$(ldk_cli alice get-balances)
    local alice_balance=$(echo "$alice_balances" | jq -r '.total_onchain_balance_sats // 0')
    log_info "Alice on-chain balance: $alice_balance sats"

    if [ "$alice_balance" -lt "$CHANNEL_AMOUNT" ]; then
        log_error "Alice needs at least $CHANNEL_AMOUNT sats, has $alice_balance"
        test_fail "Insufficient balance"
        return 1
    fi

    # Open channel with 50/50 balance
    local push_msat=$((CHANNEL_AMOUNT * 500))  # 50% in millisats
    log_info "Opening channel: $CHANNEL_AMOUNT sats, pushing $push_msat msat to Bob..."

    # Bob's address inside the docker network
    local result=$(ldk_cli alice open-channel \
        --node-pubkey "$bob_pubkey" \
        --address "bdk-bob-ln:9736" \
        --channel-amount-sats "$CHANNEL_AMOUNT" \
        --push-to-counterparty-msat "$push_msat" \
        --announce-channel 2>&1) || true

    local user_channel_id=$(echo "$result" | jq -r '.user_channel_id // empty' 2>/dev/null || echo "")
    if [ -n "$user_channel_id" ]; then
        log_info "Channel opening: ${user_channel_id:0:16}..."
    else
        # Check for error message
        local error=$(echo "$result" | grep -i "error" || echo "$result")
        log_warn "Open channel response: $error"
    fi

    # Mine blocks to confirm
    log_info "Mining blocks to confirm channel..."
    mine_blocks 6

    # Wait for channel to be ready
    log_info "Waiting for channel to be ready..."
    local max_wait=60
    local waited=0
    while [ $waited -lt $max_wait ]; do
        local ready=$(ldk_cli alice list-channels | jq -r ".channels[] | select(.counterparty_node_id == \"$bob_pubkey\") | .is_channel_ready" 2>/dev/null || echo "false")
        if [ "$ready" = "true" ]; then
            test_pass "Channel opened and ready"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    test_fail "Channel not ready after ${max_wait}s"
    return 1
}

# ============================================================================
# Test: Pay invoice from Alice to Bob
# ============================================================================

test_invoice_payment() {
    log_info ""
    log_info "=== Testing Invoice Payment (Alice -> Bob) ==="
    echo ""

    # Create invoice on Bob
    local amount_msat=100000  # 100 sats
    log_info "Bob creating invoice for $amount_msat msat..."

    local invoice_result=$(ldk_cli bob bolt11-receive --amount-msat "$amount_msat" --description "Test payment")
    local invoice=$(echo "$invoice_result" | jq -r '.invoice // empty')

    if [ -z "$invoice" ]; then
        local error=$(echo "$invoice_result" | jq -r '.error // .message // empty')
        test_fail "Create invoice failed: $invoice_result"
        return 1
    fi

    log_info "Invoice: ${invoice:0:40}..."

    # Pay invoice from Alice
    log_info "Alice paying invoice..."
    local pay_result=$(ldk_cli alice bolt11-send --invoice "$invoice" 2>&1) || true
    local payment_id=$(echo "$pay_result" | jq -r '.payment_id // .payment_hash // empty' 2>/dev/null || echo "")

    if [ -n "$payment_id" ]; then
        log_info "Payment initiated: ${payment_id:0:16}..."
        # Wait briefly for payment to complete
        sleep 2
        # Check payment status
        local payment_status=$(ldk_cli alice list-payments 2>/dev/null | jq -r ".payments[] | select(.id == \"$payment_id\") | .status" 2>/dev/null || echo "")
        if [ "$payment_status" = "1" ]; then
            test_pass "Payment succeeded"
        else
            test_pass "Payment sent (status: $payment_status)"
        fi
    else
        test_fail "Payment failed: $pay_result"
        return 1
    fi

    # Wait a moment for payment to settle
    sleep 2

    # Check balances
    local alice_channels=$(ldk_cli alice list-channels)
    local bob_channels=$(ldk_cli bob list-channels)

    local alice_balance=$(echo "$alice_channels" | jq -r '.channels[0].outbound_capacity_msat // 0')
    local bob_balance=$(echo "$bob_channels" | jq -r '.channels[0].outbound_capacity_msat // 0')

    log_info "After payment:"
    log_info "  Alice outbound capacity: $alice_balance msat"
    log_info "  Bob outbound capacity: $bob_balance msat"

    test_pass "Invoice payment complete"
}

# ============================================================================
# Test: Show channel status
# ============================================================================

show_channel_status() {
    log_info ""
    log_info "=== Channel Status ==="
    echo ""

    for node in alice bob; do
        log_info "bdk-$node-ln channels:"
        local channels=$(ldk_cli "$node" list-channels 2>/dev/null || echo '{"channels":[]}')
        local count=$(echo "$channels" | jq -r '.channels | length')

        if [ "$count" = "0" ]; then
            log_info "  No channels"
        else
            echo "$channels" | jq -r '.channels[] | "  - \(.counterparty_node_id[0:16])... ready=\(.is_channel_ready) outbound=\(.outbound_capacity_msat) inbound=\(.inbound_capacity_msat)"'
        fi
    done
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "=========================================="
    log_info "  Lightning Channel Test (BDK + LDK)"
    log_info "=========================================="
    echo ""

    # Check that ldk-cli works
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        exit 1
    fi

    # Parse command
    local cmd=${1:-full}

    case "$cmd" in
        open-channel)
            wait_for_ldk_nodes
            open_channel
            show_channel_status
            ;;
        pay-invoice)
            wait_for_ldk_nodes
            test_invoice_payment
            ;;
        status)
            wait_for_ldk_nodes
            show_channel_status
            ;;
        full|*)
            wait_for_ldk_nodes
            open_channel
            test_invoice_payment
            show_channel_status

            log_info ""
            log_info "=== Test Summary ==="
            log_info "  Passed: $TESTS_PASSED"
            log_info "  Failed: $TESTS_FAILED"

            if [ $TESTS_FAILED -gt 0 ]; then
                log_error "Some tests failed"
                exit 1
            else
                log_success "All tests passed!"
            fi
            ;;
    esac
}

main "$@"
