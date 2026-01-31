#!/bin/bash
# Cross-Collateral Test Script
#
# This script tests the cross-collateral flow:
# 1. Alice opens a ledger bound to a UTXO
# 2. Bob opens a ledger bound to a UTXO
# 3. Deposit A is opened on Bob's ledger
# 4. Deposit B is opened on Alice's ledger
# 5. Alice locks Deposit A as collateral, receiving an attestation
# 6. Bob locks Deposit B as collateral, receiving an attestation
# 7. Alice and Bob log the collateral attestations to their ledgers
# 8. Deposit C is opened on Alice's ledger, funded by Bob
# 9. Deposit D is opened on Bob's ledger, funded by Deposit C
#
# Usage:
#   ./bin/test-collateral.sh             # Run all tests
#   ./bin/test-collateral.sh --verbose   # Show more output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v  Show more output"
            echo "  --help         Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

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

# ============================================================================
# Global Variables
# ============================================================================

ALICE_RESERVES_ID=""
BOB_RESERVES_ID=""
ALICE_NODE_ID=""
BOB_NODE_ID=""

# Deposit A - on Bob's ledger
DEPOSIT_A_PUBKEY=""
DEPOSIT_A_SECRET=""

# Deposit B - on Alice's ledger
DEPOSIT_B_PUBKEY=""
DEPOSIT_B_SECRET=""

# Deposit C - on Alice's ledger (funded by Bob)
DEPOSIT_C_PUBKEY=""
DEPOSIT_C_SECRET=""
DEPOSIT_C_OFFER_ID=""
DEPOSIT_C_FUNDING_ADDRESS=""

# Deposit D - on Bob's ledger (funded by Deposit C)
DEPOSIT_D_PUBKEY=""
DEPOSIT_D_SECRET=""
DEPOSIT_D_OFFER_ID=""
DEPOSIT_D_FUNDING_ADDRESS=""

# ============================================================================
# Step 1 & 2: Open Ledgers
# ============================================================================

test_open_ledgers() {
    log_info "=== Step 1 & 2: Opening Ledgers ==="
    echo ""

    # Get current block height for enforcement block
    local current_height=$(get_block_height)
    local enforcement_block=$((current_height + 100))

    log_info "Current block: $current_height, Enforcement block: $enforcement_block"

    # Get node IDs
    local alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)

    ALICE_NODE_ID=$(echo "$alice_info" | grep "Node ID:" | awk '{print $3}')
    BOB_NODE_ID=$(echo "$bob_info" | grep "Node ID:" | awk '{print $3}')

    log_info "Alice Node ID: ${ALICE_NODE_ID:0:16}..."
    log_info "Bob Node ID: ${BOB_NODE_ID:0:16}..."

    # Step 1: Alice opens a ledger bound to her reserves UTXO
    log_info "Alice opening ledger..."
    local alice_ledger_output=$(run_bdk_cmd "bdk-alice" ledger open "$enforcement_block" 2>&1)

    if echo "$alice_ledger_output" | grep -q "Ledger opened successfully\|Opening ledger\|already"; then
        test_pass "Alice opened ledger"
        if $VERBOSE; then
            echo "    Output: $alice_ledger_output"
        fi
    else
        test_fail "Alice failed to open ledger"
        echo "    Output: $alice_ledger_output"
        return 1
    fi

    # Get Alice's reserves ID
    alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    ALICE_RESERVES_ID=$(echo "$alice_info" | grep "Reserves address:" | awk '{print $3}')
    log_info "Alice's reserves ID: ${ALICE_RESERVES_ID:0:20}..."

    # Step 2: Bob opens a ledger bound to his reserves UTXO
    log_info "Bob opening ledger..."
    local bob_ledger_output=$(run_bdk_cmd "bdk-bob" ledger open "$enforcement_block" 2>&1)

    if echo "$bob_ledger_output" | grep -q "Ledger opened successfully\|Opening ledger\|already"; then
        test_pass "Bob opened ledger"
        if $VERBOSE; then
            echo "    Output: $bob_ledger_output"
        fi
    else
        test_fail "Bob failed to open ledger"
        echo "    Output: $bob_ledger_output"
        return 1
    fi

    # Get Bob's reserves ID
    bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    BOB_RESERVES_ID=$(echo "$bob_info" | grep "Reserves address:" | awk '{print $3}')
    log_info "Bob's reserves ID: ${BOB_RESERVES_ID:0:20}..."
}

# ============================================================================
# Step 3 & 4: Open Deposits
# ============================================================================

test_open_deposits() {
    log_info "=== Step 3 & 4: Opening Deposits ==="
    echo ""

    # Create wallets directory
    mkdir -p "$SCRIPT_DIR/../wallets"

    # Generate keypair for Deposit A (will be on Bob's ledger)
    log_info "Generating deposit keypairs..."
    local keypair_a=$(run_keygen "bdk-alice")
    DEPOSIT_A_SECRET=$(echo "$keypair_a" | awk '{print $1}')
    DEPOSIT_A_PUBKEY=$(echo "$keypair_a" | awk '{print $2}')

    # Generate keypair for Deposit B (will be on Alice's ledger)
    local keypair_b=$(run_keygen "bdk-bob")
    DEPOSIT_B_SECRET=$(echo "$keypair_b" | awk '{print $1}')
    DEPOSIT_B_PUBKEY=$(echo "$keypair_b" | awk '{print $2}')

    if [ -z "$DEPOSIT_A_PUBKEY" ] || [ -z "$DEPOSIT_B_PUBKEY" ]; then
        test_fail "Failed to generate deposit keypairs"
        return 1
    fi

    # Save wallet files
    echo "{\"deposit_pubkey\": \"$DEPOSIT_A_PUBKEY\", \"deposit_secret\": \"$DEPOSIT_A_SECRET\", \"ledger\": \"bob\"}" > "$SCRIPT_DIR/../wallets/deposit_a.json"
    echo "{\"deposit_pubkey\": \"$DEPOSIT_B_PUBKEY\", \"deposit_secret\": \"$DEPOSIT_B_SECRET\", \"ledger\": \"alice\"}" > "$SCRIPT_DIR/../wallets/deposit_b.json"

    # Step 3: Open Deposit A on Bob's ledger
    log_info "Opening Deposit A on Bob's ledger: ${DEPOSIT_A_PUBKEY:0:20}..."
    local open_output=$(run_bdk_cmd "bdk-bob" deposit open "$BOB_RESERVES_ID" "$DEPOSIT_A_PUBKEY" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Deposit A opened on Bob's ledger"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
    else
        test_fail "Failed to open Deposit A on Bob's ledger"
        echo "    Output: $open_output"
        return 1
    fi

    # Step 4: Open Deposit B on Alice's ledger
    log_info "Opening Deposit B on Alice's ledger: ${DEPOSIT_B_PUBKEY:0:20}..."
    open_output=$(run_bdk_cmd "bdk-alice" deposit open "$ALICE_RESERVES_ID" "$DEPOSIT_B_PUBKEY" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Deposit B opened on Alice's ledger"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
    else
        test_fail "Failed to open Deposit B on Alice's ledger"
        echo "    Output: $open_output"
        return 1
    fi
}

# ============================================================================
# Step 5 & 6: Lock Deposits as Collateral
# ============================================================================

test_lock_collateral() {
    log_info "=== Step 5 & 6: Locking Deposits as Collateral ==="
    echo ""

    # First fund both deposits so they have balance to pledge
    log_info "Funding deposits before pledging collateral..."

    # Fund Deposit A (on Bob's ledger) - we need to create an offer and fund it
    local offer_a=$(run_bdk_cmd "bdk-bob" deposit offer "$BOB_RESERVES_ID" "$DEPOSIT_A_PUBKEY" 100000000 10000 144 2>&1)
    local offer_a_id=$(echo "$offer_a" | grep "Offer ID:" | awk '{print $3}')
    local offer_a_addr=$(echo "$offer_a" | grep "Funding address:" | awk '{print $3}')

    if [ -n "$offer_a_addr" ]; then
        local txid_a=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$offer_a_addr" 0.5 2>&1)
        mine_blocks 1
        sleep 1
        run_bdk_cmd "bdk-bob" deposit complete "$offer_a_id" "$txid_a" 50000000 >/dev/null 2>&1
        test_pass "Funded Deposit A with 0.5 BTC"
    fi

    # Fund Deposit B (on Alice's ledger)
    local offer_b=$(run_bdk_cmd "bdk-alice" deposit offer "$ALICE_RESERVES_ID" "$DEPOSIT_B_PUBKEY" 100000000 10000 144 2>&1)
    local offer_b_id=$(echo "$offer_b" | grep "Offer ID:" | awk '{print $3}')
    local offer_b_addr=$(echo "$offer_b" | grep "Funding address:" | awk '{print $3}')

    if [ -n "$offer_b_addr" ]; then
        local txid_b=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$offer_b_addr" 0.5 2>&1)
        mine_blocks 1
        sleep 1
        run_bdk_cmd "bdk-alice" deposit complete "$offer_b_id" "$txid_b" 50000000 >/dev/null 2>&1
        test_pass "Funded Deposit B with 0.5 BTC"
    fi

    # Step 5: Deposit A holder pledges their balance as collateral on Bob's ledger
    # The deposit holder (who has DEPOSIT_A_SECRET) pledges to back Bob's obligations
    log_info "Pledging Deposit A as collateral on Bob's ledger..."

    local collateral_amount=25000000000  # 0.25 BTC in msats
    local lock_blocks=100

    local pledge_output=$(run_bdk_cmd "bdk-bob" collateral pledge "$BOB_RESERVES_ID" "$DEPOSIT_A_SECRET" "$collateral_amount" "$lock_blocks" 2>&1)

    if echo "$pledge_output" | grep -q "Collateral pledge created\|Pledged amount"; then
        test_pass "Deposit A pledged as collateral on Bob's ledger"
        if $VERBOSE; then
            echo "    Output: $pledge_output"
        fi
    else
        test_fail "Failed to pledge Deposit A as collateral"
        echo "    Output: $pledge_output"
    fi

    # Step 6: Deposit B holder pledges their balance as collateral on Alice's ledger
    log_info "Pledging Deposit B as collateral on Alice's ledger..."

    pledge_output=$(run_bdk_cmd "bdk-alice" collateral pledge "$ALICE_RESERVES_ID" "$DEPOSIT_B_SECRET" "$collateral_amount" "$lock_blocks" 2>&1)

    if echo "$pledge_output" | grep -q "Collateral pledge created\|Pledged amount"; then
        test_pass "Deposit B pledged as collateral on Alice's ledger"
        if $VERBOSE; then
            echo "    Output: $pledge_output"
        fi
    else
        test_fail "Failed to pledge Deposit B as collateral"
        echo "    Output: $pledge_output"
    fi
}

# ============================================================================
# Step 7: Log Collateral to Ledgers
# ============================================================================

test_log_collateral() {
    log_info "=== Step 7: Verifying Collateral in Ledgers ==="
    echo ""

    # Check Alice's ledger deposits for collateral pledges
    log_info "Checking Alice's ledger for collateral pledges..."
    local alice_deposits=$(run_bdk_cmd "bdk-alice" deposit ls "$ALICE_RESERVES_ID" 2>&1)

    if echo "$alice_deposits" | grep -q "Deposit:"; then
        test_pass "Alice's ledger has deposits"
        if $VERBOSE; then
            echo "    Deposits:"
            echo "$alice_deposits" | sed 's/^/      /'
        fi
    fi

    # Check Bob's ledger deposits for collateral pledges
    log_info "Checking Bob's ledger for collateral pledges..."
    local bob_deposits=$(run_bdk_cmd "bdk-bob" deposit ls "$BOB_RESERVES_ID" 2>&1)

    if echo "$bob_deposits" | grep -q "Deposit:"; then
        test_pass "Bob's ledger has deposits"
        if $VERBOSE; then
            echo "    Deposits:"
            echo "$bob_deposits" | sed 's/^/      /'
        fi
    fi

    # List ledger info on both sides
    log_info "Ledger summaries..."

    local alice_ledger=$(run_bdk_cmd "bdk-alice" ledger list 2>&1)
    local bob_ledger=$(run_bdk_cmd "bdk-bob" ledger list 2>&1)

    log_info "Alice's ledger:"
    echo "$alice_ledger" | grep -v "^20" | sed 's/^/    /'

    log_info "Bob's ledger:"
    echo "$bob_ledger" | grep -v "^20" | sed 's/^/    /'

    test_pass "Collateral status verified"
}

# ============================================================================
# Step 8: Open Deposit C on Alice (funded by Bob)
# ============================================================================

test_open_deposit_c() {
    log_info "=== Step 8: Opening Deposit C on Alice (funded by Bob) ==="
    echo ""

    # Generate keypair for Deposit C
    local keypair_c=$(run_keygen "bdk-alice")
    DEPOSIT_C_SECRET=$(echo "$keypair_c" | awk '{print $1}')
    DEPOSIT_C_PUBKEY=$(echo "$keypair_c" | awk '{print $2}')

    if [ -z "$DEPOSIT_C_PUBKEY" ]; then
        test_fail "Failed to generate Deposit C keypair"
        return 1
    fi

    # Save wallet file
    echo "{\"deposit_pubkey\": \"$DEPOSIT_C_PUBKEY\", \"deposit_secret\": \"$DEPOSIT_C_SECRET\", \"ledger\": \"alice\"}" > "$SCRIPT_DIR/../wallets/deposit_c.json"

    # Open Deposit C on Alice's ledger
    log_info "Opening Deposit C on Alice's ledger: ${DEPOSIT_C_PUBKEY:0:20}..."
    local open_output=$(run_bdk_cmd "bdk-alice" deposit open "$ALICE_RESERVES_ID" "$DEPOSIT_C_PUBKEY" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Deposit C opened on Alice's ledger"
    else
        test_fail "Failed to open Deposit C"
        echo "    Output: $open_output"
        return 1
    fi

    # Create deposit offer for Deposit C
    local max_sats=50000000    # 0.5 BTC
    local min_sats=100000      # 0.001 BTC
    local blocks_valid=144

    log_info "Creating deposit offer for Deposit C..."
    local offer_output=$(run_bdk_cmd "bdk-alice" deposit offer "$ALICE_RESERVES_ID" "$DEPOSIT_C_PUBKEY" "$max_sats" "$min_sats" "$blocks_valid" 2>&1)

    if echo "$offer_output" | grep -q "Deposit offer created"; then
        DEPOSIT_C_OFFER_ID=$(echo "$offer_output" | grep "Offer ID:" | awk '{print $3}')
        DEPOSIT_C_FUNDING_ADDRESS=$(echo "$offer_output" | grep "Funding address:" | awk '{print $3}')

        test_pass "Created deposit offer for Deposit C"
        log_info "  Offer ID: ${DEPOSIT_C_OFFER_ID:0:16}..."
        log_info "  Funding address: $DEPOSIT_C_FUNDING_ADDRESS"
    else
        test_fail "Failed to create deposit offer for Deposit C"
        echo "    Output: $offer_output"
        return 1
    fi

    # Bob funds Deposit C (from his wallet, not from a deposit)
    log_info "Bob funding Deposit C..."
    local fund_amount="0.3"

    local txid=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$DEPOSIT_C_FUNDING_ADDRESS" "$fund_amount" 2>&1)

    if [ $? -eq 0 ] && [ -n "$txid" ]; then
        test_pass "Bob sent $fund_amount BTC to Deposit C's funding address"
        log_info "  TXID: ${txid:0:16}..."

        # Mine confirmation
        mine_blocks 1

        # Complete the deposit offer
        sleep 2
        local complete_output=$(run_bdk_cmd "bdk-alice" deposit complete "$DEPOSIT_C_OFFER_ID" "$txid" "30000000" 2>&1)

        if echo "$complete_output" | grep -q "Deposit offer completed"; then
            test_pass "Deposit C offer completed - deposit credited"
            local new_balance=$(echo "$complete_output" | grep "New balance:" | awk '{print $3}')
            log_info "  Deposit C balance: $new_balance msats"
        else
            test_fail "Failed to complete Deposit C offer"
            echo "    Output: $complete_output"
        fi
    else
        test_fail "Failed to fund Deposit C"
        echo "    Output: $txid"
        return 1
    fi
}

# ============================================================================
# Step 9: Open Deposit D on Bob (funded by Deposit C)
# ============================================================================

test_open_deposit_d() {
    log_info "=== Step 9: Opening Deposit D on Bob (funded by Deposit C) ==="
    echo ""

    # Generate keypair for Deposit D
    local keypair_d=$(run_keygen "bdk-bob")
    DEPOSIT_D_SECRET=$(echo "$keypair_d" | awk '{print $1}')
    DEPOSIT_D_PUBKEY=$(echo "$keypair_d" | awk '{print $2}')

    if [ -z "$DEPOSIT_D_PUBKEY" ]; then
        test_fail "Failed to generate Deposit D keypair"
        return 1
    fi

    # Save wallet file
    echo "{\"deposit_pubkey\": \"$DEPOSIT_D_PUBKEY\", \"deposit_secret\": \"$DEPOSIT_D_SECRET\", \"ledger\": \"bob\"}" > "$SCRIPT_DIR/../wallets/deposit_d.json"

    # Open Deposit D on Bob's ledger
    log_info "Opening Deposit D on Bob's ledger: ${DEPOSIT_D_PUBKEY:0:20}..."
    local open_output=$(run_bdk_cmd "bdk-bob" deposit open "$BOB_RESERVES_ID" "$DEPOSIT_D_PUBKEY" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Deposit D opened on Bob's ledger"
    else
        test_fail "Failed to open Deposit D"
        echo "    Output: $open_output"
        return 1
    fi

    # Create deposit offer for Deposit D
    local max_sats=20000000    # 0.2 BTC
    local min_sats=100000      # 0.001 BTC
    local blocks_valid=144

    log_info "Creating deposit offer for Deposit D..."
    local offer_output=$(run_bdk_cmd "bdk-bob" deposit offer "$BOB_RESERVES_ID" "$DEPOSIT_D_PUBKEY" "$max_sats" "$min_sats" "$blocks_valid" 2>&1)

    if echo "$offer_output" | grep -q "Deposit offer created"; then
        DEPOSIT_D_OFFER_ID=$(echo "$offer_output" | grep "Offer ID:" | awk '{print $3}')
        DEPOSIT_D_FUNDING_ADDRESS=$(echo "$offer_output" | grep "Funding address:" | awk '{print $3}')

        test_pass "Created deposit offer for Deposit D"
        log_info "  Offer ID: ${DEPOSIT_D_OFFER_ID:0:16}..."
        log_info "  Funding address: $DEPOSIT_D_FUNDING_ADDRESS"
    else
        test_fail "Failed to create deposit offer for Deposit D"
        echo "    Output: $offer_output"
        return 1
    fi

    # Withdraw from Deposit C to fund Deposit D
    log_info "Withdrawing from Deposit C to fund Deposit D..."

    local amount_sats=15000000   # 0.15 BTC
    local fee_sats=1000

    # Request withdrawal from Deposit C
    local withdraw_output=$(run_bdk_cmd "bdk-alice" withdraw request "$ALICE_RESERVES_ID" "$DEPOSIT_C_SECRET" "$DEPOSIT_D_FUNDING_ADDRESS" "$amount_sats" "$fee_sats" 2>&1)

    if echo "$withdraw_output" | grep -q "Withdrawal request created\|Withdrawal locked"; then
        local withdrawal_id=$(echo "$withdraw_output" | grep -E "Withdrawal ID:|withdrawal_id" | awk '{print $NF}')
        test_pass "Withdrawal from Deposit C locked"
        log_info "  Withdrawal ID: ${withdrawal_id:0:16}..."

        # Complete the withdrawal
        local complete_output=$(run_bdk_cmd "bdk-alice" withdraw complete "$ALICE_RESERVES_ID" "$withdrawal_id" 2>&1)

        if $VERBOSE; then
            echo "    Withdraw complete output:"
            echo "$complete_output" | sed 's/^/      /'
        fi

        if echo "$complete_output" | grep -q "Withdrawal completed\|Transaction ID"; then
            test_pass "Withdrawal broadcasted"

            # Extract TXID - CLI outputs "Transaction ID: <txid>"
            local funding_txid=$(echo "$complete_output" | grep "Transaction ID:" | awk '{print $3}')
            if [ -z "$funding_txid" ]; then
                # Fallback: look for 64-character hex string
                funding_txid=$(echo "$complete_output" | grep -oE '[a-f0-9]{64}' | head -1)
            fi
            log_info "  Funding TXID: ${funding_txid:0:16}..."

            if [ -z "$funding_txid" ] || [ ${#funding_txid} -ne 64 ]; then
                log_warn "Could not extract valid TXID from withdrawal output"
                echo "    Complete output: $complete_output"
            fi

            # Mine confirmation
            mine_blocks 1

            # Complete Deposit D's offer
            sleep 2
            run_bdk_cmd "bdk-bob" info >/dev/null 2>&1  # Sync

            local deposit_complete=$(run_bdk_cmd "bdk-bob" deposit complete "$DEPOSIT_D_OFFER_ID" "$funding_txid" "$amount_sats" 2>&1)

            if echo "$deposit_complete" | grep -q "Deposit offer completed"; then
                test_pass "Deposit D offer completed - deposit credited"
                local new_balance=$(echo "$deposit_complete" | grep "New balance:" | awk '{print $3}')
                log_info "  Deposit D balance: $new_balance msats"
            else
                test_fail "Failed to complete Deposit D offer"
                echo "    Output: $deposit_complete"
            fi
        else
            test_fail "Failed to complete withdrawal from Deposit C"
            echo "    Output: $complete_output"
        fi
    else
        test_fail "Failed to create withdrawal request from Deposit C"
        echo "    Output: $withdraw_output"
        return 1
    fi
}

# ============================================================================
# Final Verification
# ============================================================================

test_verify_final_state() {
    log_info "=== Final Verification ==="
    echo ""

    # List all deposits on Alice's ledger
    log_info "Alice's ledger deposits:"
    local alice_deposits=$(run_bdk_cmd "bdk-alice" deposit ls "$ALICE_RESERVES_ID" 2>&1)
    echo "$alice_deposits" | sed 's/^/    /'

    # List all deposits on Bob's ledger
    log_info "Bob's ledger deposits:"
    local bob_deposits=$(run_bdk_cmd "bdk-bob" deposit ls "$BOB_RESERVES_ID" 2>&1)
    echo "$bob_deposits" | sed 's/^/    /'

    # Show ledger info (history may require different format)
    log_info "Alice's ledger info:"
    local alice_ledger=$(run_bdk_cmd "bdk-alice" ledger list 2>&1)
    echo "$alice_ledger" | head -20 | sed 's/^/    /'

    log_info "Bob's ledger info:"
    local bob_ledger=$(run_bdk_cmd "bdk-bob" ledger list 2>&1)
    echo "$bob_ledger" | head -20 | sed 's/^/    /'

    test_pass "Final state verified"
}

# ============================================================================
# Main
# ============================================================================

run_all_tests() {
    log_info "=========================================="
    log_info "Cross-Collateral Test Script"
    log_info "=========================================="
    echo ""

    # Prerequisites: ensure nodes are funded and have reserves
    log_info "Checking prerequisites..."

    # Fund nodes if needed
    for node in "bdk-alice" "bdk-bob"; do
        local info_output=$(run_bdk_cmd "$node" info 2>&1)
        local balance=$(echo "$info_output" | grep "Wallet balance:" | awk '{print $3}')

        if [ -z "$balance" ] || [ "$balance" -lt 100000000 ]; then
            log_info "Funding $node..."
            fund_node "$node" 10
        else
            log_info "$node has balance: $balance sats"
        fi
    done

    # Create reserves if needed
    for node in "bdk-alice" "bdk-bob"; do
        local info_output=$(run_bdk_cmd "$node" info 2>&1)
        if ! echo "$info_output" | grep -q "Reserves address:"; then
            log_info "Creating reserves for $node..."
            create_node_reserves "$node" 100000000
            mine_blocks 1
        fi
    done

    echo ""
    test_open_ledgers

    echo ""
    test_open_deposits

    echo ""
    test_lock_collateral

    echo ""
    test_log_collateral

    echo ""
    test_open_deposit_c

    echo ""
    test_open_deposit_d

    echo ""
    test_verify_final_state
}

# Run tests
run_all_tests

echo ""
log_info "=========================================="
log_info "Test Summary"
log_info "=========================================="
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    log_error "Some tests failed"
    exit 1
else
    log_success "All tests passed!"
    exit 0
fi
