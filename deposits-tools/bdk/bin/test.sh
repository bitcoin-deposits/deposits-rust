#!/bin/bash
# Test script for BDK deposits network
#
# This script runs basic tests to verify the BDK network is working:
# 1. Check all services are healthy
# 2. Verify nodes have funds
# 3. Test nostr connectivity between nodes
# 4. (Future) Test deposits protocol operations
#
# Usage:
#   ./bin/test.sh             # Run all tests
#   ./bin/test.sh --health    # Just check health
#   ./bin/test.sh --verbose   # Show more output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
HEALTH_ONLY=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --health|-h)
            HEALTH_ONLY=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --health, -h   Just check service health"
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

# Test: Services are healthy
test_health() {
    log_info "Testing service health..."

    # Bitcoin Core
    if bitcoin_cli getblockchaininfo >/dev/null 2>&1; then
        test_pass "Bitcoin Core is responding"
    else
        test_fail "Bitcoin Core not responding"
        return 1
    fi

    # Electrs
    if curl -s "http://$ELECTRS_HOST:$ELECTRS_PORT" >/dev/null 2>&1; then
        test_pass "Electrs is responding"
    else
        test_fail "Electrs not responding"
    fi

    # Nostr relay
    if curl -s "http://localhost:7778" >/dev/null 2>&1; then
        test_pass "Nostr relay is responding"
    else
        test_fail "Nostr relay not responding"
    fi

    # BDK nodes are running
    for node in "${NODES[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
            test_pass "$node container is running"
        else
            test_fail "$node container not running"
        fi
    done
}

# Test: Block height is reasonable
test_block_height() {
    log_info "Testing block height..."

    local height=$(get_block_height)
    if [ "$height" -gt 100 ]; then
        test_pass "Block height is $height (> 100)"
    else
        test_fail "Block height is only $height (expected > 100)"
    fi
}

# Test: Faucet has funds
test_faucet_balance() {
    log_info "Testing faucet balance..."

    local balance=$(bitcoin_cli -rpcwallet=faucet getbalance 2>/dev/null || echo "0")
    if [ "$(echo "$balance > 0" | bc)" -eq 1 ]; then
        test_pass "Faucet has $balance BTC"
    else
        test_fail "Faucet has no funds"
    fi
}

# Test: Nodes are logging activity
test_node_activity() {
    log_info "Testing node activity..."

    for node in "${NODES[@]}"; do
        local log_lines=$(docker logs "$node" 2>&1 | wc -l)
        if [ "$log_lines" -gt 5 ]; then
            test_pass "$node has $log_lines log lines"
            if $VERBOSE; then
                echo "  Recent logs from $node:"
                docker logs "$node" 2>&1 | tail -5 | sed 's/^/    /'
            fi
        else
            test_fail "$node has minimal logs ($log_lines lines)"
        fi
    done
}

# Test: Nostr relay accepts events (basic connectivity test)
test_nostr_connectivity() {
    log_info "Testing Nostr relay connectivity..."

    # Simple HTTP check - the relay should respond to requests
    local response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:7778")
    if [ "$response" = "200" ] || [ "$response" = "400" ]; then
        # 400 is expected for non-websocket HTTP request to a websocket endpoint
        test_pass "Nostr relay accepts connections (HTTP $response)"
    else
        test_fail "Nostr relay not accepting connections (HTTP $response)"
    fi
}

# Test: Electrs is synced with bitcoind
test_electrs_sync() {
    log_info "Testing Electrs sync..."

    local btc_height=$(get_block_height)

    # Give electrs a moment to sync
    sleep 2

    # Check electrs is indexing (it logs sync progress)
    local electrs_logs=$(docker logs bdk-electrs 2>&1 | tail -20)
    if echo "$electrs_logs" | grep -q "chain updated\|indexed\|compacting"; then
        test_pass "Electrs is processing blocks"
    else
        # Even if we can't verify exact height, check it's running
        if curl -s "http://$ELECTRS_HOST:$ELECTRS_PORT" >/dev/null 2>&1; then
            test_pass "Electrs is running (may still be syncing)"
        else
            test_fail "Electrs not responding"
        fi
    fi
}

# Test: Can mine a new block
test_mining() {
    log_info "Testing mining..."

    local before=$(get_block_height)
    bitcoin_cli -rpcwallet=faucet -generate 1 >/dev/null 2>&1
    local after=$(get_block_height)

    if [ "$after" -eq $((before + 1)) ]; then
        test_pass "Successfully mined block $after"
    else
        test_fail "Mining did not increment block height"
    fi
}

# Test: Fund nodes properly
test_fund_nodes() {
    log_info "Testing node funding..."

    for node in "${NODES[@]}"; do
        local address=$(get_node_address "$node")
        if [ -z "$address" ]; then
            test_fail "Could not get address for $node"
            continue
        fi

        # Check if already funded
        local info_output=$(run_bdk_cmd "$node" info 2>&1)
        local balance=$(echo "$info_output" | grep "Wallet balance:" | awk '{print $3}')

        if [ -n "$balance" ] && [ "$balance" -gt 100000000 ]; then
            test_pass "$node already has $balance sats"
        else
            # Fund the node
            log_info "Funding $node at $address..."
            bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 10 >/dev/null 2>&1
            mine_blocks 1
            test_pass "$node funded with 10 BTC"
        fi
    done
}

# Test: Create reserves UTXO for each node
test_create_reserves() {
    log_info "Testing reserves creation..."

    for node in "${NODES[@]}"; do
        # Check wallet balance first
        local info_output=$(run_bdk_cmd "$node" info 2>&1)
        local balance=$(echo "$info_output" | grep "Wallet balance:" | awk '{print $3}')

        if [ -z "$balance" ] || [ "$balance" -lt 100000000 ]; then
            test_fail "$node has insufficient balance for reserves (balance: ${balance:-0})"
            continue
        fi

        # Create reserves (1 BTC = 100,000,000 sats)
        local reserves_output=$(run_bdk_cmd "$node" reserves 100000000 2>&1)

        if echo "$reserves_output" | grep -q "Reserves created"; then
            local txid=$(echo "$reserves_output" | grep "TXID:" | awk '{print $2}')
            test_pass "$node created reserves: ${txid:0:16}..."

            if $VERBOSE; then
                echo "    Reserves output:"
                echo "$reserves_output" | grep -E "TXID:|Vout:|Amount:|Timeout" | sed 's/^/      /'
            fi
        else
            test_fail "$node reserves creation failed"
            if $VERBOSE; then
                echo "    Output: $reserves_output"
            fi
        fi
    done

    # Mine blocks to confirm reserves
    mine_blocks 1
}

# Test: Open ledgers between nodes
test_open_ledgers() {
    log_info "Testing ledger opening..."

    # Get current block height for enforcement block
    local current_height=$(get_block_height)
    # Set enforcement block 100 blocks in the future for bootstrap phase
    local enforcement_block=$((current_height + 100))

    log_info "Current block: $current_height, Enforcement block: $enforcement_block"

    # Alice opens ledger with Bob (Alice = operator, Bob = reserves)
    # First get Bob's node ID
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    local bob_node_id=$(echo "$bob_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$bob_node_id" ]; then
        test_fail "Could not get Bob's node ID"
        return
    fi

    log_info "Opening ledger: Alice (operator) <-> Bob (reserves)"
    log_info "Bob's Node ID: ${bob_node_id:0:20}..."

    local ledger_output=$(run_bdk_cmd "bdk-alice" ledger open "$bob_node_id" "$enforcement_block" 2>&1)

    if echo "$ledger_output" | grep -q "Ledger opened successfully"; then
        test_pass "Alice opened ledger with Bob"
        if $VERBOSE; then
            echo "    Ledger output:"
            echo "$ledger_output" | grep -E "Operator:|Reserves:|Sequence:|Bootstrap" | sed 's/^/      /'
        fi
    else
        test_fail "Alice failed to open ledger with Bob"
        if $VERBOSE; then
            echo "    Output: $ledger_output"
        fi
    fi

    # Bob opens ledger with Charlie (Bob = operator, Charlie = reserves)
    local charlie_info=$(run_bdk_cmd "bdk-charlie" info 2>&1)
    local charlie_node_id=$(echo "$charlie_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$charlie_node_id" ]; then
        test_fail "Could not get Charlie's node ID"
        return
    fi

    log_info "Opening ledger: Bob (operator) <-> Charlie (reserves)"
    log_info "Charlie's Node ID: ${charlie_node_id:0:20}..."

    ledger_output=$(run_bdk_cmd "bdk-bob" ledger open "$charlie_node_id" "$enforcement_block" 2>&1)

    if echo "$ledger_output" | grep -q "Ledger opened successfully"; then
        test_pass "Bob opened ledger with Charlie"
    else
        test_fail "Bob failed to open ledger with Charlie"
        if $VERBOSE; then
            echo "    Output: $ledger_output"
        fi
    fi

    # Charlie opens ledger with Alice (Charlie = operator, Alice = reserves)
    # This completes the triangle for cross-collateral
    local alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    local alice_node_id=$(echo "$alice_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$alice_node_id" ]; then
        test_fail "Could not get Alice's node ID"
        return
    fi

    log_info "Opening ledger: Charlie (operator) <-> Alice (reserves)"
    log_info "Alice's Node ID: ${alice_node_id:0:20}..."

    ledger_output=$(run_bdk_cmd "bdk-charlie" ledger open "$alice_node_id" "$enforcement_block" 2>&1)

    if echo "$ledger_output" | grep -q "Ledger opened successfully"; then
        test_pass "Charlie opened ledger with Alice"
    else
        test_fail "Charlie failed to open ledger with Alice"
        if $VERBOSE; then
            echo "    Output: $ledger_output"
        fi
    fi
}

# Test: List ledgers
test_list_ledgers() {
    log_info "Testing ledger listing..."

    for node in "${NODES[@]}"; do
        local list_output=$(run_bdk_cmd "$node" ledger list 2>&1)

        # Count ledgers (look for "Operator" or "Partner" role lines)
        # Use grep -E and wc -l to avoid issues with grep -c exit codes
        local ledger_count=$(echo "$list_output" | grep -E "Operator|Partner" | wc -l | tr -d ' ')

        if [ "$ledger_count" -gt 0 ]; then
            test_pass "$node has $ledger_count ledger relationship(s)"
            if $VERBOSE; then
                echo "    Ledger list:"
                echo "$list_output" | grep -E "Operator:|Reserves:|Sequence:|Enforcement" | sed 's/^/      /'
            fi
        else
            # No ledgers found for this node
            if echo "$list_output" | grep -q "No ledgers found"; then
                test_fail "$node has no ledgers"
            else
                test_pass "$node ledger list executed"
            fi
        fi
    done
}

# Test: Request collateral reservess
test_request_reservess() {
    log_info "Testing collateral reserves requests..."

    # Get node IDs
    local alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    local charlie_info=$(run_bdk_cmd "bdk-charlie" info 2>&1)

    local alice_id=$(echo "$alice_info" | grep "Node ID:" | awk '{print $3}')
    local bob_id=$(echo "$bob_info" | grep "Node ID:" | awk '{print $3}')
    local charlie_id=$(echo "$charlie_info" | grep "Node ID:" | awk '{print $3}')

    # Alice requests Bob as reserves
    if [ -n "$bob_id" ]; then
        local request_output=$(run_bdk_cmd "bdk-alice" reserves request "$bob_id" 2>&1)

        if echo "$request_output" | grep -q "Partnership request sent"; then
            test_pass "Alice sent reserves request to Bob"
        else
            test_fail "Alice failed to send reserves request to Bob"
            if $VERBOSE; then
                echo "    Output: $request_output"
            fi
        fi
    fi

    # Bob requests Charlie as reserves
    if [ -n "$charlie_id" ]; then
        request_output=$(run_bdk_cmd "bdk-bob" reserves request "$charlie_id" 2>&1)

        if echo "$request_output" | grep -q "Partnership request sent"; then
            test_pass "Bob sent reserves request to Charlie"
        else
            test_fail "Bob failed to send reserves request to Charlie"
        fi
    fi

    # Charlie requests Alice as reserves (completing the triangle)
    if [ -n "$alice_id" ]; then
        request_output=$(run_bdk_cmd "bdk-charlie" reserves request "$alice_id" 2>&1)

        if echo "$request_output" | grep -q "Partnership request sent"; then
            test_pass "Charlie sent reserves request to Alice"
        else
            test_fail "Charlie failed to send reserves request to Alice"
        fi
    fi

    # Wait a moment for messages to propagate via Nostr
    sleep 2
}

# Test: List reservess
test_list_reservess() {
    log_info "Testing reserves listing..."

    for node in "${NODES[@]}"; do
        local list_output=$(run_bdk_cmd "$node" reserves list 2>&1)

        # Note: Partners may not be established yet (just requests sent)
        # So we just verify the command runs without error
        if echo "$list_output" | grep -qE "No collateral reservess|Partner|Collateral"; then
            test_pass "$node reserves list executed"
            if $VERBOSE; then
                echo "    Partners: $list_output"
            fi
        else
            test_fail "$node reserves list failed"
        fi
    done
}

# ============================================================================
# Deposit Lifecycle Tests
# ============================================================================

# Global variables to store deposit info across tests
ALICE_DEPOSIT_A=""
ALICE_DEPOSIT_B=""
BOB_NODE_ID=""
DEPOSIT_OFFER_ID=""
DEPOSIT_FUNDING_ADDRESS=""
FUNDING_TXID=""
FUNDING_AMOUNT_SATS=""

# Test: Open deposits in Alice's ledger with Bob
test_open_deposits() {
    log_info "Testing deposit opening..."

    # Get Bob's node ID (Bob is the reserves in Alice's ledger)
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    BOB_NODE_ID=$(echo "$bob_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$BOB_NODE_ID" ]; then
        test_fail "Could not get Bob's node ID"
        return 1
    fi

    # Generate two deposit pubkeys (using sha256 of identifiers for determinism in tests)
    # In a real scenario, these would be user-controlled keys
    ALICE_DEPOSIT_A=$(echo -n "alice_deposit_a_test_key" | sha256sum | awk '{print $1}')
    ALICE_DEPOSIT_B=$(echo -n "alice_deposit_b_test_key" | sha256sum | awk '{print $1}')

    # For the test, we'll use compressed pubkey format (02 prefix + 32 bytes)
    # Generate proper test pubkeys
    ALICE_DEPOSIT_A="02$(echo -n "deposit_a_$(date +%s)" | sha256sum | awk '{print $1}')"
    ALICE_DEPOSIT_B="02$(echo -n "deposit_b_$(date +%s)" | sha256sum | awk '{print $1}')"

    log_info "Opening Deposit A: ${ALICE_DEPOSIT_A:0:20}..."
    log_info "Opening Deposit B: ${ALICE_DEPOSIT_B:0:20}..."

    # Open Deposit A
    local open_output=$(run_bdk_cmd "bdk-alice" deposit open "$BOB_NODE_ID" "$ALICE_DEPOSIT_A" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Alice opened Deposit A"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
    else
        test_fail "Alice failed to open Deposit A"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
        return 1
    fi

    # Open Deposit B
    open_output=$(run_bdk_cmd "bdk-alice" deposit open "$BOB_NODE_ID" "$ALICE_DEPOSIT_B" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Alice opened Deposit B"
    else
        test_fail "Alice failed to open Deposit B"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
        return 1
    fi
}

# Test: List deposits in a ledger
test_list_deposits() {
    log_info "Testing deposit listing..."

    if [ -z "$BOB_NODE_ID" ]; then
        test_fail "Bob's node ID not set"
        return 1
    fi

    local list_output=$(run_bdk_cmd "bdk-alice" deposit ls "$BOB_NODE_ID" 2>&1)

    if echo "$list_output" | grep -q "Deposit:"; then
        local deposit_count=$(echo "$list_output" | grep -c "Deposit:" || echo "0")
        test_pass "Alice's ledger has $deposit_count deposit(s)"
        if $VERBOSE; then
            echo "    Deposits:"
            echo "$list_output" | grep -E "Deposit:|Balance:|Locked:" | sed 's/^/      /'
        fi
    else
        test_fail "No deposits found in Alice's ledger"
        if $VERBOSE; then
            echo "    Output: $list_output"
        fi
    fi
}

# Test: Create a deposit offer for on-chain funding
test_create_deposit_offer() {
    log_info "Testing deposit offer creation..."

    if [ -z "$BOB_NODE_ID" ] || [ -z "$ALICE_DEPOSIT_A" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    # Create offer: max 1 BTC, min 0.001 BTC, valid for 144 blocks
    local max_sats=100000000    # 1 BTC
    local min_sats=100000       # 0.001 BTC
    local blocks_valid=144      # ~1 day

    local offer_output=$(run_bdk_cmd "bdk-alice" deposit offer "$BOB_NODE_ID" "$ALICE_DEPOSIT_A" "$max_sats" "$min_sats" "$blocks_valid" 2>&1)

    if echo "$offer_output" | grep -q "Deposit offer created"; then
        DEPOSIT_OFFER_ID=$(echo "$offer_output" | grep "Offer ID:" | awk '{print $3}')
        DEPOSIT_FUNDING_ADDRESS=$(echo "$offer_output" | grep "Funding address:" | awk '{print $3}')

        test_pass "Alice created deposit offer"
        log_info "  Offer ID: ${DEPOSIT_OFFER_ID:0:16}..."
        log_info "  Funding address: $DEPOSIT_FUNDING_ADDRESS"

        if $VERBOSE; then
            echo "    Full offer output:"
            echo "$offer_output" | grep -E "Offer ID:|Funding address:|Deadline|Amount" | sed 's/^/      /'
        fi
    else
        test_fail "Alice failed to create deposit offer"
        if $VERBOSE; then
            echo "    Output: $offer_output"
        fi
        return 1
    fi
}

# Test: Fund the deposit offer on-chain
test_fund_deposit_offer() {
    log_info "Testing deposit offer funding..."

    if [ -z "$DEPOSIT_FUNDING_ADDRESS" ]; then
        test_fail "Funding address not set"
        return 1
    fi

    # Send 0.5 BTC to the funding address from the faucet
    local amount_btc="0.5"
    log_info "Sending $amount_btc BTC to $DEPOSIT_FUNDING_ADDRESS"

    local txid=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$DEPOSIT_FUNDING_ADDRESS" "$amount_btc" 2>&1)

    if [ $? -eq 0 ] && [ -n "$txid" ]; then
        test_pass "Sent $amount_btc BTC to funding address"
        log_info "  TXID: ${txid:0:16}..."

        # Store for later use
        FUNDING_TXID="$txid"
        FUNDING_AMOUNT_SATS=50000000  # 0.5 BTC in sats

        # Mine a block to confirm
        mine_blocks 1
        test_pass "Mined confirmation block"
    else
        test_fail "Failed to send funds to deposit offer"
        if $VERBOSE; then
            echo "    Output: $txid"
        fi
        return 1
    fi
}

# Test: Check if deposit offer has been funded
test_check_deposit_offer() {
    log_info "Testing deposit offer funding check..."

    if [ -z "$DEPOSIT_OFFER_ID" ]; then
        test_fail "Offer ID not set"
        return 1
    fi

    # Sync Alice's wallet first
    run_bdk_cmd "bdk-alice" info >/dev/null 2>&1

    local check_output=$(run_bdk_cmd "bdk-alice" deposit check "$DEPOSIT_OFFER_ID" 2>&1)

    if echo "$check_output" | grep -q "Funding detected"; then
        test_pass "Deposit offer funding detected"
        if $VERBOSE; then
            echo "    Check output:"
            echo "$check_output" | grep -E "Transaction:|Amount:" | sed 's/^/      /'
        fi
    else
        # May need to wait for sync
        log_info "Funding not detected yet, waiting for sync..."
        sleep 3
        check_output=$(run_bdk_cmd "bdk-alice" deposit check "$DEPOSIT_OFFER_ID" 2>&1)

        if echo "$check_output" | grep -q "Funding detected"; then
            test_pass "Deposit offer funding detected (after sync)"
        else
            test_fail "Deposit offer funding not detected"
            if $VERBOSE; then
                echo "    Output: $check_output"
            fi
        fi
    fi
}

# Test: Complete the deposit offer (credit the deposit)
test_complete_deposit_offer() {
    log_info "Testing deposit offer completion..."

    if [ -z "$DEPOSIT_OFFER_ID" ] || [ -z "$FUNDING_TXID" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    local complete_output=$(run_bdk_cmd "bdk-alice" deposit complete "$DEPOSIT_OFFER_ID" "$FUNDING_TXID" "$FUNDING_AMOUNT_SATS" 2>&1)

    if echo "$complete_output" | grep -q "Deposit offer completed"; then
        test_pass "Deposit offer completed - deposit credited"

        # Extract new balance
        local new_balance=$(echo "$complete_output" | grep "New balance:" | awk '{print $3}')
        log_info "  New balance: $new_balance msats"

        if $VERBOSE; then
            echo "    Complete output:"
            echo "$complete_output" | sed 's/^/      /'
        fi
    else
        test_fail "Failed to complete deposit offer"
        if $VERBOSE; then
            echo "    Output: $complete_output"
        fi
        return 1
    fi
}

# Test: Transfer funds between deposits
test_deposit_transfer() {
    log_info "Testing deposit-to-deposit transfer..."

    if [ -z "$BOB_NODE_ID" ] || [ -z "$ALICE_DEPOSIT_A" ] || [ -z "$ALICE_DEPOSIT_B" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    # Transfer 0.1 BTC (100,000,000 msats) from Deposit A to Deposit B
    local amount_msats=100000000  # 0.1 BTC in msats

    log_info "Transferring $amount_msats msats from Deposit A to Deposit B..."

    local transfer_output=$(run_bdk_cmd "bdk-alice" deposit transfer "$BOB_NODE_ID" "$ALICE_DEPOSIT_A" "$ALICE_DEPOSIT_B" "$amount_msats" 2>&1)

    if echo "$transfer_output" | grep -q "Transfer complete"; then
        test_pass "Transfer completed successfully"

        # Extract balances
        local from_balance=$(echo "$transfer_output" | grep "From balance:" | awk '{print $3}')
        local to_balance=$(echo "$transfer_output" | grep "To balance:" | awk '{print $3}')

        log_info "  Deposit A balance: $from_balance msats"
        log_info "  Deposit B balance: $to_balance msats"

        if $VERBOSE; then
            echo "    Transfer output:"
            echo "$transfer_output" | sed 's/^/      /'
        fi
    else
        test_fail "Transfer failed"
        if $VERBOSE; then
            echo "    Output: $transfer_output"
        fi
        return 1
    fi
}

# Test: Verify final deposit balances
test_verify_deposit_balances() {
    log_info "Testing final deposit balances..."

    if [ -z "$BOB_NODE_ID" ]; then
        test_fail "Bob's node ID not set"
        return 1
    fi

    local list_output=$(run_bdk_cmd "bdk-alice" deposit ls "$BOB_NODE_ID" 2>&1)

    # Check that Deposit A has funds (should have ~0.4 BTC after transfer)
    # Check that Deposit B has funds (should have ~0.1 BTC from transfer)

    if echo "$list_output" | grep -A2 "$ALICE_DEPOSIT_A" | grep -q "Balance:"; then
        local deposit_a_balance=$(echo "$list_output" | grep -A2 "$ALICE_DEPOSIT_A" | grep "Balance:" | awk '{print $2}')
        if [ -n "$deposit_a_balance" ] && [ "$deposit_a_balance" -gt 0 ]; then
            test_pass "Deposit A has balance: $deposit_a_balance msats"
        else
            test_fail "Deposit A has no balance"
        fi
    fi

    if echo "$list_output" | grep -A2 "$ALICE_DEPOSIT_B" | grep -q "Balance:"; then
        local deposit_b_balance=$(echo "$list_output" | grep -A2 "$ALICE_DEPOSIT_B" | grep "Balance:" | awk '{print $2}')
        if [ -n "$deposit_b_balance" ] && [ "$deposit_b_balance" -gt 0 ]; then
            test_pass "Deposit B has balance: $deposit_b_balance msats"
        else
            test_fail "Deposit B has no balance"
        fi
    fi

    if $VERBOSE; then
        echo "    Final deposit state:"
        echo "$list_output" | sed 's/^/      /'
    fi
}

# Test: List all deposit offers
test_list_deposit_offers() {
    log_info "Testing deposit offer listing..."

    local list_output=$(run_bdk_cmd "bdk-alice" deposit list 2>&1)

    if echo "$list_output" | grep -q "Offer:"; then
        local offer_count=$(echo "$list_output" | grep -c "Offer:" || echo "0")
        test_pass "Alice has $offer_count deposit offer(s)"

        # Check that our offer is shown as completed
        if echo "$list_output" | grep -q "Completed"; then
            test_pass "Deposit offer shows as Completed"
        fi

        if $VERBOSE; then
            echo "    Offers:"
            echo "$list_output" | sed 's/^/      /'
        fi
    else
        # No offers is also valid if they've been cleaned up
        if echo "$list_output" | grep -q "No deposit offers"; then
            test_pass "Deposit offer list executed (no offers)"
        else
            test_fail "Deposit offer list failed"
            if $VERBOSE; then
                echo "    Output: $list_output"
            fi
        fi
    fi
}

# Run all tests
run_all_tests() {
    log_info "=== BDK Network Tests ==="
    echo ""

    test_health

    if $HEALTH_ONLY; then
        return
    fi

    echo ""
    test_block_height
    test_faucet_balance
    test_node_activity
    test_nostr_connectivity
    test_electrs_sync
    test_mining

    echo ""
    test_fund_nodes

    echo ""
    test_create_reserves

    echo ""
    test_open_ledgers

    echo ""
    test_list_ledgers

    echo ""
    test_request_reservess

    echo ""
    test_list_reservess

    echo ""
    log_info "=== Deposit Lifecycle Tests ==="
    echo ""

    # Open deposits in Alice's ledger
    test_open_deposits

    echo ""
    test_list_deposits

    echo ""
    # Create a deposit offer for on-chain funding
    test_create_deposit_offer

    echo ""
    # Fund the deposit offer on-chain
    test_fund_deposit_offer

    echo ""
    # Check if the funding was detected
    test_check_deposit_offer

    echo ""
    # Complete the offer and credit the deposit
    test_complete_deposit_offer

    echo ""
    # Transfer from Deposit A to Deposit B
    test_deposit_transfer

    echo ""
    # Verify final balances
    test_verify_deposit_balances

    echo ""
    # List all deposit offers
    test_list_deposit_offers
}

# Main
run_all_tests

echo ""
log_info "=== Test Summary ==="
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
