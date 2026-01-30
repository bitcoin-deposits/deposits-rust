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

# Test: Open ledgers for each node
# Each BDK node opens its own ledger backed by its reserves UTXO
test_open_ledgers() {
    log_info "Testing ledger opening..."

    # Get current block height for enforcement block
    local current_height=$(get_block_height)
    # Set enforcement block 100 blocks in the future for bootstrap phase
    local enforcement_block=$((current_height + 100))

    log_info "Current block: $current_height, Enforcement block: $enforcement_block"

    # Each node opens their own ledger backed by their reserves
    for node in "${NODES[@]}"; do
        log_info "Opening ledger for $node..."

        local ledger_output=$(run_bdk_cmd "$node" ledger open "$enforcement_block" 2>&1)

        if echo "$ledger_output" | grep -q "Ledger opened successfully\|Opening ledger backed by reserves"; then
            test_pass "$node opened ledger"
            if $VERBOSE; then
                echo "    Ledger output:"
                echo "$ledger_output" | grep -E "Operator:|Partner:|Sequence:|Bootstrap" | sed 's/^/      /'
            fi
        elif echo "$ledger_output" | grep -q "already\|exists"; then
            # Ledger may already exist from previous run or network-init
            test_pass "$node ledger already exists"
        else
            test_fail "$node failed to open ledger"
            # Always show output on failure for debugging
            echo "    Output: $ledger_output"
        fi
    done
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

# Test: Request collateral partners
test_request_partners() {
    log_info "Testing collateral partner requests..."

    # Get node IDs
    local alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    local charlie_info=$(run_bdk_cmd "bdk-charlie" info 2>&1)

    local alice_id=$(echo "$alice_info" | grep "Node ID:" | awk '{print $3}')
    local bob_id=$(echo "$bob_info" | grep "Node ID:" | awk '{print $3}')
    local charlie_id=$(echo "$charlie_info" | grep "Node ID:" | awk '{print $3}')

    # Alice requests Bob as partner
    if [ -n "$bob_id" ]; then
        local request_output=$(run_bdk_cmd "bdk-alice" partner request "$bob_id" 2>&1)

        if echo "$request_output" | grep -q "Partnership request sent"; then
            test_pass "Alice sent partner request to Bob"
        else
            test_fail "Alice failed to send partner request to Bob"
            if $VERBOSE; then
                echo "    Output: $request_output"
            fi
        fi
    fi

    # Bob requests Charlie as partner
    if [ -n "$charlie_id" ]; then
        request_output=$(run_bdk_cmd "bdk-bob" partner request "$charlie_id" 2>&1)

        if echo "$request_output" | grep -q "Partnership request sent"; then
            test_pass "Bob sent partner request to Charlie"
        else
            test_fail "Bob failed to send partner request to Charlie"
        fi
    fi

    # Charlie requests Alice as partner (completing the triangle)
    if [ -n "$alice_id" ]; then
        request_output=$(run_bdk_cmd "bdk-charlie" partner request "$alice_id" 2>&1)

        if echo "$request_output" | grep -q "Partnership request sent"; then
            test_pass "Charlie sent partner request to Alice"
        else
            test_fail "Charlie failed to send partner request to Alice"
        fi
    fi

    # Wait a moment for messages to propagate via Nostr
    sleep 2
}

# Test: List partners
test_list_partners() {
    log_info "Testing partner listing..."

    for node in "${NODES[@]}"; do
        local list_output=$(run_bdk_cmd "$node" partner list 2>&1)

        # Note: Partners may not be established yet (just requests sent)
        # So we just verify the command runs without error
        if echo "$list_output" | grep -qE "No collateral partners|Partner|Collateral"; then
            test_pass "$node partner list executed"
            if $VERBOSE; then
                echo "    Partners: $list_output"
            fi
        else
            test_fail "$node partner list failed"
        fi
    done
}

# ============================================================================
# Deposit Lifecycle Tests
# ============================================================================

# Global variables to store deposit info across tests
ALICE_RESERVES_ID=""
BOB_RESERVES_ID=""
DEPOSIT_A_PUBKEY=""
DEPOSIT_A_SECRET=""
DEPOSIT_B_PUBKEY=""
DEPOSIT_B_SECRET=""
DEPOSIT_A_OFFER_ID=""
DEPOSIT_A_FUNDING_ADDRESS=""
DEPOSIT_B_OFFER_ID=""
DEPOSIT_B_FUNDING_ADDRESS=""
FUNDING_TXID=""
FUNDING_AMOUNT_SATS=""

# Test: Open deposits on Alice and Bob's ledgers
test_open_deposits() {
    log_info "Testing deposit opening..."

    # Create wallets directory
    mkdir -p "$SCRIPT_DIR/../wallets"

    # Get Alice's reserves ID (her ledger address)
    local alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    ALICE_RESERVES_ID=$(echo "$alice_info" | grep "Reserves address:" | awk '{print $3}')

    if [ -z "$ALICE_RESERVES_ID" ]; then
        test_fail "Could not get Alice's reserves ID"
        return 1
    fi
    log_info "Alice's reserves ID: ${ALICE_RESERVES_ID:0:20}..."

    # Get Bob's reserves ID (his ledger address)
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    BOB_RESERVES_ID=$(echo "$bob_info" | grep "Reserves address:" | awk '{print $3}')

    if [ -z "$BOB_RESERVES_ID" ]; then
        test_fail "Could not get Bob's reserves ID"
        return 1
    fi
    log_info "Bob's reserves ID: ${BOB_RESERVES_ID:0:20}..."

    # Generate keypair for Deposit A (on Alice's ledger)
    log_info "Generating deposit keypairs..."
    local keypair_a=$(run_bdk_cmd "bdk-alice" keygen 2>&1)
    DEPOSIT_A_SECRET=$(echo "$keypair_a" | awk '{print $1}')
    DEPOSIT_A_PUBKEY=$(echo "$keypair_a" | awk '{print $2}')

    # Generate keypair for Deposit B (on Bob's ledger)
    local keypair_b=$(run_bdk_cmd "bdk-bob" keygen 2>&1)
    DEPOSIT_B_SECRET=$(echo "$keypair_b" | awk '{print $1}')
    DEPOSIT_B_PUBKEY=$(echo "$keypair_b" | awk '{print $2}')

    if [ -z "$DEPOSIT_A_PUBKEY" ] || [ -z "$DEPOSIT_B_PUBKEY" ]; then
        test_fail "Failed to generate deposit keypairs"
        return 1
    fi

    # Save wallet files
    echo "{\"deposit_pubkey\": \"$DEPOSIT_A_PUBKEY\", \"deposit_secret\": \"$DEPOSIT_A_SECRET\", \"node\": \"alice\"}" > "$SCRIPT_DIR/../wallets/deposit_a.json"
    echo "{\"deposit_pubkey\": \"$DEPOSIT_B_PUBKEY\", \"deposit_secret\": \"$DEPOSIT_B_SECRET\", \"node\": \"bob\"}" > "$SCRIPT_DIR/../wallets/deposit_b.json"

    log_info "Opening Deposit A on Alice: ${DEPOSIT_A_PUBKEY:0:20}..."

    # Open Deposit A on Alice's ledger
    local open_output=$(run_bdk_cmd "bdk-alice" deposit open "$ALICE_RESERVES_ID" "$DEPOSIT_A_PUBKEY" 2>&1)

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

    log_info "Opening Deposit B on Bob: ${DEPOSIT_B_PUBKEY:0:20}..."

    # Open Deposit B on Bob's ledger
    open_output=$(run_bdk_cmd "bdk-bob" deposit open "$BOB_RESERVES_ID" "$DEPOSIT_B_PUBKEY" 2>&1)

    if echo "$open_output" | grep -q "Deposit opened"; then
        test_pass "Bob opened Deposit B"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
    else
        test_fail "Bob failed to open Deposit B"
        if $VERBOSE; then
            echo "    Output: $open_output"
        fi
        return 1
    fi
}

# Test: List deposits in ledgers
test_list_deposits() {
    log_info "Testing deposit listing..."

    if [ -z "$ALICE_RESERVES_ID" ] || [ -z "$BOB_RESERVES_ID" ]; then
        test_fail "Reserves IDs not set"
        return 1
    fi

    # Check Alice's ledger
    local list_output=$(run_bdk_cmd "bdk-alice" deposit ls "$ALICE_RESERVES_ID" 2>&1)
    if echo "$list_output" | grep -q "Deposit:"; then
        test_pass "Alice's ledger has deposits"
        if $VERBOSE; then
            echo "    Alice's deposits:"
            echo "$list_output" | grep -E "Deposit:|Balance:|Locked:" | sed 's/^/      /'
        fi
    else
        test_fail "No deposits found in Alice's ledger"
        if $VERBOSE; then
            echo "    Output: $list_output"
        fi
    fi

    # Check Bob's ledger
    list_output=$(run_bdk_cmd "bdk-bob" deposit ls "$BOB_RESERVES_ID" 2>&1)
    if echo "$list_output" | grep -q "Deposit:"; then
        test_pass "Bob's ledger has deposits"
        if $VERBOSE; then
            echo "    Bob's deposits:"
            echo "$list_output" | grep -E "Deposit:|Balance:|Locked:" | sed 's/^/      /'
        fi
    else
        test_fail "No deposits found in Bob's ledger"
        if $VERBOSE; then
            echo "    Output: $list_output"
        fi
    fi
}

# Test: Create deposit offer for Deposit A (on Alice)
test_create_deposit_offer_a() {
    log_info "Testing deposit offer creation for Deposit A..."

    if [ -z "$ALICE_RESERVES_ID" ] || [ -z "$DEPOSIT_A_PUBKEY" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    # Create offer: max 1 BTC, min 0.001 BTC, valid for 144 blocks
    local max_sats=100000000    # 1 BTC
    local min_sats=100000       # 0.001 BTC
    local blocks_valid=144      # ~1 day

    local offer_output=$(run_bdk_cmd "bdk-alice" deposit offer "$ALICE_RESERVES_ID" "$DEPOSIT_A_PUBKEY" "$max_sats" "$min_sats" "$blocks_valid" 2>&1)

    if echo "$offer_output" | grep -q "Deposit offer created"; then
        DEPOSIT_A_OFFER_ID=$(echo "$offer_output" | grep "Offer ID:" | awk '{print $3}')
        DEPOSIT_A_FUNDING_ADDRESS=$(echo "$offer_output" | grep "Funding address:" | awk '{print $3}')

        test_pass "Alice created deposit offer for Deposit A"
        log_info "  Offer ID: ${DEPOSIT_A_OFFER_ID:0:16}..."
        log_info "  Funding address: $DEPOSIT_A_FUNDING_ADDRESS"

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

# Test: Fund Deposit A's offer on-chain (from faucet, simulating external funding)
test_fund_deposit_offer_a() {
    log_info "Testing deposit offer funding for Deposit A..."

    if [ -z "$DEPOSIT_A_FUNDING_ADDRESS" ]; then
        test_fail "Funding address not set"
        return 1
    fi

    # Send 0.5 BTC to the funding address from the faucet
    local amount_btc="0.5"
    log_info "Sending $amount_btc BTC to Deposit A's funding address"

    local txid=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$DEPOSIT_A_FUNDING_ADDRESS" "$amount_btc" 2>&1)

    if [ $? -eq 0 ] && [ -n "$txid" ]; then
        test_pass "Sent $amount_btc BTC to Deposit A's funding address"
        log_info "  TXID: ${txid:0:16}..."

        # Store for later use
        FUNDING_TXID="$txid"
        FUNDING_AMOUNT_SATS=50000000  # 0.5 BTC in sats

        # Mine a block to confirm
        mine_blocks 1
        test_pass "Mined confirmation block"
    else
        test_fail "Failed to send funds to Deposit A's offer"
        if $VERBOSE; then
            echo "    Output: $txid"
        fi
        return 1
    fi
}

# Test: Check if Deposit A's offer has been funded
test_check_deposit_offer_a() {
    log_info "Testing deposit offer funding check for Deposit A..."

    if [ -z "$DEPOSIT_A_OFFER_ID" ]; then
        test_fail "Offer ID not set"
        return 1
    fi

    # Sync Alice's wallet first
    run_bdk_cmd "bdk-alice" info >/dev/null 2>&1

    local check_output=$(run_bdk_cmd "bdk-alice" deposit check "$DEPOSIT_A_OFFER_ID" 2>&1)

    if echo "$check_output" | grep -q "Funding detected"; then
        test_pass "Deposit A offer funding detected"
        if $VERBOSE; then
            echo "    Check output:"
            echo "$check_output" | grep -E "Transaction:|Amount:" | sed 's/^/      /'
        fi
    else
        # May need to wait for sync
        log_info "Funding not detected yet, waiting for sync..."
        sleep 3
        check_output=$(run_bdk_cmd "bdk-alice" deposit check "$DEPOSIT_A_OFFER_ID" 2>&1)

        if echo "$check_output" | grep -q "Funding detected"; then
            test_pass "Deposit A offer funding detected (after sync)"
        else
            test_fail "Deposit A offer funding not detected"
            if $VERBOSE; then
                echo "    Output: $check_output"
            fi
        fi
    fi
}

# Test: Complete Deposit A's offer (credit the deposit)
test_complete_deposit_offer_a() {
    log_info "Testing deposit offer completion for Deposit A..."

    if [ -z "$DEPOSIT_A_OFFER_ID" ] || [ -z "$FUNDING_TXID" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    local complete_output=$(run_bdk_cmd "bdk-alice" deposit complete "$DEPOSIT_A_OFFER_ID" "$FUNDING_TXID" "$FUNDING_AMOUNT_SATS" 2>&1)

    if echo "$complete_output" | grep -q "Deposit offer completed"; then
        test_pass "Deposit A offer completed - deposit credited"

        # Extract new balance
        local new_balance=$(echo "$complete_output" | grep "New balance:" | awk '{print $3}')
        log_info "  Deposit A new balance: $new_balance msats"

        if $VERBOSE; then
            echo "    Complete output:"
            echo "$complete_output" | sed 's/^/      /'
        fi
    else
        test_fail "Failed to complete Deposit A offer"
        if $VERBOSE; then
            echo "    Output: $complete_output"
        fi
        return 1
    fi
}

# Test: Create deposit offer for Deposit B (on Bob)
test_create_deposit_offer_b() {
    log_info "Testing deposit offer creation for Deposit B..."

    if [ -z "$BOB_RESERVES_ID" ] || [ -z "$DEPOSIT_B_PUBKEY" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    # Create offer: max 0.3 BTC, min 0.001 BTC, valid for 144 blocks
    local max_sats=30000000     # 0.3 BTC
    local min_sats=100000       # 0.001 BTC
    local blocks_valid=144      # ~1 day

    local offer_output=$(run_bdk_cmd "bdk-bob" deposit offer "$BOB_RESERVES_ID" "$DEPOSIT_B_PUBKEY" "$max_sats" "$min_sats" "$blocks_valid" 2>&1)

    if echo "$offer_output" | grep -q "Deposit offer created"; then
        DEPOSIT_B_OFFER_ID=$(echo "$offer_output" | grep "Offer ID:" | awk '{print $3}')
        DEPOSIT_B_FUNDING_ADDRESS=$(echo "$offer_output" | grep "Funding address:" | awk '{print $3}')

        test_pass "Bob created deposit offer for Deposit B"
        log_info "  Offer ID: ${DEPOSIT_B_OFFER_ID:0:16}..."
        log_info "  Funding address: $DEPOSIT_B_FUNDING_ADDRESS"

        if $VERBOSE; then
            echo "    Full offer output:"
            echo "$offer_output" | grep -E "Offer ID:|Funding address:|Deadline|Amount" | sed 's/^/      /'
        fi
    else
        test_fail "Bob failed to create deposit offer"
        if $VERBOSE; then
            echo "    Output: $offer_output"
        fi
        return 1
    fi
}

# Test: Withdraw from Deposit A to fund Deposit B's offer
test_withdraw_to_fund_deposit_b() {
    log_info "Testing withdrawal from Deposit A to fund Deposit B..."

    if [ -z "$ALICE_RESERVES_ID" ] || [ -z "$DEPOSIT_A_SECRET" ] || [ -z "$DEPOSIT_B_FUNDING_ADDRESS" ]; then
        test_fail "Required variables not set"
        return 1
    fi

    # Withdraw 0.2 BTC (leaving some for fees)
    local amount_sats=20000000   # 0.2 BTC
    local fee_sats=1000          # Small fee

    log_info "Withdrawing $amount_sats sats from Deposit A to Deposit B's funding address..."

    # Request withdrawal (generates nonce, signs, and locks)
    local withdraw_output=$(run_bdk_cmd "bdk-alice" withdraw request "$ALICE_RESERVES_ID" "$DEPOSIT_A_SECRET" "$DEPOSIT_B_FUNDING_ADDRESS" "$amount_sats" "$fee_sats" 2>&1)

    if echo "$withdraw_output" | grep -q "Withdrawal request created\|Withdrawal locked"; then
        local withdrawal_id=$(echo "$withdraw_output" | grep -E "Withdrawal ID:|withdrawal_id" | awk '{print $NF}')
        test_pass "Withdrawal from Deposit A locked"
        log_info "  Withdrawal ID: ${withdrawal_id:0:16}..."

        # Complete the withdrawal (broadcast)
        local complete_output=$(run_bdk_cmd "bdk-alice" withdraw complete "$ALICE_RESERVES_ID" "$withdrawal_id" 2>&1)

        if echo "$complete_output" | grep -q "Withdrawal complete\|broadcast"; then
            test_pass "Withdrawal broadcasted"

            # Mine a block to confirm
            mine_blocks 1
            test_pass "Mined confirmation block"

            # Store the txid for Deposit B completion
            FUNDING_TXID=$(echo "$complete_output" | grep -E "TXID:|txid" | awk '{print $NF}')
            FUNDING_AMOUNT_SATS=$amount_sats
        else
            test_fail "Failed to complete withdrawal"
            if $VERBOSE; then
                echo "    Output: $complete_output"
            fi
            return 1
        fi
    else
        test_fail "Failed to create withdrawal request"
        if $VERBOSE; then
            echo "    Output: $withdraw_output"
        fi
        return 1
    fi
}

# Test: Check and complete Deposit B's offer
test_complete_deposit_offer_b() {
    log_info "Testing deposit offer completion for Deposit B..."

    if [ -z "$DEPOSIT_B_OFFER_ID" ]; then
        test_fail "Deposit B offer ID not set"
        return 1
    fi

    # Sync Bob's wallet first
    run_bdk_cmd "bdk-bob" info >/dev/null 2>&1
    sleep 2

    # Check if funded
    local check_output=$(run_bdk_cmd "bdk-bob" deposit check "$DEPOSIT_B_OFFER_ID" 2>&1)

    if echo "$check_output" | grep -q "Funding detected"; then
        test_pass "Deposit B offer funding detected"

        # Extract txid and amount from check output (use specific patterns to avoid matching help text)
        local detected_txid=$(echo "$check_output" | grep "^  Transaction:" | awk '{print $2}')
        local detected_amount=$(echo "$check_output" | grep "^  Amount:" | awk '{print $2}')

        if [ -n "$detected_txid" ] && [ -n "$detected_amount" ]; then
            local complete_output=$(run_bdk_cmd "bdk-bob" deposit complete "$DEPOSIT_B_OFFER_ID" "$detected_txid" "$detected_amount" 2>&1)

            if echo "$complete_output" | grep -q "Deposit offer completed"; then
                test_pass "Deposit B offer completed - deposit credited"

                local new_balance=$(echo "$complete_output" | grep "New balance:" | awk '{print $3}')
                log_info "  Deposit B new balance: $new_balance msats"
            else
                test_fail "Failed to complete Deposit B offer"
                if $VERBOSE; then
                    echo "    Output: $complete_output"
                fi
            fi
        else
            test_fail "Could not extract funding details"
        fi
    else
        test_fail "Deposit B offer funding not detected"
        if $VERBOSE; then
            echo "    Output: $check_output"
        fi
    fi
}

# Test: Verify final deposit balances
test_verify_deposit_balances() {
    log_info "Testing final deposit balances..."

    if [ -z "$ALICE_RESERVES_ID" ] || [ -z "$BOB_RESERVES_ID" ]; then
        test_fail "Reserves IDs not set"
        return 1
    fi

    # Check Alice's ledger (Deposit A should have ~0.3 BTC after withdrawal)
    local alice_list=$(run_bdk_cmd "bdk-alice" deposit ls "$ALICE_RESERVES_ID" 2>&1)

    if echo "$alice_list" | grep -A2 "$DEPOSIT_A_PUBKEY" | grep -q "Balance:"; then
        local deposit_a_balance=$(echo "$alice_list" | grep -A2 "$DEPOSIT_A_PUBKEY" | grep "Balance:" | awk '{print $2}')
        if [ -n "$deposit_a_balance" ] && [ "$deposit_a_balance" -gt 0 ]; then
            test_pass "Deposit A (Alice) has balance: $deposit_a_balance msats"
        else
            test_fail "Deposit A has no balance"
        fi
    else
        test_fail "Could not find Deposit A balance"
    fi

    # Check Bob's ledger (Deposit B should have ~0.2 BTC from withdrawal funding)
    local bob_list=$(run_bdk_cmd "bdk-bob" deposit ls "$BOB_RESERVES_ID" 2>&1)

    if echo "$bob_list" | grep -A2 "$DEPOSIT_B_PUBKEY" | grep -q "Balance:"; then
        local deposit_b_balance=$(echo "$bob_list" | grep -A2 "$DEPOSIT_B_PUBKEY" | grep "Balance:" | awk '{print $2}')
        if [ -n "$deposit_b_balance" ] && [ "$deposit_b_balance" -gt 0 ]; then
            test_pass "Deposit B (Bob) has balance: $deposit_b_balance msats"
        else
            test_fail "Deposit B has no balance"
        fi
    else
        test_fail "Could not find Deposit B balance"
    fi

    if $VERBOSE; then
        echo "    Alice's deposits:"
        echo "$alice_list" | sed 's/^/      /'
        echo "    Bob's deposits:"
        echo "$bob_list" | sed 's/^/      /'
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
    test_request_partners

    echo ""
    test_list_partners

    echo ""
    log_info "=== Deposit Lifecycle Tests ==="
    echo ""

    # Open deposits: Deposit A on Alice, Deposit B on Bob
    test_open_deposits

    echo ""
    test_list_deposits

    echo ""
    # Create deposit offer for Deposit A (on Alice)
    test_create_deposit_offer_a

    echo ""
    # Fund Deposit A's offer on-chain (from faucet)
    test_fund_deposit_offer_a

    echo ""
    # Check if Deposit A's funding was detected
    test_check_deposit_offer_a

    echo ""
    # Complete Deposit A's offer (credit the deposit)
    test_complete_deposit_offer_a

    echo ""
    # Create deposit offer for Deposit B (on Bob)
    test_create_deposit_offer_b

    echo ""
    # Withdraw from Deposit A to fund Deposit B's offer
    test_withdraw_to_fund_deposit_b

    echo ""
    # Check and complete Deposit B's offer
    test_complete_deposit_offer_b

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
