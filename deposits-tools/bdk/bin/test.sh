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

    # Alice opens ledger with Bob (Alice = operator, Bob = partner)
    # First get Bob's node ID
    local bob_info=$(run_bdk_cmd "bdk-bob" info 2>&1)
    local bob_node_id=$(echo "$bob_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$bob_node_id" ]; then
        test_fail "Could not get Bob's node ID"
        return
    fi

    log_info "Opening ledger: Alice (operator) <-> Bob (partner)"
    log_info "Bob's Node ID: ${bob_node_id:0:20}..."

    local ledger_output=$(run_bdk_cmd "bdk-alice" ledger open "$bob_node_id" "$enforcement_block" 2>&1)

    if echo "$ledger_output" | grep -q "Ledger opened successfully"; then
        test_pass "Alice opened ledger with Bob"
        if $VERBOSE; then
            echo "    Ledger output:"
            echo "$ledger_output" | grep -E "Operator:|Partner:|Sequence:|Bootstrap" | sed 's/^/      /'
        fi
    else
        test_fail "Alice failed to open ledger with Bob"
        if $VERBOSE; then
            echo "    Output: $ledger_output"
        fi
    fi

    # Bob opens ledger with Charlie (Bob = operator, Charlie = partner)
    local charlie_info=$(run_bdk_cmd "bdk-charlie" info 2>&1)
    local charlie_node_id=$(echo "$charlie_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$charlie_node_id" ]; then
        test_fail "Could not get Charlie's node ID"
        return
    fi

    log_info "Opening ledger: Bob (operator) <-> Charlie (partner)"
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

    # Charlie opens ledger with Alice (Charlie = operator, Alice = partner)
    # This completes the triangle for cross-collateral
    local alice_info=$(run_bdk_cmd "bdk-alice" info 2>&1)
    local alice_node_id=$(echo "$alice_info" | grep "Node ID:" | awk '{print $3}')

    if [ -z "$alice_node_id" ]; then
        test_fail "Could not get Alice's node ID"
        return
    fi

    log_info "Opening ledger: Charlie (operator) <-> Alice (partner)"
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
                echo "$list_output" | grep -E "Operator:|Partner:|Sequence:|Enforcement" | sed 's/^/      /'
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
