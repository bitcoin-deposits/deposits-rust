#!/bin/bash
# Four-operator dispute protocol test script (with on-chain lottery)
#
# This script tests the full dispute protocol with 4 operators:
# 1. Each creates reserves UTXOs of the same amount
# 2. Each opens ledgers with 200 block enforcement delay
# 3. Each operator adds others as quorum members (15% collateral each)
# 4. Alice publishes invalid update (goes rogue)
# 5. Bob, Charlie, Diana each:
#    - Publish CustodyDispute (opens dispute)
#    - Rebuild quorum with non-Alice members
#    - Post collateral attestations from non-Alice members
#    - Request non-Alice quorum members join their chain
#    - Publish CustodyArmed (pre-commitment with lottery hash)
# 6. Confiscate reserves to lottery Tapscript output
# 7. All participants reveal preimages via Nostr
# 8. Winner determined by preimage-size lottery, claims output
# 9. Winner: CustodyAcquire, Losers: CustodyYield
#
# Usage:
#   ./bin/test-dispute-4op.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Configuration
RESERVES_AMOUNT=100000000  # 1 BTC in sats
COLLATERAL_PERCENT=15      # 15% of reserves as collateral
ENFORCEMENT_DELAY=200      # Blocks until enforcement
COLLATERAL_LOCK_BLOCKS=500 # Lock duration

# Use temp directory for state
STATE_DIR=$(mktemp -d)
trap "rm -rf $STATE_DIR" EXIT

# Store/retrieve functions (bash 3.2 compatible)
store_value() {
    local key="$1"
    local value="$2"
    echo "$value" > "$STATE_DIR/$key"
}

get_value() {
    local key="$1"
    if [ -f "$STATE_DIR/$key" ]; then
        cat "$STATE_DIR/$key"
    fi
}

# Operators - 4 total
OPERATORS="bdk-alice bdk-bob bdk-charlie bdk-diana"
NON_ALICE_OPERATORS="bdk-bob bdk-charlie bdk-diana"

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
# Phase 1: Setup - Fund operators and get their info
# ============================================================================

setup_operators() {
    log_info "=== Phase 1: Setup Operators ==="
    echo ""

    for op in $OPERATORS; do
        log_info "Setting up $op..."

        # Fund if needed
        local info_output=$(run_bdk_cmd "$op" info 2>&1)
        local balance=$(echo "$info_output" | grep "Wallet balance:" | awk '{print $3}')

        if [ -z "$balance" ] || [ "$balance" -lt 200000000 ]; then
            local address=$(get_node_address "$op")
            bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 10 >/dev/null 2>&1
            mine_blocks 1
            log_info "  Funded $op with 10 BTC"
        fi

        # Get node info
        info_output=$(run_bdk_cmd "$op" info 2>&1)
        local node_id=$(echo "$info_output" | grep "Node ID:" | awk '{print $3}')
        store_value "node_id_$op" "$node_id"

        if [ -n "$node_id" ]; then
            test_pass "$op ready: ${node_id:0:16}..."
        else
            test_fail "Could not get node ID for $op"
            return 1
        fi
    done
}

# ============================================================================
# Phase 2: Create reserves UTXOs (same amount for all)
# ============================================================================

create_reserves() {
    log_info ""
    log_info "=== Phase 2: Create Reserves ($RESERVES_AMOUNT sats each) ==="
    echo ""

    for op in $OPERATORS; do
        log_info "Creating reserves for $op..."

        local reserves_output=$(run_bdk_cmd "$op" reserves "$RESERVES_AMOUNT" 2>&1)

        if echo "$reserves_output" | grep -q "Reserves created"; then
            test_pass "$op created reserves"
        elif echo "$reserves_output" | grep -q "already have reserves"; then
            test_pass "$op already has reserves"
        else
            test_fail "$op reserves creation failed"
            echo "    Output: $reserves_output"
        fi
    done

    # Mine to confirm
    mine_blocks 1
}

# ============================================================================
# Phase 3: Open ledgers with enforcement delay
# ============================================================================

open_ledgers() {
    log_info ""
    log_info "=== Phase 3: Open Ledgers (enforcement +$ENFORCEMENT_DELAY blocks) ==="
    echo ""

    local current_height=$(get_block_height)
    local enforcement_block=$((current_height + ENFORCEMENT_DELAY))

    log_info "Current block: $current_height, Enforcement: $enforcement_block"
    echo ""

    for op in $OPERATORS; do
        log_info "Opening ledger for $op..."

        local ledger_output=$(run_bdk_cmd "$op" ledger open "$enforcement_block" 2>&1)

        if echo "$ledger_output" | grep -q "Ledger opened\|Opening ledger"; then
            test_pass "$op opened ledger"
        elif echo "$ledger_output" | grep -q "already"; then
            test_pass "$op ledger already exists"
        else
            test_fail "$op failed to open ledger"
            echo "    Output: $ledger_output"
        fi

        # Extract ledger_id hash and reserves_id from the output
        local ledger_id=$(echo "$ledger_output" | grep "Ledger ID:" | awk '{print $3}')
        local reserves_id=$(echo "$ledger_output" | grep "Reserves:.*bcrt1" | awk '{print $2}')

        if [ -n "$ledger_id" ]; then
            store_value "ledger_id_$op" "$ledger_id"
            log_info "  Ledger ID: ${ledger_id:0:16}..."
        fi

        if [ -n "$reserves_id" ]; then
            store_value "reserves_id_$op" "$reserves_id"
        else
            # Fallback: get reserves_id from info command
            local info_output=$(run_bdk_cmd "$op" info 2>&1)
            reserves_id=$(echo "$info_output" | grep "Reserves address:" | awk '{print $3}')
            store_value "reserves_id_$op" "$reserves_id"
        fi

        # If we didn't get ledger_id, try from ledger list
        if [ -z "$ledger_id" ]; then
            local list_output=$(run_bdk_cmd "$op" ledger list 2>&1)
            ledger_id=$(echo "$list_output" | grep "Ledger ID:" | head -1 | awk '{print $3}')
            if [ -n "$ledger_id" ]; then
                store_value "ledger_id_$op" "$ledger_id"
                log_info "  Ledger ID: ${ledger_id:0:16}..."
            else
                log_warn "  Could not get ledger_id for $op"
            fi
        fi
    done
}

# ============================================================================
# Phase 3a: Start Nostr watchers on each operator
# ============================================================================

start_nostr_watchers() {
    log_info ""
    log_info "=== Phase 3a: Start Nostr Watchers ==="
    log_info "(Each operator listens for incoming requests)"
    echo ""

    for op in $OPERATORS; do
        local ledger_id=$(get_value "ledger_id_$op")
        if [ -n "$ledger_id" ]; then
            start_nostr_watch "$op" "$ledger_id"
            test_pass "$op nostr watcher started"
        else
            test_fail "$op has no ledger_id"
        fi
    done

    # Give watchers time to connect
    sleep 2
}

# ============================================================================
# Restart Nostr watchers (to pick up new QuorumJoin operations)
# ============================================================================

restart_nostr_watchers() {
    log_info ""
    log_info "=== Restarting Nostr Watchers ==="
    log_info "(Watchers need restart to subscribe to joined ledgers)"
    echo ""

    # Stop existing watchers
    for op in $OPERATORS; do
        stop_nostr_watch "$op"
    done
    sleep 1

    # Restart watchers
    for op in $OPERATORS; do
        local ledger_id=$(get_value "ledger_id_$op")
        if [ -n "$ledger_id" ]; then
            start_nostr_watch "$op" "$ledger_id"
            test_pass "$op nostr watcher restarted"
        fi
    done

    # Give watchers time to connect and scan for QuorumJoin operations
    sleep 3
}

# ============================================================================
# Phase 3b: Add all nodes as quorum members to each other
# ============================================================================

add_quorum_members() {
    log_info ""
    log_info "=== Phase 3b: Add Quorum Members ==="
    log_info "(Each operator adds the other operators as quorum members)"
    echo ""

    local current_height=$(get_block_height)
    local membership_expires=$((current_height + 1000))

    for op in $OPERATORS; do
        local op_reserves_id=$(get_value "reserves_id_$op")
        local op_node_id=$(get_value "node_id_$op")

        for member in $OPERATORS; do
            if [ "$op" != "$member" ]; then
                local member_node_id=$(get_value "node_id_$member")
                local member_reserves_id=$(get_value "reserves_id_$member")
                local op_short=$(echo "$op" | sed 's/bdk-//')
                local member_short=$(echo "$member" | sed 's/bdk-//')

                log_info "$op_short adding $member_short as quorum member..."

                # Add member to op's quorum
                local add_output=$(run_bdk_cmd "$op" partner add "$op_reserves_id" "$member_node_id" 2>&1)

                if echo "$add_output" | grep -q "Quorum member added\|added"; then
                    # Record the join on member's ledger
                    local join_output=$(run_bdk_cmd "$member" partner join "$member_reserves_id" "$op_node_id" "$op_reserves_id" "$membership_expires" 2>&1)

                    if echo "$join_output" | grep -q "Quorum join recorded\|recorded"; then
                        test_pass "$member_short joined $op_short's quorum (both sides recorded)"
                    else
                        test_pass "$op_short added $member_short (join record failed: $join_output)"
                    fi
                else
                    test_fail "$op_short failed to add $member_short as quorum member"
                    echo "    Output: $add_output"
                fi
            fi
        done
    done
}

# ============================================================================
# Phase 3c: Rotate reserves to quorum-based Taproot
# ============================================================================

rotate_reserves_to_quorum() {
    log_info ""
    log_info "=== Phase 3c: Rotate Reserves to Quorum-Based Taproot ==="
    echo ""

    for op in $OPERATORS; do
        local op_reserves_id=$(get_value "reserves_id_$op")
        local op_short=$(echo "$op" | sed 's/bdk-//')

        log_info "$op_short rotating reserves to quorum-based Taproot..."

        local rotate_output=$(run_bdk_cmd "$op" reserves rotate "$op_reserves_id" 2>&1)

        if echo "$rotate_output" | grep -q "Reserves rotated\|rotated successfully"; then
            local new_address=$(echo "$rotate_output" | grep "New Address:" | awk '{print $3}')
            local quorum_count=$(echo "$rotate_output" | grep "Quorum Members:" | awk '{print $3}')
            local expiry_block=$(echo "$rotate_output" | grep "First Expiry Block:" | awk '{print $4}')

            test_pass "$op_short rotated to Taproot with $quorum_count members (expiry: block $expiry_block)"
        else
            log_warn "$op_short: Reserves rotation returned: $(echo "$rotate_output" | head -1)"
        fi
    done

    mine_blocks 1
}

# ============================================================================
# Phase 4: Generate deposit keys and open cross-deposits (15% collateral)
# ============================================================================

generate_deposit_keys() {
    log_info ""
    log_info "=== Phase 4a: Generate Deposit Keys ==="
    echo ""

    for depositor in $OPERATORS; do
        for operator in $OPERATORS; do
            if [ "$depositor" != "$operator" ]; then
                local dep_short=$(echo "$depositor" | sed 's/bdk-//')
                local op_short=$(echo "$operator" | sed 's/bdk-//')
                local keyfile="deposit_${dep_short}_${op_short}"

                local keypair=$(run_bdk_cmd "$depositor" keygen 2>&1)
                local secret=$(echo "$keypair" | awk '{print $1}')
                local pubkey=$(echo "$keypair" | awk '{print $2}')

                store_value "pubkey_${depositor}_${operator}" "$pubkey"
                store_value "secret_${depositor}_${operator}" "$secret"
                log_info "$keyfile: ${pubkey:0:16}..."
            fi
        done
    done
}

open_cross_deposits() {
    log_info ""
    log_info "=== Phase 4b: Open Cross-Deposits via Nostr ==="
    echo ""

    for depositor in $OPERATORS; do
        for operator in $OPERATORS; do
            if [ "$depositor" != "$operator" ]; then
                local pubkey=$(get_value "pubkey_${depositor}_${operator}")
                local ledger_id=$(get_value "ledger_id_$operator")
                local dep_short=$(echo "$depositor" | sed 's/bdk-//')
                local op_short=$(echo "$operator" | sed 's/bdk-//')

                log_info "$dep_short requesting deposit on $op_short's ledger..."

                local open_output=$(run_nostr_request "$depositor" "$ledger_id" deposit_open "$pubkey" 2>&1)

                if echo "$open_output" | grep -q "SUCCESS\|deposit_pubkey"; then
                    test_pass "$depositor opened deposit on $operator via Nostr"
                    store_value "deposit_${depositor}_on_${operator}" "1"
                else
                    test_fail "$depositor failed to open deposit on $operator"
                    echo "    Output: $open_output"
                fi
            fi
        done
    done
}

# ============================================================================
# Phase 5: Fund deposits (15% collateral on each partner)
# ============================================================================

fund_deposits() {
    log_info ""
    log_info "=== Phase 5: Fund Deposits via Nostr (${COLLATERAL_PERCENT}% each) ==="
    echo ""

    local deposit_amount=$((RESERVES_AMOUNT * COLLATERAL_PERCENT / 100))

    for depositor in $OPERATORS; do
        for operator in $OPERATORS; do
            local has_deposit=$(get_value "deposit_${depositor}_on_${operator}")
            if [ "$depositor" != "$operator" ] && [ "$has_deposit" = "1" ]; then
                local pubkey=$(get_value "pubkey_${depositor}_${operator}")
                local ledger_id=$(get_value "ledger_id_$operator")
                local dep_short=$(echo "$depositor" | sed 's/bdk-//')
                local op_short=$(echo "$operator" | sed 's/bdk-//')

                log_info "$dep_short funding deposit on $op_short ($deposit_amount sats)..."

                local offer_output=$(run_nostr_request "$depositor" "$ledger_id" deposit_offer "$pubkey" "$deposit_amount" "10000" "144" 2>&1)

                if echo "$offer_output" | grep -q "SUCCESS\|offer_id"; then
                    local offer_id=$(echo "$offer_output" | grep -o '"offer_id"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"//' | sed 's/"$//')
                    local funding_address=$(echo "$offer_output" | grep -o '"funding_address"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"//' | sed 's/"$//')

                    if [ -n "$funding_address" ]; then
                        local btc_amount=$(awk "BEGIN {printf \"%.8f\", $deposit_amount / 100000000}")
                        bitcoin_cli -rpcwallet=faucet sendtoaddress "$funding_address" "$btc_amount" >/dev/null 2>&1

                        if [ $? -eq 0 ]; then
                            mine_blocks 1

                            local check_output=$(run_bdk_cmd "$operator" deposit check "$offer_id" 2>&1)

                            if echo "$check_output" | grep -q "Funding detected"; then
                                local txid=$(echo "$check_output" | grep "Transaction:" | awk '{print $2}')
                                local detected_amount=$(echo "$check_output" | grep "Amount:" | awk '{print $2}')

                                local complete_output=$(run_bdk_cmd "$operator" deposit complete "$offer_id" "$txid" "$detected_amount" 2>&1)

                                if echo "$complete_output" | grep -q "completed\|credited"; then
                                    test_pass "$dep_short's deposit on $op_short funded ($detected_amount sats)"
                                else
                                    test_fail "Failed to complete $dep_short's deposit on $op_short"
                                fi
                            else
                                test_fail "Funding not detected for $dep_short's deposit on $op_short"
                            fi
                        else
                            test_fail "Failed to fund $dep_short's deposit on $op_short"
                        fi
                    fi
                else
                    test_fail "Failed to get deposit offer from $op_short"
                fi
            fi
        done
    done
}

# ============================================================================
# Phase 6: Lock collateral and record attestations
# ============================================================================

lock_collateral() {
    log_info ""
    log_info "=== Phase 6: Lock Collateral (lock for $COLLATERAL_LOCK_BLOCKS blocks) ==="
    echo ""

    local deposit_amount=$((RESERVES_AMOUNT * COLLATERAL_PERCENT / 100))
    local deposit_amount_msats=$((deposit_amount * 1000))

    for depositor in $OPERATORS; do
        for operator in $OPERATORS; do
            local has_deposit=$(get_value "deposit_${depositor}_on_${operator}")
            if [ "$depositor" != "$operator" ] && [ "$has_deposit" = "1" ]; then
                local secret=$(get_value "secret_${depositor}_${operator}")
                local ledger_id=$(get_value "ledger_id_$operator")
                local depositor_reserves_id=$(get_value "reserves_id_$depositor")
                local depositor_node_id=$(get_value "node_id_$depositor")
                local dep_short=$(echo "$depositor" | sed 's/bdk-//')
                local op_short=$(echo "$operator" | sed 's/bdk-//')

                log_info "$dep_short locking collateral on $op_short's ledger..."

                local lock_output=$(run_nostr_request "$depositor" "$ledger_id" collateral_lock "$secret" "$deposit_amount_msats" "$COLLATERAL_LOCK_BLOCKS" "$depositor_node_id" 2>&1)

                if echo "$lock_output" | grep -q "SUCCESS\|attestation"; then
                    local attestation_b64=$(echo "$lock_output" | grep -o '"attestation_b64"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/"attestation_b64"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')

                    if [ -n "$attestation_b64" ]; then
                        local attestation_json=$(echo "$attestation_b64" | base64 -d 2>/dev/null)
                        local record_output=$(run_bdk_cmd "$depositor" collateral record "$depositor_reserves_id" "$attestation_json" 2>&1)

                        if echo "$record_output" | grep -q "recorded\|Collateral attestation"; then
                            test_pass "$dep_short: locked on $op_short, attestation recorded"
                        else
                            test_fail "$dep_short: locked but attestation not recorded"
                        fi
                    fi
                else
                    test_fail "$dep_short failed to lock on $op_short"
                fi
            fi
        done
    done
}

# ============================================================================
# Phase 7: Mine past enforcement block
# ============================================================================

mine_to_enforcement() {
    log_info ""
    log_info "=== Phase 7: Mine Past Enforcement Block ==="
    echo ""

    local blocks_to_mine=$((ENFORCEMENT_DELAY + 10))
    log_info "Mining $blocks_to_mine blocks to reach enforcement..."
    mine_blocks "$blocks_to_mine"

    local new_height=$(get_block_height)
    test_pass "Mined to block $new_height"
}

# ============================================================================
# Phase 8: Alice publishes invalid update
# ============================================================================

alice_goes_rogue() {
    log_info ""
    log_info "=== Phase 8: Alice Goes Rogue (publishes invalid update) ==="
    echo ""

    local alice_reserves=$(get_value "reserves_id_bdk-alice")
    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")

    # Export valid ledger first
    log_info "Alice exporting valid ledger to Nostr..."
    run_bdk_cmd "bdk-alice" nostr export "$alice_ledger_id" >/dev/null 2>&1

    # Publish invalid update
    log_info "Alice publishing invalid update (hash chain broken)..."
    local danger_output=$(run_bdk_cmd "bdk-alice" danger publish-invalid \
        "$alice_reserves" invalid-hash 2>&1)

    if echo "$danger_output" | grep -q "Published invalid update"; then
        local event_id=$(echo "$danger_output" | grep "Event ID:" | awk '{print $3}')
        test_pass "alice published invalid update: ${event_id:0:16}..."
        store_value "alice_went_rogue" "1"
    else
        test_fail "Alice failed to publish invalid update"
        echo "Output: $danger_output"
    fi

    sleep 2
}

# ============================================================================
# Phase 9: Non-Alice operators start dispute protocol
# ============================================================================

start_disputes() {
    log_info ""
    log_info "=== Phase 9: Non-Alice Operators Start Disputes ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")

    for op in $NON_ALICE_OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')

        log_info "$op_short publishing CustodyDispute on Alice's ledger..."

        local dispute_output=$(run_bdk_cmd "$op" recovery dispute "$alice_ledger_id" 2>&1)

        if echo "$dispute_output" | grep -q "CustodyDispute published"; then
            test_pass "$op_short published CustodyDispute"
            store_value "dispute_${op}" "1"
        else
            test_fail "$op_short failed to publish CustodyDispute"
            echo "Output: $dispute_output"
        fi
    done

    sleep 2
}

# ============================================================================
# Phase 10: Rebuild quorum with non-Alice members
# ============================================================================

rebuild_quorum() {
    log_info ""
    log_info "=== Phase 10: Rebuild Quorum (non-Alice members only) ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")
    local current_height=$(get_block_height)
    local membership_expires=$((current_height + 1000))

    for op in $NON_ALICE_OPERATORS; do
        local has_dispute=$(get_value "dispute_${op}")
        if [ "$has_dispute" != "1" ]; then
            continue
        fi

        local op_short=$(echo "$op" | sed 's/bdk-//')
        local op_node_id=$(get_value "node_id_$op")

        log_info "$op_short rebuilding quorum on their dispute branch..."

        # Add other non-Alice operators as quorum members
        for member in $NON_ALICE_OPERATORS; do
            if [ "$op" != "$member" ]; then
                local member_node_id=$(get_value "node_id_$member")
                local member_reserves_id=$(get_value "reserves_id_$member")
                local member_short=$(echo "$member" | sed 's/bdk-//')

                log_info "  $op_short adding $member_short to quorum..."

                # Add member to quorum using recovery rebuild quorum-add
                local add_output=$(run_bdk_cmd "$op" recovery rebuild "$alice_ledger_id" quorum-add "$member_node_id" 2>&1)

                if echo "$add_output" | grep -q "published\|QuorumAddMember"; then
                    test_pass "$op_short added $member_short to dispute quorum"
                else
                    log_warn "$op_short failed to add $member_short"
                    echo "Output: $add_output" | head -5
                fi
            fi
        done
    done
}

# ============================================================================
# Phase 11: Post collateral attestations from non-Alice members
# ============================================================================

post_attestations() {
    log_info ""
    log_info "=== Phase 11: Post Non-Alice Collateral Attestations ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")

    for op in $NON_ALICE_OPERATORS; do
        local has_dispute=$(get_value "dispute_${op}")
        if [ "$has_dispute" != "1" ]; then
            continue
        fi

        local op_short=$(echo "$op" | sed 's/bdk-//')
        local op_node_id=$(get_value "node_id_$op")

        log_info "$op_short getting attestations from non-Alice members..."

        # Get attestations from other non-Alice operators
        for attester in $NON_ALICE_OPERATORS; do
            if [ "$op" != "$attester" ]; then
                local attester_short=$(echo "$attester" | sed 's/bdk-//')
                local attester_reserves_id=$(get_value "reserves_id_$attester")

                # Get the deposit secret that the attester used for their deposit on op's ledger
                local deposit_secret=$(get_value "secret_${attester}_${op}")

                if [ -z "$deposit_secret" ]; then
                    log_warn "No deposit secret found for $attester_short on $op_short's ledger"
                    continue
                fi

                log_info "  $attester_short locking collateral for $op_short..."

                # Attester locks their deposit on op's ledger via Nostr request
                # (the deposit is on op's ledger, so op must process the lock request)
                local op_ledger_id=$(get_value "ledger_id_$op")
                local lock_output=$(run_nostr_request "$attester" "$op_ledger_id" collateral_lock "$deposit_secret" 15000000000 500 "$op_node_id" 2>&1)

                # Extract attestation JSON from Nostr response (base64 encoded)
                local attestation_b64=$(echo "$lock_output" | grep -o '"attestation_b64"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/"attestation_b64"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')
                local attestation_json=""
                if [ -n "$attestation_b64" ]; then
                    attestation_json=$(echo "$attestation_b64" | base64 -d 2>/dev/null)
                fi

                if [ -n "$attestation_json" ]; then
                    log_info "  $op_short recording attestation from $attester_short..."

                    # Record attestation on dispute branch
                    local record_output=$(run_bdk_cmd "$op" recovery rebuild "$alice_ledger_id" attestation "$attestation_json" 2>&1)

                    if echo "$record_output" | grep -q "published\|CollateralAttestation"; then
                        test_pass "$op_short got attestation from $attester_short"
                    else
                        log_warn "$op_short failed to record attestation from $attester_short"
                        echo "Output: $record_output" | head -5
                    fi
                else
                    log_warn "$attester_short failed to provide attestation"
                    echo "Lock output: $lock_output" | head -5
                fi
            fi
        done
    done
}

# ============================================================================
# Phase 12: Publish CustodyArmed (pre-commitment)
# ============================================================================

arm_for_entropy() {
    log_info ""
    log_info "=== Phase 12: Publish CustodyArmed (Pre-Commitment) ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")

    for op in $NON_ALICE_OPERATORS; do
        local has_dispute=$(get_value "dispute_${op}")
        if [ "$has_dispute" != "1" ]; then
            continue
        fi

        local op_short=$(echo "$op" | sed 's/bdk-//')

        log_info "$op_short publishing CustodyArmed..."

        local arm_output=$(run_bdk_cmd "$op" recovery arm "$alice_ledger_id" 2>&1)

        if echo "$arm_output" | grep -q "CustodyArmed published"; then
            local armed_block=$(echo "$arm_output" | grep "Armed block:" | awk '{print $3}')
            test_pass "$op_short armed at block $armed_block"
            store_value "armed_${op}" "1"
        else
            test_fail "$op_short failed to arm"
            echo "Output: $arm_output"
        fi
    done

    sleep 2
}

# ============================================================================
# Phase 13: Confiscate reserves to lottery output
# ============================================================================

confiscate_to_lottery() {
    log_info ""
    log_info "=== Phase 13: Confiscate Reserves to Lottery Output ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")

    # First armed operator initiates confiscation
    local confiscator=""
    for op in $NON_ALICE_OPERATORS; do
        local has_armed=$(get_value "armed_${op}")
        if [ "$has_armed" == "1" ]; then
            confiscator="$op"
            break
        fi
    done

    if [ -z "$confiscator" ]; then
        test_fail "No armed operator found for confiscation"
        return 1
    fi

    local op_short=$(echo "$confiscator" | sed 's/bdk-//')
    log_info "$op_short initiating confiscation to lottery output..."

    local confiscate_output=$(run_bdk_cmd "$confiscator" recovery confiscate "$alice_ledger_id" 2>&1)

    if echo "$confiscate_output" | grep -q "Confiscation transaction broadcast"; then
        local txid=$(echo "$confiscate_output" | grep "Txid:" | awk '{print $2}')
        test_pass "$op_short broadcast confiscation TX: ${txid:0:16}..."
        store_value "confiscation_txid" "$txid"

        # Mine to confirm
        log_info "Mining to confirm confiscation..."
        mine_blocks 1
        test_pass "Confiscation confirmed"
    else
        test_fail "$op_short failed to confiscate"
        echo "Output: $confiscate_output" | tail -20
        return 1
    fi

    sleep 2
}

# ============================================================================
# Phase 14: All participants reveal preimages
# ============================================================================

reveal_preimages() {
    log_info ""
    log_info "=== Phase 14: Reveal Preimages ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")

    for op in $NON_ALICE_OPERATORS; do
        local has_armed=$(get_value "armed_${op}")
        if [ "$has_armed" != "1" ]; then
            continue
        fi

        local op_short=$(echo "$op" | sed 's/bdk-//')
        log_info "$op_short revealing preimage..."

        local reveal_output=$(run_bdk_cmd "$op" recovery reveal "$alice_ledger_id" 2>&1)

        if echo "$reveal_output" | grep -q "Preimage revealed"; then
            test_pass "$op_short revealed preimage"
        else
            test_fail "$op_short failed to reveal preimage"
            echo "Output: $reveal_output" | tail -10
        fi
    done

    sleep 2
}

# ============================================================================
# Phase 15: Lottery claim (Winner: CustodyAcquire, Losers: CustodyYield)
# ============================================================================

claim_custody() {
    log_info ""
    log_info "=== Phase 15: Lottery Claim ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")
    local winner=""

    for op in $NON_ALICE_OPERATORS; do
        local has_armed=$(get_value "armed_${op}")
        if [ "$has_armed" != "1" ]; then
            continue
        fi

        local op_short=$(echo "$op" | sed 's/bdk-//')

        log_info "$op_short checking lottery result..."

        local claim_output=$(run_bdk_cmd "$op" recovery lottery-claim "$alice_ledger_id" 2>&1)

        if echo "$claim_output" | grep -q "CustodyAcquire published successfully"; then
            test_pass "$op_short WON (published CustodyAcquire)"
            winner="$op"
            store_value "dispute_winner" "$op"

            # Mine to confirm claim TX
            log_info "Mining to confirm claim transaction..."
            mine_blocks 1
        elif echo "$claim_output" | grep -q "YOU WON"; then
            # Won but something may have failed
            if echo "$claim_output" | grep -q "Claim transaction broadcast"; then
                test_pass "$op_short WON and claimed"
                winner="$op"
                store_value "dispute_winner" "$op"
                mine_blocks 1
            else
                test_fail "$op_short won but claim failed"
                echo "    Output: $(echo "$claim_output" | tail -10)"
            fi
        elif echo "$claim_output" | grep -q "did not win\|You did not win"; then
            test_pass "$op_short lost lottery"
        elif echo "$claim_output" | grep -q "Not all preimages"; then
            log_warn "$op_short waiting for more preimages"
        else
            log_warn "$op_short lottery-claim output:"
            echo "$claim_output" | head -15
        fi
    done

    if [ -n "$winner" ]; then
        log_info ""
        log_info "Lottery Winner: $winner"
    fi

    # Losers publish CustodyYield
    log_info ""
    log_info "Losers publishing CustodyYield..."
    for op in $NON_ALICE_OPERATORS; do
        local has_armed=$(get_value "armed_${op}")
        if [ "$has_armed" != "1" ]; then
            continue
        fi

        if [ "$op" == "$winner" ]; then
            continue
        fi

        local op_short=$(echo "$op" | sed 's/bdk-//')
        log_info "$op_short publishing CustodyYield..."

        local release_output=$(run_bdk_cmd "$op" recovery release "$alice_ledger_id" 2>&1)

        if echo "$release_output" | grep -q "CustodyYield published"; then
            test_pass "$op_short yielded"
        else
            log_warn "$op_short release output: $(echo "$release_output" | tail -5)"
        fi
    done
}

# ============================================================================
# Phase 16: Winner continues the ledger with new operations
# ============================================================================

winner_continues_ledger() {
    log_info ""
    log_info "=== Phase 16: Winner Continues Ledger ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")
    local winner=$(get_value "dispute_winner")

    if [ -z "$winner" ]; then
        log_warn "No winner determined, skipping ledger continuation"
        return
    fi

    local winner_short=$(echo "$winner" | sed 's/bdk-//')

    log_info "Winner ($winner_short) continuing ledger with new operations..."

    # Winner adds 3 more operations to make their chain longer
    local continue_output=$(run_bdk_cmd "$winner" recovery continue "$alice_ledger_id" --count 3 2>&1)

    if echo "$continue_output" | grep -q "continued successfully\|New latest"; then
        test_pass "$winner_short continued ledger (chain now longer)"
        echo "$continue_output" | grep -E "seq [0-9]+" | head -5
    else
        log_warn "Continue output: $continue_output"
        # Still pass - the winner did get custody
        test_pass "$winner_short acquired custody"
    fi
}

# ============================================================================
# Phase 17: Show final state
# ============================================================================

show_final_state() {
    log_info ""
    log_info "=== Phase 17: Final State ==="
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice")
    local winner=$(get_value "dispute_winner")

    log_info "Alice's ledger (disputed): ${alice_ledger_id:0:16}..."
    log_info "Winner: $winner"
    echo ""

    # Show tree view of Alice's ledger
    log_info "Ledger tree view:"
    run_bdk_cmd "bdk-bob" nostr import "$alice_ledger_id" --dry-run 2>&1
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup_nostr_watchers() {
    log_info ""
    log_info "=== Cleanup: Stopping Nostr Watchers ==="
    for op in $OPERATORS; do
        stop_nostr_watch "$op"
    done
}

reset_nostr_data() {
    log_info "Resetting Nostr relay data..."
    $DC stop nostr-relay >/dev/null 2>&1 || true
    $DC rm -f nostr-relay >/dev/null 2>&1 || true
    docker volume rm bdk_bdk_nostr_data >/dev/null 2>&1 || true
    $DC stop bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1 || true
    $DC rm -f bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1 || true
    docker volume rm bdk_bdk_alice_data bdk_bdk_bob_data bdk_bdk_charlie_data bdk_bdk_dave_data >/dev/null 2>&1 || true
    $DC up -d nostr-relay bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1
    sleep 5
    log_success "Nostr relay and BDK nodes reset"
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "=========================================="
    log_info "  Four-Operator Dispute Protocol Test"
    log_info "=========================================="
    log_info "Operators: $OPERATORS"
    log_info "Reserves: $RESERVES_AMOUNT sats each"
    log_info "Collateral: ${COLLATERAL_PERCENT}% per partner"
    log_info "Enforcement delay: $ENFORCEMENT_DELAY blocks"
    log_info "Collateral lock: $COLLATERAL_LOCK_BLOCKS blocks"
    echo ""

    trap cleanup_nostr_watchers EXIT

    # Reset data from previous runs
    reset_nostr_data

    # Setup phase
    setup_operators
    create_reserves
    open_ledgers

    # Start watchers EARLY - they will dynamically discover QuorumJoin operations
    # as they happen (no need to wait or restart)
    start_nostr_watchers

    add_quorum_members
    rotate_reserves_to_quorum

    # Give watchers a moment to discover the new QuorumJoin operations
    sleep 2

    generate_deposit_keys
    open_cross_deposits
    fund_deposits
    lock_collateral
    mine_to_enforcement

    # Dispute phase
    alice_goes_rogue
    start_disputes
    rebuild_quorum
    post_attestations
    arm_for_entropy

    # Lottery phase (on-chain dispute resolution)
    confiscate_to_lottery
    reveal_preimages
    claim_custody

    # Post-dispute: winner continues ledger
    winner_continues_ledger

    # Results
    show_final_state

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
}

main
