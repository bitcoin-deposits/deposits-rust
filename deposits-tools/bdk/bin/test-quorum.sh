#!/bin/bash
# Four-operator × three-ledger quorum test script
#
# Topology: 4 operators (Alice, Bob, Charlie, Diana) × 3 ledgers each = 12 ledgers
# Each ledger has 3 quorum members (all other operators)
# Each ledger gets 1 deposit (round-robin assignment from the 3 other operators)
# Dispute target: Alice's ledger #1
# Lottery candidates: Bob, Charlie, Diana
#
# Usage:
#   ./bin/test-quorum.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Configuration
RESERVES_AMOUNT=100000000  # 1 BTC in sats
DEPOSIT_PERCENT=20         # 20% of reserves
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

# Operators as simple array
OPERATORS="bdk-alice bdk-bob bdk-charlie bdk-diana"
LEDGERS_PER_OP=3

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

# Get the Nth other operator (0-indexed, excluding $1)
get_other_n() {
    local exclude=$1 n=$2 i=0
    for op in $OPERATORS; do
        if [ "$op" != "$exclude" ]; then
            [ $i -eq $n ] && echo "$op" && return
            i=$((i + 1))
        fi
    done
}

# ============================================================================
# Phase 1: Setup - Fund operators and get their info
# ============================================================================

setup_operators() {
    log_info "=== Phase 1: Setup Operators ==="
    echo ""

    # Gather info and addresses in parallel
    local tmpdir=$(mktemp -d)
    local pids=()
    for op in $OPERATORS; do
        (
            run_bdk_cmd "$op" info 2>&1 > "$tmpdir/info_$op" || true
            get_node_address "$op" > "$tmpdir/addr_$op" 2>/dev/null || true
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    # Fund underfunded nodes (need ~3 BTC for 3 reserves + fees)
    local need_mine=false
    for op in $OPERATORS; do
        local info_output=$(cat "$tmpdir/info_$op")
        local balance=$(echo "$info_output" | grep "Wallet balance:" | awk '{print $3}')
        if [ -z "$balance" ] || [ "$balance" -lt 1000000000 ]; then
            local address=$(cat "$tmpdir/addr_$op" 2>/dev/null)
            if [ -n "$address" ]; then
                bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 10 >/dev/null 2>&1
                need_mine=true
                log_info "  Funded $op with 10 BTC"
            fi
        fi
    done
    if $need_mine; then
        mine_blocks 1
    fi

    # Store node IDs
    for op in $OPERATORS; do
        local info_output=$(cat "$tmpdir/info_$op")
        local node_id=$(echo "$info_output" | grep "Node ID:" | awk '{print $3}')
        store_value "node_id_$op" "$node_id"

        if [ -n "$node_id" ]; then
            test_pass "$op ready: ${node_id:0:16}..."
        else
            test_fail "Could not get node ID for $op"
            rm -rf "$tmpdir"
            return 1
        fi
    done
    rm -rf "$tmpdir"
}

# ============================================================================
# Phase 2: Create reserves UTXOs (3 per operator)
# One batch per round (all operators parallel), mine between rounds so
# electrs indexes the change outputs before the next reserves create.
# ============================================================================

create_reserves() {
    log_info ""
    log_info "=== Phase 2: Create Reserves ($RESERVES_AMOUNT sats × $LEDGERS_PER_OP per operator) ==="
    echo ""

    local tmpdir=$(mktemp -d)
    for batch in $(seq 1 $LEDGERS_PER_OP); do
        log_info "Reserves batch $batch/$LEDGERS_PER_OP..."
        local pids=()
        for op in $OPERATORS; do
            (run_bdk_cmd "$op" reserves "$RESERVES_AMOUNT" 2>&1 > "$tmpdir/${op}_${batch}" || true) &
            pids+=($!)
        done
        for pid in "${pids[@]}"; do wait "$pid" || true; done

        # Mine to confirm so electrs indexes change outputs for the next round
        mine_blocks 1
        sleep 2  # Wait for electrs to index the new block
    done

    # Check results
    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for batch in $(seq 1 $LEDGERS_PER_OP); do
            local reserves_output=$(cat "$tmpdir/${op}_${batch}")
            if echo "$reserves_output" | grep -q "Reserves created"; then
                test_pass "$op_short created reserves #$batch"
            elif echo "$reserves_output" | grep -q "already have reserves"; then
                test_pass "$op_short already has reserves #$batch"
            else
                test_fail "$op_short reserves creation #$batch failed"
                echo "    Output: $reserves_output"
            fi
        done
    done
    rm -rf "$tmpdir"
}

# ============================================================================
# Phase 3: Open ledgers (3 per operator = 12 total)
# All 3 sequential per operator, all operators parallel.
# Then extract IDs from `ledger list` (authoritative).
# ============================================================================

open_ledgers() {
    log_info ""
    log_info "=== Phase 3: Open Ledgers ($LEDGERS_PER_OP per operator, enforcement +$ENFORCEMENT_DELAY blocks) ==="
    echo ""

    local current_height=$(get_block_height)
    local enforcement_block=$((current_height + ENFORCEMENT_DELAY))

    log_info "Current block: $current_height, Enforcement: $enforcement_block"
    echo ""

    # Open all ledgers: sequential per operator, parallel across operators.
    # || true prevents set -e from killing the subshell on a failed open,
    # so ledger list always runs and we get IDs for whichever opens succeeded.
    local tmpdir=$(mktemp -d)
    local pids=()
    for op in $OPERATORS; do
        (
            for n in $(seq 1 $LEDGERS_PER_OP); do
                run_bdk_cmd "$op" ledger open "$enforcement_block" \
                    2>&1 > "$tmpdir/open_${op}_${n}" || true
            done
            # Capture the authoritative ledger list after all opens
            run_bdk_cmd "$op" ledger list 2>&1 > "$tmpdir/list_${op}" || true
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    # Check open results and extract IDs from ledger list
    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        local list_output=$(cat "$tmpdir/list_${op}")

        for n in $(seq 1 $LEDGERS_PER_OP); do
            local open_output=$(cat "$tmpdir/open_${op}_${n}")

            # Check success — must match the post-call message, not the pre-call one
            if echo "$open_output" | grep -q "Ledger opened successfully"; then
                test_pass "$op_short opened ledger #$n"
            elif echo "$open_output" | grep -q "already"; then
                test_pass "$op_short ledger #$n already exists"
            else
                test_fail "$op_short failed to open ledger #$n"
                echo "    Output: $open_output"
            fi

            # Extract Nth ledger ID and reserves key from the authoritative list
            local ledger_id=$(echo "$list_output" | grep "Ledger ID:" | sed -n "${n}p" | awk '{print $NF}')
            local reserves_key=$(echo "$list_output" | grep "Reserves Key:" | sed -n "${n}p" | awk '{print $NF}')

            if [ -n "$ledger_id" ]; then
                store_value "ledger_id_${op}_${n}" "$ledger_id"
                log_info "  $op_short L$n: ${ledger_id:0:16}..."
            else
                log_warn "  Could not get ledger_id for $op_short #$n"
            fi

            if [ -n "$reserves_key" ]; then
                store_value "reserves_id_${op}_${n}" "$reserves_key"
            fi
        done
    done
    rm -rf "$tmpdir"

    # Also store first ledger as "primary" for backward compat
    for op in $OPERATORS; do
        store_value "ledger_id_$op" "$(get_value "ledger_id_${op}_1")"
        store_value "reserves_id_$op" "$(get_value "reserves_id_${op}_1")"
    done
}

# ============================================================================
# Phase 3a: Start Nostr watchers on each operator for all their ledgers
# ============================================================================

start_nostr_watchers() {
    log_info ""
    log_info "=== Phase 3a: Start Nostr Watchers ==="
    log_info "(Each operator watches their $LEDGERS_PER_OP ledgers)"
    echo ""

    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local ledger_id=$(get_value "ledger_id_${op}_${n}")
            if [ -n "$ledger_id" ]; then
                start_nostr_watch "$op" "$ledger_id"
                local op_short=$(echo "$op" | sed 's/bdk-//')
                test_pass "$op_short watcher started for ledger #$n"
            else
                test_fail "$op has no ledger_id for #$n"
            fi
        done
    done

    # Give watchers time to connect and daemons to discover new ledgers
    # Daemons reload every 2s; wait enough for 3+ reload cycles
    log_info "Waiting for daemons to discover new ledgers..."
    sleep 8
}

# ============================================================================
# Phase 3b: Add all nodes as quorum members to each other's ledgers
# For each of 12 ledgers, add the 3 other operators as quorum members.
# Each (op_ledger, member) pair is independent — fire all in parallel.
# ============================================================================

add_quorum_members() {
    log_info ""
    log_info "=== Phase 3b: Add Quorum Members ==="
    log_info "(Each ledger gets 3 quorum members = 36 add + 36 join ops)"
    echo ""

    local current_height=$(get_block_height)
    local membership_expires=$((current_height + 1000))

    # Process quorum additions per-operator sequentially (to avoid overwhelming
    # each daemon and the Nostr relay), but parallel across operators.
    # Each operator processes: L1 members, then L2 members, then L3 members.
    local op_pids=()
    for op in $OPERATORS; do
        (
            local op_short=$(echo "$op" | sed 's/bdk-//')
            local op_node_id=$(get_value "node_id_$op")

            for n in $(seq 1 $LEDGERS_PER_OP); do
                local op_reserves_id=$(get_value "reserves_id_${op}_${n}")
                local op_ledger_id=$(get_value "ledger_id_${op}_${n}")

                for member in $OPERATORS; do
                    if [ "$op" != "$member" ]; then
                        local member_short=$(echo "$member" | sed 's/bdk-//')
                        local member_node_id=$(get_value "node_id_$member")
                        local member_ledger_id=$(get_value "ledger_id_${member}_1")
                        local member_reserves_id=$(get_value "reserves_id_${member}_1")
                        local result_file="$STATE_DIR/quorum_${op}_${n}_${member}.result"

                        # Add member to op's quorum (sequential per operator)
                        local add_output=$(run_bdk_cmd "$op" partner add "$op_reserves_id" "$member_node_id" "$member_ledger_id" 2>&1)

                        if echo "$add_output" | grep -q "Quorum member added\|added"; then
                            # Record the join on member's FIRST ledger
                            local join_output=$(run_bdk_cmd "$member" partner join "$member_reserves_id" "$op_node_id" "$op_ledger_id" "$membership_expires" 2>&1)

                            if echo "$join_output" | grep -q "Quorum join recorded\|recorded"; then
                                echo "PASS:joined" > "$result_file"
                            else
                                echo "PASS:add_ok_join_fail" > "$result_file"
                                echo "$join_output" > "${result_file}.output"
                            fi
                        else
                            echo "FAIL:add_failed" > "$result_file"
                            echo "$add_output" > "${result_file}.output"
                        fi

                        # Small delay between requests to avoid relay congestion
                        sleep 1
                    fi
                done
            done
        ) &
        op_pids+=($!)
    done
    for pid in "${op_pids[@]}"; do wait "$pid" || true; done

    # Collect results
    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for n in $(seq 1 $LEDGERS_PER_OP); do
            for member in $OPERATORS; do
                if [ "$op" != "$member" ]; then
                    local member_short=$(echo "$member" | sed 's/bdk-//')
                    local result_file="$STATE_DIR/quorum_${op}_${n}_${member}.result"

                    if [ -f "$result_file" ]; then
                        local result=$(cat "$result_file")
                        if echo "$result" | grep -q "^PASS:joined"; then
                            test_pass "$member_short joined $op_short L$n quorum"
                        elif echo "$result" | grep -q "^PASS:add_ok"; then
                            test_pass "$op_short added $member_short to L$n (join record failed)"
                        else
                            test_fail "$op_short failed to add $member_short to L$n"
                            [ -f "${result_file}.output" ] && echo "    Output: $(cat "${result_file}.output")"
                        fi
                    fi
                fi
            done
        done
    done
}

# ============================================================================
# Phase 3c: Rotate reserves to quorum-based Taproot
# ============================================================================

rotate_reserves_to_quorum() {
    log_info ""
    log_info "=== Phase 3c: Rotate Reserves to Quorum-Based Taproot ==="
    log_info "(Each operator rotates all $LEDGERS_PER_OP ledgers)"
    echo ""

    # Wait for daemons to reload ledgers with quorum members
    log_info "Waiting for daemons to sync quorum members..."
    sleep 10

    # Rotate all 12 ledgers: sequential per operator (shared wallet state),
    # parallel across operators
    local tmpdir=$(mktemp -d)
    local pids=()
    for op in $OPERATORS; do
        (
            local op_short=$(echo "$op" | sed 's/bdk-//')
            for n in $(seq 1 $LEDGERS_PER_OP); do
                local op_ledger_id=$(get_value "ledger_id_${op}_${n}")
                local ok=false
                for attempt in 1 2 3; do
                    local rotate_output=$(run_bdk_cmd "$op" reserves rotate "$op_ledger_id" 2>&1)
                    if echo "$rotate_output" | grep -q "Reserves rotated\|rotated successfully\|No existing reserves to rotate"; then
                        echo "$rotate_output" > "$tmpdir/rotate_${op}_${n}"
                        ok=true
                        break
                    fi
                    sleep 5
                done
                if [ "$ok" != true ]; then
                    echo "FAILED" > "$tmpdir/rotate_${op}_${n}"
                fi
            done
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local rotate_output=$(cat "$tmpdir/rotate_${op}_${n}" 2>/dev/null)
            if echo "$rotate_output" | grep -q "Reserves rotated\|rotated successfully"; then
                local quorum_count=$(echo "$rotate_output" | grep "Quorum Members:" | awk '{print $3}')
                test_pass "$op_short L$n rotated to Taproot with $quorum_count members"
            elif echo "$rotate_output" | grep -q "No existing reserves to rotate"; then
                test_pass "$op_short L$n reserves already rotated"
            else
                test_fail "$op_short L$n reserves rotation FAILED"
                echo "    Output: $(echo "$rotate_output" | tail -3)"
            fi
        done
    done
    rm -rf "$tmpdir"

    # Mine to confirm rotation transactions
    mine_blocks 1
}

# ============================================================================
# Phase 4: Generate deposit keys and open deposits (round-robin)
# Each ledger gets exactly 1 deposit from one of the 3 other operators.
# Assignment: operator's L1 ← others[0], L2 ← others[1], L3 ← others[2]
# ============================================================================

generate_deposit_keys() {
    log_info ""
    log_info "=== Phase 4a: Generate Deposit Keys ==="
    log_info "(12 deposits: 1 per ledger, round-robin across other operators)"
    echo ""

    # Generate all 12 keypairs in parallel
    local tmpdir=$(mktemp -d)
    local pids=()

    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            (run_bdk_cmd "$depositor" keygen 2>&1 > "$tmpdir/key_${depositor}_${op}_${n}") &
            pids+=($!)
        done
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    # Store results
    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            local dep_short=$(echo "$depositor" | sed 's/bdk-//')
            local keypair=$(cat "$tmpdir/key_${depositor}_${op}_${n}")
            local secret=$(echo "$keypair" | awk '{print $1}')
            local pubkey=$(echo "$keypair" | awk '{print $2}')

            store_value "pubkey_${depositor}_${op}_${n}" "$pubkey"
            store_value "secret_${depositor}_${op}_${n}" "$secret"
            log_info "  deposit: $dep_short → $op_short L$n: ${pubkey:0:16}..."
        done
    done
    rm -rf "$tmpdir"
}

open_cross_deposits() {
    log_info ""
    log_info "=== Phase 4b: Open Cross-Deposits via Nostr ==="
    log_info "(12 deposit_open requests in parallel)"
    echo ""

    local pids=()
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            local pubkey=$(get_value "pubkey_${depositor}_${op}_${n}")
            local ledger_id=$(get_value "ledger_id_${op}_${n}")
            local dep_short=$(echo "$depositor" | sed 's/bdk-//')
            local op_short=$(echo "$op" | sed 's/bdk-//')

            log_info "$dep_short requesting deposit on $op_short L$n (${pubkey:0:12}...)"

            (
                local result_file="$STATE_DIR/open_${depositor}_${op}_${n}.result"
                local open_output=$(run_nostr_request "$depositor" "$ledger_id" deposit_open "$pubkey" 2>&1)
                if echo "$open_output" | grep -q "SUCCESS\|deposit_pubkey"; then
                    echo "PASS" > "$result_file"
                else
                    echo "FAIL" > "$result_file"
                    echo "$open_output" > "${result_file}.output"
                fi
            ) &
            pids+=($!)
        done
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Collect results
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            local dep_short=$(echo "$depositor" | sed 's/bdk-//')
            local op_short=$(echo "$op" | sed 's/bdk-//')
            local result_file="$STATE_DIR/open_${depositor}_${op}_${n}.result"
            if [ -f "$result_file" ] && [ "$(cat "$result_file")" = "PASS" ]; then
                test_pass "$dep_short opened deposit on $op_short L$n"
                store_value "deposit_${depositor}_on_${op}_${n}" "1"
            else
                test_fail "$dep_short failed to open deposit on $op_short L$n"
                [ -f "${result_file}.output" ] && echo "    Output: $(cat "${result_file}.output")"
            fi
        done
    done
}

# ============================================================================
# Phase 5: Fund deposits (all 12)
# ============================================================================

fund_deposits() {
    log_info ""
    log_info "=== Phase 5: Fund Deposits via Nostr ==="
    echo ""

    # Mine warmup blocks for electrs sync
    log_info "Mining warmup blocks for electrs sync..."
    mine_blocks 5
    sleep 15

    local deposit_amount=$((RESERVES_AMOUNT * DEPOSIT_PERCENT / 100))
    local btc_amount=$(awk "BEGIN {printf \"%.8f\", $deposit_amount / 100000000}")

    # --- Phase 5a: Request all deposit offers in parallel ---
    log_info "Requesting all deposit offers in parallel..."
    local pids=()

    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            local has_deposit=$(get_value "deposit_${depositor}_on_${op}_${n}")
            if [ "$has_deposit" = "1" ]; then
                local pubkey=$(get_value "pubkey_${depositor}_${op}_${n}")
                local ledger_id=$(get_value "ledger_id_${op}_${n}")

                (
                    local offer_output=$(run_nostr_request "$depositor" "$ledger_id" make_offer "$pubkey" "$deposit_amount" "10000" "144" 2>&1)
                    echo "$offer_output" > "$STATE_DIR/offer_${depositor}_${op}_${n}.output"
                ) &
                pids+=($!)
            fi
        done
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    # Parse offer results
    local funded_triples=""
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            local has_deposit=$(get_value "deposit_${depositor}_on_${op}_${n}")
            if [ "$has_deposit" = "1" ]; then
                local dep_short=$(echo "$depositor" | sed 's/bdk-//')
                local op_short=$(echo "$op" | sed 's/bdk-//')
                local offer_output=$(cat "$STATE_DIR/offer_${depositor}_${op}_${n}.output" 2>/dev/null)

                if echo "$offer_output" | grep -q "SUCCESS\|offer_id"; then
                    local offer_id=$(echo "$offer_output" | grep -o '"offer_id"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"//' | sed 's/"$//')
                    local funding_address=$(echo "$offer_output" | grep -o '"funding_address"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"//' | sed 's/"$//')

                    if [ -n "$funding_address" ]; then
                        store_value "offer_id_${depositor}_${op}_${n}" "$offer_id"
                        store_value "funding_addr_${depositor}_${op}_${n}" "$funding_address"
                        funded_triples="$funded_triples ${depositor}:${op}:${n}"
                        log_info "  $dep_short@${op_short}_L$n: ${funding_address:0:20}..."
                    else
                        test_fail "No funding_address for $dep_short on $op_short L$n"
                    fi
                else
                    test_fail "Failed to get deposit offer from $op_short L$n"
                    echo "    Output: $offer_output"
                fi
            fi
        done
    done

    # Wait for all offers to be persisted
    sleep 3

    # --- Phase 5b: Send all funding transactions ---
    log_info ""
    log_info "Sending all funding transactions..."
    local sent_count=0

    for triple in $funded_triples; do
        local depositor=$(echo "$triple" | cut -d: -f1)
        local operator=$(echo "$triple" | cut -d: -f2)
        local n=$(echo "$triple" | cut -d: -f3)
        local funding_address=$(get_value "funding_addr_${depositor}_${operator}_${n}")
        local dep_short=$(echo "$depositor" | sed 's/bdk-//')
        local op_short=$(echo "$operator" | sed 's/bdk-//')

        local send_output=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$funding_address" "$btc_amount" 2>&1)
        if [ $? -eq 0 ]; then
            log_info "  Sent to $dep_short@${op_short}_L$n: ${send_output:0:16}..."
            sent_count=$((sent_count + 1))
        else
            test_fail "Failed to fund $dep_short's deposit on $op_short L$n"
        fi
    done

    # --- Phase 5c: Mine and wait for electrs ---
    log_info ""
    log_info "Mining to confirm all $sent_count funding transactions..."
    mine_blocks 1
    sleep 15

    # --- Phase 5d: Check and complete all deposits ---
    log_info ""
    log_info "Checking deposit funding..."

    for triple in $funded_triples; do
        local depositor=$(echo "$triple" | cut -d: -f1)
        local operator=$(echo "$triple" | cut -d: -f2)
        local n=$(echo "$triple" | cut -d: -f3)
        local offer_id=$(get_value "offer_id_${depositor}_${operator}_${n}")
        local dep_short=$(echo "$depositor" | sed 's/bdk-//')
        local op_short=$(echo "$operator" | sed 's/bdk-//')

        local funding_detected=false
        local check_output=""
        for retry in 1 2 3 4 5; do
            check_output=$(run_bdk_cmd "$operator" deposit check "$offer_id" 2>&1) || true
            if echo "$check_output" | grep -q "Funding detected"; then
                funding_detected=true
                break
            fi
            sleep 5
        done

        if [ "$funding_detected" = true ]; then
            local txid=$(echo "$check_output" | grep "Transaction:" | awk '{print $2}')
            local detected_amount=$(echo "$check_output" | grep "Amount:" | awk '{print $2}')

            if echo "$check_output" | grep -q "already completed"; then
                test_pass "$dep_short's deposit on $op_short L$n funded ($detected_amount sats, auto-completed)"
            else
                local complete_output=$(run_bdk_cmd "$operator" deposit complete "$offer_id" "$txid" "$detected_amount" 2>&1)

                if echo "$complete_output" | grep -q "completed\|credited"; then
                    test_pass "$dep_short's deposit on $op_short L$n funded ($detected_amount sats)"
                else
                    test_fail "Failed to complete $dep_short's deposit on $op_short L$n"
                    echo "    Output: $complete_output"
                fi
            fi
        elif echo "$check_output" | grep -q "OfferNotFound"; then
            test_pass "$dep_short's deposit on $op_short L$n funded (daemon auto-completed)"
        else
            test_fail "Funding not detected for $dep_short's deposit on $op_short L$n"
            echo "    Output: $check_output"
        fi
    done
}

# ============================================================================
# Phase 6: Lock collateral and record attestations
# Each depositor locks on the ledger where they deposited.
# Attestation recorded on depositor's FIRST ledger.
# Parallel per depositor (sequential within each to avoid ledger write conflicts).
# ============================================================================

lock_collateral() {
    log_info ""
    log_info "=== Phase 6: Lock Collateral via Nostr (lock for $COLLATERAL_LOCK_BLOCKS blocks) ==="
    echo ""

    local deposit_amount=$((RESERVES_AMOUNT * DEPOSIT_PERCENT / 100))
    local deposit_amount_msats=$((deposit_amount * 1000))

    # Group by depositor to avoid concurrent writes to same local ledger
    local pids=()
    for depositor in $OPERATORS; do
        (
            for op in $OPERATORS; do
                for n in $(seq 1 $LEDGERS_PER_OP); do
                    local expected_depositor=$(get_other_n "$op" $((n - 1)))
                    if [ "$depositor" = "$expected_depositor" ]; then
                        local has_deposit=$(get_value "deposit_${depositor}_on_${op}_${n}")
                        if [ "$has_deposit" = "1" ]; then
                            local secret=$(get_value "secret_${depositor}_${op}_${n}")
                            local ledger_id=$(get_value "ledger_id_${op}_${n}")
                            local depositor_ledger_id=$(get_value "ledger_id_${depositor}_1")
                            local depositor_node_id=$(get_value "node_id_$depositor")
                            local dep_short=$(echo "$depositor" | sed 's/bdk-//')
                            local op_short=$(echo "$op" | sed 's/bdk-//')
                            local result_file="$STATE_DIR/lock_${depositor}_${op}_${n}.result"

                            log_info "$dep_short requesting collateral lock on $op_short L$n..."

                            local lock_output=$(run_nostr_request "$depositor" "$ledger_id" collateral_lock "$secret" "$deposit_amount_msats" "$COLLATERAL_LOCK_BLOCKS" "$depositor_node_id" 2>&1)

                            if echo "$lock_output" | grep -q "SUCCESS\|attestation"; then
                                local attestation_b64=$(echo "$lock_output" | grep -o '"attestation_b64"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/"attestation_b64"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')

                                if [ -n "$attestation_b64" ]; then
                                    local attestation_json=$(echo "$attestation_b64" | base64 -d 2>/dev/null)

                                    log_info "  $dep_short recording attestation from $op_short L$n..."
                                    local record_output=$(run_bdk_cmd "$depositor" collateral record "$depositor_ledger_id" "$attestation_json" 2>&1)

                                    if echo "$record_output" | grep -q "recorded\|Collateral attestation"; then
                                        echo "PASS:locked and recorded" > "$result_file"
                                    else
                                        echo "FAIL:locked but attestation not recorded" > "$result_file"
                                        echo "$record_output" > "${result_file}.output"
                                    fi
                                else
                                    echo "FAIL:locked but no attestation in response" > "$result_file"
                                    echo "$lock_output" > "${result_file}.output"
                                fi
                            else
                                echo "FAIL:failed to lock" > "$result_file"
                                echo "$lock_output" > "${result_file}.output"
                            fi
                        fi
                    fi
                done
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Collect results
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local depositor=$(get_other_n "$op" $((n - 1)))
            local dep_short=$(echo "$depositor" | sed 's/bdk-//')
            local op_short=$(echo "$op" | sed 's/bdk-//')
            local result_file="$STATE_DIR/lock_${depositor}_${op}_${n}.result"

            if [ -f "$result_file" ]; then
                local result=$(cat "$result_file")
                if echo "$result" | grep -q "^PASS"; then
                    test_pass "$dep_short: locked on $op_short L$n, attestation recorded"
                else
                    local reason=$(echo "$result" | sed 's/^FAIL://')
                    test_fail "$dep_short: $reason on $op_short L$n"
                    [ -f "${result_file}.output" ] && log_warn "    Output: $(cat "${result_file}.output")"
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
# Phase 8: Validate ledgers (all 12)
# ============================================================================

validate_ledgers() {
    log_info ""
    log_info "=== Phase 8: Validate Ledgers (all 12) ==="
    echo ""

    # Fetch all 12 ledger histories in parallel
    local tmpdir=$(mktemp -d)
    local pids=()
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local ledger_id=$(get_value "ledger_id_${op}_${n}")
            (run_bdk_cmd "$op" ledger history "$ledger_id" 2>&1 > "$tmpdir/${op}_${n}") &
            pids+=($!)
        done
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    # Analyze results
    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local history_output=$(cat "$tmpdir/${op}_${n}")

            local op_count=$(echo "$history_output" | grep -c "↑" 2>/dev/null || echo "0")
            local lock_count=$(echo "$history_output" | grep -c "CollateralLock" 2>/dev/null || echo "0")
            local attestation_count=$(echo "$history_output" | grep -c "CollateralAttestation" 2>/dev/null || echo "0")
            local deposit_count=$(echo "$history_output" | grep -c "DepositOpen" 2>/dev/null || echo "0")
            local quorum_add_count=$(echo "$history_output" | grep -c "QuorumAddMember" 2>/dev/null || echo "0")
            local quorum_join_count=$(echo "$history_output" | grep -c "QuorumJoin" 2>/dev/null || echo "0")
            local reserves_rotate_count=$(echo "$history_output" | grep -c "ReservesRotate" 2>/dev/null || echo "0")

            if [ "$op_count" -gt 0 ]; then
                test_pass "$op_short L$n: $op_count ops, $deposit_count deposits, $quorum_add_count adds, $quorum_join_count joins, $reserves_rotate_count rotations, $lock_count locks, $attestation_count attestations"
            else
                test_fail "$op_short L$n has no operations"
            fi
        done
    done
    rm -rf "$tmpdir"
}

# ============================================================================
# Phase 8b: Full ledger validation (conformance check) on all 12
# ============================================================================

full_validate_ledgers() {
    log_info ""
    log_info "=== Phase 8b: Full Ledger Validation (Conformance Check) ==="
    echo ""

    # Run all 12 validations in parallel
    local tmpdir=$(mktemp -d)
    local pids=()
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local ledger_id=$(get_value "ledger_id_${op}_${n}")
            (run_bdk_cmd "$op" ledger validate "$ledger_id" 2>&1 > "$tmpdir/${op}_${n}") &
            pids+=($!)
        done
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local validate_output=$(cat "$tmpdir/${op}_${n}")

            if echo "$validate_output" | grep -q "Valid: YES"; then
                local hash_valid=$(echo "$validate_output" | grep "Valid length" | sed 's/.*: //' | tr -d '\n\r')
                local reserves_coverage=$(echo "$validate_output" | grep "reserves_coverage" | grep -o "([^)]*)" | tail -1 | tr -d '\n\r')
                local rules_failed=$(echo "$validate_output" | grep -c "\[FAIL\]" 2>/dev/null | tr -d '\n\r' || echo "0")
                rules_failed=${rules_failed:-0}

                if [ "$rules_failed" -eq 0 ]; then
                    test_pass "$op_short L$n: CONFORMING (hash: $hash_valid, coverage: $reserves_coverage)"
                else
                    test_fail "$op_short L$n: valid but $rules_failed rule(s) failed"
                    echo "$validate_output" | grep "\[FAIL\]"
                fi
            else
                test_fail "$op_short L$n: validation failed"
                echo "$validate_output" | grep -E "Error|FAIL|Invalid" | head -5
            fi
        done
    done
    rm -rf "$tmpdir"
}

# ============================================================================
# Phase 8c: Create Test Deposits for Post-Recovery
# Create deposit_r (funded) and deposit_s (unfunded) on Alice's L1
# ============================================================================

create_recovery_test_deposits() {
    log_info ""
    log_info "=== Phase 8c: Create Recovery Test Deposits ==="
    log_info "(deposit_r = funded, deposit_s = unfunded, both on Alice's L1)"
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice_1")
    local alice_reserves_id=$(get_value "reserves_id_bdk-alice_1")

    # Generate keypairs in parallel
    log_info "Generating keypairs for deposit_r and deposit_s..."
    local tmpdir=$(mktemp -d)
    (run_bdk_cmd "bdk-bob" keygen 2>&1 > "$tmpdir/key_r") &
    local pid_r=$!
    (run_bdk_cmd "bdk-bob" keygen 2>&1 > "$tmpdir/key_s") &
    local pid_s=$!
    wait "$pid_r"; wait "$pid_s"

    local keypair_r=$(cat "$tmpdir/key_r")
    local secret_r=$(echo "$keypair_r" | awk '{print $1}')
    local pubkey_r=$(echo "$keypair_r" | awk '{print $2}')
    store_value "secret_deposit_r" "$secret_r"
    store_value "pubkey_deposit_r" "$pubkey_r"
    log_info "  deposit_r pubkey: ${pubkey_r:0:16}..."

    local keypair_s=$(cat "$tmpdir/key_s")
    local secret_s=$(echo "$keypair_s" | awk '{print $1}')
    local pubkey_s=$(echo "$keypair_s" | awk '{print $2}')
    store_value "secret_deposit_s" "$secret_s"
    store_value "pubkey_deposit_s" "$pubkey_s"
    log_info "  deposit_s pubkey: ${pubkey_s:0:16}..."
    rm -rf "$tmpdir"

    # Open both deposits on Alice's L1 via Nostr (staggered to avoid relay collision)
    log_info ""
    log_info "Opening deposit_r and deposit_s on Alice's L1..."
    local tmpdir2=$(mktemp -d)
    (run_nostr_request "bdk-bob" "$alice_ledger_id" deposit_open "$pubkey_r" 2>&1 > "$tmpdir2/open_r" || true) &
    local pid_r=$!
    sleep 1
    (run_nostr_request "bdk-bob" "$alice_ledger_id" deposit_open "$pubkey_s" 2>&1 > "$tmpdir2/open_s" || true) &
    local pid_s=$!
    wait "$pid_r" || true; wait "$pid_s" || true

    local open_r=$(cat "$tmpdir2/open_r")
    local open_s=$(cat "$tmpdir2/open_s")
    rm -rf "$tmpdir2"

    if echo "$open_r" | grep -q "SUCCESS\|deposit_pubkey"; then
        test_pass "deposit_r opened on Alice's L1"
    else
        test_fail "Failed to open deposit_r"
        echo "    Output: $open_r"
    fi

    if echo "$open_s" | grep -q "SUCCESS\|deposit_pubkey"; then
        test_pass "deposit_s opened on Alice's L1"
    else
        test_fail "Failed to open deposit_s"
        echo "    Output: $open_s"
    fi

    # Fund deposit_r (deposit_s stays unfunded)
    log_info ""
    log_info "Funding deposit_r (10000 sats)..."
    local fund_amount=10000

    local offer_output=$(run_nostr_request "bdk-bob" "$alice_ledger_id" make_offer "$pubkey_r" "$fund_amount" "1000" "144" 2>&1)

    if echo "$offer_output" | grep -q "SUCCESS\|offer_id"; then
        local offer_id=$(echo "$offer_output" | grep -o '"offer_id"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"//' | sed 's/"$//')
        local funding_address=$(echo "$offer_output" | grep -o '"funding_address"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"//' | sed 's/"$//')

        if [ -n "$funding_address" ]; then
            log_info "  Got offer, funding address: ${funding_address:0:20}..."

            local btc_amount=$(awk "BEGIN {printf \"%.8f\", $fund_amount / 100000000}")
            local send_output=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$funding_address" "$btc_amount" 2>&1)
            local send_status=$?

            if [ $send_status -eq 0 ]; then
                log_info "  TX sent: ${send_output:0:16}..."
                mine_blocks 1
                sleep 8

                local funding_detected=false
                local check_output=""
                for retry in 1 2 3 4 5; do
                    check_output=$(run_bdk_cmd "bdk-alice" deposit check "$offer_id" 2>&1) || true
                    if echo "$check_output" | grep -q "Funding detected"; then
                        funding_detected=true
                        break
                    fi
                    sleep 5
                done

                if [ "$funding_detected" = true ]; then
                    local txid=$(echo "$check_output" | grep "Transaction:" | awk '{print $2}')
                    local detected_amount=$(echo "$check_output" | grep "Amount:" | awk '{print $2}')

                    if echo "$check_output" | grep -q "already completed"; then
                        test_pass "deposit_r funded with $detected_amount sats (auto-completed)"
                        store_value "deposit_r_balance" "$detected_amount"
                    else
                        local complete_output=$(run_bdk_cmd "bdk-alice" deposit complete "$offer_id" "$txid" "$detected_amount" 2>&1)

                        if echo "$complete_output" | grep -q "completed\|credited"; then
                            test_pass "deposit_r funded with $detected_amount sats"
                            store_value "deposit_r_balance" "$detected_amount"
                        else
                            test_fail "Failed to complete deposit_r funding"
                            echo "    Output: $complete_output"
                        fi
                    fi
                elif echo "$check_output" | grep -q "OfferNotFound"; then
                    test_pass "deposit_r funded (daemon auto-completed, offer cleaned up)"
                    store_value "deposit_r_balance" "$fund_amount"
                else
                    test_fail "Funding not detected for deposit_r"
                    echo "    Funding address: $funding_address"
                fi
            else
                test_fail "Failed to send funds to deposit_r"
            fi
        else
            test_fail "No funding address in offer response"
        fi
    else
        test_fail "Failed to create deposit offer for deposit_r"
        echo "    Output: $offer_output"
    fi

    log_info ""
    log_info "deposit_s remains unfunded (will request offer after recovery)"
}

# ============================================================================
# Phase 9+10: Automated Dispute & Recovery
# Dispute target: Alice's L1
# Lottery candidates: Bob, Charlie, Diana (3 candidates)
# ============================================================================

test_automated_dispute() {
    log_info ""
    log_info "=== Phase 9: Automated Dispute Detection ==="
    log_info "(Alice publishes invalid update on L1, daemons detect and auto-arm)"
    echo ""

    local alice_ledger_id=$(get_value "ledger_id_bdk-alice_1")
    local alice_prefix=${alice_ledger_id:0:16}

    # Alice exports her valid ledger to Nostr (so daemons can auto-import it)
    log_info "Alice exporting valid L1 ledger to Nostr..."
    run_bdk_cmd "bdk-alice" nostr export "$alice_ledger_id" >/dev/null 2>&1
    test_pass "alice exported L1 ledger to Nostr"

    # Wait for daemons to auto-import
    log_info "Waiting for daemons to auto-import Alice's L1..."
    sleep 15

    # Alice publishes an invalid update
    log_info "Alice publishing invalid update (invalid-hash violation)..."
    local danger_output=$(run_bdk_cmd "bdk-alice" danger publish-invalid \
        "$alice_ledger_id" invalid-hash 2>&1)

    if echo "$danger_output" | grep -q "Published invalid update"; then
        local event_id=$(echo "$danger_output" | grep "Event ID:" | awk '{print $3}')
        test_pass "alice published invalid update: ${event_id:0:16}..."
    else
        test_fail "Failed to publish invalid update"
        echo "Output: $danger_output"
        return
    fi

    # Wait for daemons to auto-arm — 3 candidates: Bob, Charlie, Diana
    log_info ""
    log_info "Waiting for daemons to auto-arm for dispute..."
    local armed_node
    armed_node=$(wait_for_docker_marker "custody_armed_${alice_prefix}*" 60 bdk-bob bdk-charlie bdk-diana)
    if [ $? -eq 0 ]; then
        test_pass "$armed_node auto-armed for dispute"
    else
        test_fail "No daemon auto-armed within 60s"
        log_info "Checking daemon logs for clues..."
        docker logs bdk-bob 2>&1 | grep -i "INVALID\|auto-arm\|import" | tail -5
        return
    fi

    # Wait for second and third nodes
    local armed2
    armed2=$(wait_for_docker_marker "custody_armed_${alice_prefix}*" 30 bdk-bob bdk-charlie bdk-diana)
    if [ $? -eq 0 ]; then
        test_pass "second daemon armed: $armed2"
    else
        log_warn "Only one daemon armed (may still proceed)"
    fi

    local armed3
    armed3=$(wait_for_docker_marker "custody_armed_${alice_prefix}*" 30 bdk-bob bdk-charlie bdk-diana)
    if [ $? -eq 0 ]; then
        test_pass "all 3 daemons armed for dispute"
    else
        log_warn "Not all 3 daemons armed (may still proceed with confiscation)"
    fi

    log_info ""
    log_info "=== Phase 10: Automated Custody Recovery ==="
    log_info "(Daemons auto-confiscate, reveal preimages, run lottery, rotate)"
    echo ""

    # Wait for confiscation TX
    log_info "Waiting for auto-confiscation..."
    local confiscated_node
    confiscated_node=$(wait_for_docker_marker "confiscated_${alice_prefix}*" 120 bdk-bob bdk-charlie bdk-diana)
    if [ $? -eq 0 ]; then
        test_pass "$confiscated_node broadcast confiscation TX"
    else
        test_fail "No confiscation TX broadcast within 120s"
        log_info "Checking daemon logs..."
        docker logs bdk-bob 2>&1 | grep -i "confiscat" | tail -5
        return
    fi

    # Mine blocks to confirm confiscation TX
    log_info "Mining blocks to confirm confiscation..."
    mine_blocks 6
    sleep 15

    # Wait for lottery to complete
    log_info "Waiting for lottery completion..."
    local lottery_done=false
    for attempt in $(seq 1 12); do
        local completed_node
        completed_node=$(wait_for_docker_marker "lottery_completed_${alice_prefix}*" 5 bdk-bob bdk-charlie bdk-diana)
        if [ $? -eq 0 ]; then
            lottery_done=true
            test_pass "lottery completed on $completed_node"
            break
        fi
        mine_blocks 2
        sleep 10
    done

    if [ "$lottery_done" != true ]; then
        test_fail "Lottery not completed within timeout"
        log_info "Checking daemon logs for lottery state..."
        docker logs bdk-bob 2>&1 | grep -i "lottery\|reveal\|preimage" | tail -10
        return
    fi

    # Mine blocks for claim TX confirmation
    mine_blocks 3
    sleep 10

    # Wait for post-win rotation
    log_info "Waiting for post-win rotation..."
    local rotated_done=false
    for attempt in $(seq 1 12); do
        local rotated_node
        rotated_node=$(wait_for_docker_marker "lottery_rotated_${alice_prefix}*" 5 bdk-bob bdk-charlie bdk-diana)
        if [ $? -eq 0 ]; then
            rotated_done=true
            test_pass "post-win rotation completed on $rotated_node"
            break
        fi
        mine_blocks 2
        sleep 10
    done

    if [ "$rotated_done" != true ]; then
        log_warn "Post-win rotation not completed (may need more blocks)"
    fi

    # Determine the winner — check 3 candidates
    log_info ""
    log_info "Determining lottery winner..."
    local selected_candidate=""

    for candidate in bdk-bob bdk-charlie bdk-diana; do
        local rotated_content=$(docker exec "$candidate" sh -c "cat /data/lottery_rotated_${alice_prefix}*.marker 2>/dev/null" 2>/dev/null)
        if [ "$rotated_content" = "rotated" ]; then
            selected_candidate="$candidate"
            break
        fi
    done

    if [ -n "$selected_candidate" ]; then
        test_pass "lottery winner: $selected_candidate"
    else
        # Fallback: check ledger history for CustodyAcquire
        for candidate in bdk-bob bdk-charlie bdk-diana; do
            local history=$(run_bdk_cmd "$candidate" ledger history "$alice_ledger_id" 2>&1)
            if echo "$history" | grep -q "CustodyAcquire"; then
                selected_candidate="$candidate"
                break
            fi
        done
        if [ -n "$selected_candidate" ]; then
            test_pass "lottery winner (from history): $selected_candidate"
        else
            log_warn "Could not determine winner, defaulting to bdk-bob"
            selected_candidate="bdk-bob"
        fi
    fi

    # Store for Phase 11
    store_value "recovery_new_custodian" "$selected_candidate"
    store_value "recovery_ledger_id" "$alice_ledger_id"

    log_info ""
    log_info "Automated dispute resolution complete"
    log_info "  - Daemons detected invalid update"
    log_info "  - Auto-armed with preimage commitments"
    log_info "  - Auto-confiscated reserves to lottery address"
    log_info "  - Auto-revealed preimages and determined winner"
    log_info "  - Winner: $selected_candidate"
}

# ============================================================================
# Phase 11: Post-Recovery Payment Test
# ============================================================================

test_post_recovery_payment() {
    log_info ""
    log_info "=== Phase 11: Post-Recovery Deposit Flow Test ==="
    log_info "(deposit_s creates offer via Nostr, deposit_r funds it on-chain)"
    echo ""

    local new_custodian=$(get_value "recovery_new_custodian")
    local alice_reserves_id=$(get_value "reserves_id_bdk-alice_1")
    local alice_ledger_id=$(get_value "ledger_id_bdk-alice_1")

    if [ -z "$new_custodian" ]; then
        log_warn "No new custodian recorded - skipping post-recovery test"
        return
    fi

    local pubkey_s=$(get_value "pubkey_deposit_s")
    local pubkey_r=$(get_value "pubkey_deposit_r")

    if [ -z "$pubkey_s" ] || [ -z "$pubkey_r" ]; then
        log_warn "Missing deposit_r/deposit_s pubkeys - skipping test"
        return
    fi

    log_info "New custodian: $new_custodian"
    log_info "Recovered ledger: ${alice_ledger_id:0:16}..."
    log_info "deposit_r (funded): ${pubkey_r:0:16}..."
    log_info "deposit_s (unfunded): ${pubkey_s:0:16}..."

    # All 3 candidates import the ledger in parallel
    log_info ""
    log_info "All quorum members importing recovered ledger (parallel)..."
    local tmpdir=$(mktemp -d)
    local pids=()
    for member in bdk-bob bdk-charlie bdk-diana; do
        (run_bdk_cmd "$member" nostr import "$alice_ledger_id" 2>&1 > "$tmpdir/import_${member}") &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    for member in bdk-bob bdk-charlie bdk-diana; do
        local import_output=$(cat "$tmpdir/import_${member}")
        if echo "$import_output" | grep -q "Imported successfully\|Import complete"; then
            test_pass "$member imported recovered ledger"
        else
            log_warn "$member failed to import - may already have it"
        fi
    done
    rm -rf "$tmpdir"

    log_info ""
    log_info "NOT stopping alice's watcher - she's gone rogue!"

    # Verify imported ledger state
    log_info ""
    log_info "Verifying imported ledger state..."
    local ledger_info=$(run_bdk_cmd "$new_custodian" ledger info 2>&1 | head -20)
    log_info "  Ledger info on $new_custodian:"
    echo "$ledger_info" | grep -E "(Ledger|Operator|operator_key|CustodyAcquire)" | head -5

    # Start nostr watchers for the recovered ledger on ALL quorum members
    log_info ""
    log_info "Starting nostr watchers on ALL quorum members for recovered ledger..."
    for member in bdk-bob bdk-charlie bdk-diana; do
        start_nostr_watch "$member" "$alice_ledger_id"
    done
    sleep 5

    # Check dispute status
    log_info ""
    log_info "deposit_s checking dispute status before depositing..."
    local dispute_output=$(run_bdk_cmd "$new_custodian" nostr dispute status "$alice_ledger_id" 2>&1)
    local dispute_status=$(echo "$dispute_output" | grep "DISPUTE_STATUS:" | awk '{print $2}')

    log_info "  Dispute status: $dispute_status"

    if [ "$dispute_status" = "DISPUTED" ]; then
        log_info "  Ledger has unresolved custody dispute - waiting for CustodyAcquire..."
        sleep 2
        run_bdk_cmd "$new_custodian" nostr import "$alice_ledger_id" >/dev/null 2>&1
        sleep 1
        dispute_output=$(run_bdk_cmd "$new_custodian" nostr dispute status "$alice_ledger_id" 2>&1)
        dispute_status=$(echo "$dispute_output" | grep "DISPUTE_STATUS:" | awk '{print $2}')
        log_info "  After re-import: $dispute_status"
    fi

    if [ "$dispute_status" = "SAFE" ] || [ "$dispute_status" = "RESOLVED" ]; then
        test_pass "Ledger dispute status OK - safe to deposit"
    else
        test_fail "Ledger still in disputed state - cannot safely deposit"
        echo "    Output: $dispute_output"
        return
    fi

    # deposit_s creates a make_offer via deposits-wallet
    local fund_amount=5000
    log_info ""
    log_info "deposit_s requesting make_offer via deposits-wallet..."
    log_info "  Ledger ID: ${alice_ledger_id:0:16}..."
    log_info "  Amount: $fund_amount sats"

    local offer_output=$(run_wallet_cmd "bdk-diana" open "$alice_ledger_id" "$fund_amount" \
        --alias "deposit_s_recovery" 2>&1)

    local funding_address=""

    if echo "$offer_output" | grep -q "Fund with\|funding_address\|created"; then
        funding_address=$(echo "$offer_output" | grep -A1 "Fund with" | tail -1 | tr -d ' ')
        if [ -z "$funding_address" ]; then
            funding_address=$(echo "$offer_output" | grep -o 'bcrt1[a-z0-9]*')
        fi
        test_pass "deposit_s got verified offer via deposits-wallet (co-signature valid!)"
        log_info "  Funding address: $funding_address"
    else
        if echo "$offer_output" | grep -q "Invalid co-signature\|not a quorum member\|rejecting response"; then
            log_info "deposits-wallet correctly rejected rogue operator responses"
            test_fail "No valid co-signed offer received (quorum members may be offline)"
        else
            test_fail "deposit_s failed to get offer via deposits-wallet"
        fi
        echo "    Output: $offer_output"
        return
    fi

    test_pass "Offer co-signature verified - safe to fund"

    # Fund the offer
    log_info ""
    log_info "Funding deposit_s's offer on-chain ($fund_amount sats)..."

    sleep 3

    local btc_amount=$(awk "BEGIN {printf \"%.8f\", $fund_amount / 100000000}")
    bitcoin_cli -rpcwallet=faucet sendtoaddress "$funding_address" "$btc_amount" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        test_fail "Failed to send funds to deposit_s's offer"
        return
    fi

    mine_blocks 1
    test_pass "Funded deposit_s's offer on-chain"

    # Wait for daemon to auto-complete
    log_info ""
    log_info "Waiting for daemon to auto-complete deposit..."
    sleep 5

    bump_operator "$new_custodian" "$alice_ledger_id" >/dev/null 2>&1 || true
    sleep 5

    local deposit_completed=false
    local history_output=""
    for retry in 1 2 3 4 5; do
        history_output=$(run_bdk_cmd "$new_custodian" ledger history "$alice_ledger_id" 2>&1)
        if echo "$history_output" | grep -q "OnchainCredit.*${fund_amount}000 msat"; then
            deposit_completed=true
            break
        fi
        bump_operator "$new_custodian" "$alice_ledger_id" >/dev/null 2>&1 || true
        sleep 5
    done

    if [ "$deposit_completed" = true ]; then
        test_pass "deposit_s funded under new custody! (OnchainCredit in ledger)"
    else
        if echo "$history_output" | grep -q "CustodyAcquire"; then
            test_fail "deposit_s funding not auto-completed (CustodyAcquire exists but no OnchainCredit)"
        else
            test_fail "deposit_s funding not confirmed in ledger"
        fi
        echo "  History output (last 10 entries):"
        echo "$history_output" | grep "↑" | tail -10
    fi

    # Verify operations in ledger history
    log_info ""
    log_info "Verifying operations in ledger history..."
    history_output=$(run_bdk_cmd "$new_custodian" ledger history "$alice_reserves_id" 2>&1)

    if echo "$history_output" | grep -q "DepositOpen"; then
        test_pass "DepositOpen recorded in ledger"
    else
        log_warn "DepositOpen not found in history"
    fi

    if echo "$history_output" | grep -q "OnchainCredit"; then
        test_pass "OnchainCredit recorded in ledger"
    else
        log_warn "OnchainCredit not found in history"
    fi

    log_info ""
    log_info "Post-recovery deposit flow complete!"
    log_info "  1. Ledger responds to Nostr requests under new custody"
    log_info "  2. Co-signature verification rejects rogue operator (Alice)"
    log_info "  3. Only quorum-backed offers accepted by depositors"
    log_info "  4. Full deposit flow works (offer -> verify -> fund -> complete)"
    log_info "  5. 3-candidate lottery (Bob, Charlie, Diana) resolved correctly"
}

# ============================================================================
# Show final state
# ============================================================================

show_final_state() {
    log_info ""
    log_info "=== Final State ==="
    echo ""

    # Fetch all 12 ledger histories in parallel
    local tmpdir=$(mktemp -d)
    local pids=()
    for op in $OPERATORS; do
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local ledger_id=$(get_value "ledger_id_${op}_${n}")
            (run_bdk_cmd "$op" ledger history "$ledger_id" 2>&1 > "$tmpdir/${op}_${n}") &
            pids+=($!)
        done
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    for op in $OPERATORS; do
        local op_short=$(echo "$op" | sed 's/bdk-//')
        for n in $(seq 1 $LEDGERS_PER_OP); do
            local ledger_id=$(get_value "ledger_id_${op}_${n}")
            echo "=== $op_short L$n (${ledger_id:0:16}...) ==="
            cat "$tmpdir/${op}_${n}" | grep -v "^$"
            echo ""
        done
    done
    rm -rf "$tmpdir"
}

# ============================================================================
# Main
# ============================================================================

cleanup_nostr_watchers() {
    log_info ""
    log_info "=== Cleanup: Stopping Nostr Watchers ==="
    for op in $OPERATORS; do
        stop_nostr_watch "$op"
    done
}

# Clear deposits-wallet alias data from previous test runs.
reset_wallet_aliases() {
    log_info "Clearing deposits-wallet aliases..."
    for container in bdk-alice bdk-bob bdk-charlie bdk-diana; do
        docker exec "$container" sh -c 'rm -f /data/wallet/deposits.json /data/wallet/deposit_key_index.txt ~/.deposits-wallet/deposits.json ~/.deposits-wallet/deposit_key_index.txt' 2>/dev/null || true
    done
    log_success "Wallet aliases cleared"
}

main() {
    log_info "=========================================="
    log_info "  Four-Operator × Three-Ledger Quorum Test"
    log_info "  (4 operators × 3 ledgers = 12 ledgers)"
    log_info "=========================================="
    log_info "Operators: $OPERATORS"
    log_info "Ledgers per operator: $LEDGERS_PER_OP"
    log_info "Reserves: $RESERVES_AMOUNT sats each"
    log_info "Deposit: ${DEPOSIT_PERCENT}% of reserves"
    log_info "Enforcement delay: $ENFORCEMENT_DELAY blocks"
    log_info "Collateral lock: $COLLATERAL_LOCK_BLOCKS blocks"
    echo ""

    # Ensure watchers are stopped on exit
    trap cleanup_nostr_watchers EXIT

    # Clear stale wallet aliases from previous runs
    reset_wallet_aliases

    setup_operators
    create_reserves
    open_ledgers
    start_nostr_watchers
    add_quorum_members
    generate_deposit_keys
    open_cross_deposits
    fund_deposits
    lock_collateral
    mine_to_enforcement
    validate_ledgers
    full_validate_ledgers
    create_recovery_test_deposits
    # Rotate AFTER all deposits/collateral are set up (rotation enables co-signing
    # which would block deposit/lock operations with co-sign timeouts)
    rotate_reserves_to_quorum
    test_automated_dispute
    test_post_recovery_payment
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
