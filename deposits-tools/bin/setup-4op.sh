#!/bin/bash
# Four-operator setup script
#
# Sets up a persistent environment with 4 operators cross-linked:
# 1. Each creates reserves UTXOs (1 BTC each)
# 2. Each opens ledgers with configurable enforcement delay
# 3. Each operator adds others as quorum members
# 4. Rotates reserves to quorum-based Taproot
#
# After this script completes, you have a fully cross-linked network
# ready for manual testing, deposits, or dispute scenarios.
#
# Usage:
#   ./bin/setup-4op.sh [--skip-reset] [--enforcement-delay BLOCKS]
#
# The --skip-reset flag preserves existing state (useful for resuming).
# Default enforcement delay is 200 blocks.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Configuration (can be overridden via args)
RESERVES_AMOUNT=100000000  # 1 BTC in sats
ENFORCEMENT_DELAY=200      # Blocks until enforcement
LEDGERS_PER_OP=3           # Number of ledgers per operator
SKIP_RESET=false

# Fee schedule defaults (advertised minimums)
ANNUAL_FEE_BPS=50          # 0.5% annual custody fee
MIN_FEE_SATS=100           # 100 sats minimum per period
FEE_PERIOD=2016            # ~2 weeks in blocks
TRANSFER_FEE_FIXED=2       # 2 sats per transfer
TRANSFER_FEE_RATE_BPS=20   # 0.2% per transfer

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-reset)
            SKIP_RESET=true
            shift
            ;;
        --enforcement-delay)
            ENFORCEMENT_DELAY="$2"
            shift 2
            ;;
        --reserves)
            RESERVES_AMOUNT="$2"
            shift 2
            ;;
        --ledgers-per-op)
            LEDGERS_PER_OP="$2"
            shift 2
            ;;
        --annual-fee-bps)
            ANNUAL_FEE_BPS="$2"
            shift 2
            ;;
        --min-fee-sats)
            MIN_FEE_SATS="$2"
            shift 2
            ;;
        --fee-period)
            FEE_PERIOD="$2"
            shift 2
            ;;
        --transfer-fee-fixed)
            TRANSFER_FEE_FIXED="$2"
            shift 2
            ;;
        --transfer-fee-rate-bps)
            TRANSFER_FEE_RATE_BPS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-reset] [--enforcement-delay BLOCKS] [--reserves SATS] [--ledgers-per-op N]"
            echo "       [--annual-fee-bps N] [--min-fee-sats N] [--fee-period N]"
            echo "       [--transfer-fee-fixed N] [--transfer-fee-rate-bps N]"
            exit 1
            ;;
    esac
done

# Use temp directory for state (persists until script ends)
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
OPERATORS="alice bob charlie diana"

# ============================================================================
# Reset function - clears Nostr relay and node data
# ============================================================================

reset_nostr_data() {
    log_info "Resetting Nostr relay data..."
    $DC stop relay-alice relay-bob relay-charlie relay-diana relay-ledgers >/dev/null 2>&1 || true
    $DC rm -f relay-alice relay-bob relay-charlie relay-diana relay-ledgers >/dev/null 2>&1 || true
    docker volume rm bdk_relay_alice_data bdk_relay_bob_data bdk_relay_charlie_data bdk_relay_diana_data bdk_relay_ledgers_data >/dev/null 2>&1 || true
    $DC stop alice bob charlie diana >/dev/null 2>&1 || true
    $DC rm -f alice bob charlie diana >/dev/null 2>&1 || true
    docker volume rm bdk_alice_data bdk_bob_data bdk_charlie_data bdk_diana_data >/dev/null 2>&1 || true
    $DC up -d relay-alice relay-bob relay-charlie relay-diana relay-ledgers alice bob charlie diana >/dev/null 2>&1
    sleep 5
    log_success "Nostr relay and nodes reset"
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

        local min_balance=$((RESERVES_AMOUNT * LEDGERS_PER_OP + 50000000))  # reserves + 0.5 BTC for fees
        if [ -z "$balance" ] || [ "$balance" -lt "$min_balance" ]; then
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
            log_success "$op ready: ${node_id:0:16}..."
        else
            log_error "Could not get node ID for $op"
            return 1
        fi
    done
}

# ============================================================================
# Phase 2: Create reserves UTXOs
# ============================================================================

create_reserves() {
    log_info ""
    log_info "=== Phase 2: Create Reserves ($RESERVES_AMOUNT sats each, $LEDGERS_PER_OP per operator) ==="
    echo ""

    for op in $OPERATORS; do
        log_info "Creating reserves for $op..."

        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            # Check if already has reserves
            if [ "$SKIP_RESET" = true ]; then
                local existing_id=$(get_value "reserves_id_${op}${suffix}")
                if [ -n "$existing_id" ]; then
                    log_info "  $op ledger $idx already has reserves, skipping"
                    continue
                fi
            fi

            local output=$(run_bdk_cmd "$op" reserves create $RESERVES_AMOUNT 2>&1)

            if echo "$output" | grep -q "Created reserves\|Reserves created"; then
                local reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
                store_value "reserves_id_${op}${suffix}" "$reserves_id"
                log_success "$op created reserves $idx"
            else
                log_error "$op failed to create reserves $idx"
                echo "    Output: $output"
                return 1
            fi
        done
    done

    mine_blocks 1
}

# ============================================================================
# Phase 3: Open ledgers
# ============================================================================

open_ledgers() {
    log_info ""
    log_info "=== Phase 3: Open Ledgers (enforcement +$ENFORCEMENT_DELAY blocks, $LEDGERS_PER_OP per operator) ==="
    echo ""

    local current_block=$(get_block_height)
    local enforcement_block=$((current_block + ENFORCEMENT_DELAY))
    log_info "Current block: $current_block, Enforcement: $enforcement_block"
    echo ""

    for op in $OPERATORS; do
        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            log_info "Opening ledger $idx for $op..."

            # Check if already has ledger
            if [ "$SKIP_RESET" = true ]; then
                local existing_id=$(get_value "ledger_id_${op}${suffix}")
                if [ -n "$existing_id" ]; then
                    log_info "  $op ledger $idx already exists, skipping"
                    continue
                fi
            fi

            # Pass enforcement block, fee schedule, and external relay URL
            local relay_url=$(get_node_relay_url "$op")
            local output=$(run_bdk_cmd "$op" ledger open "$enforcement_block" \
                --annual-fee-bps "$ANNUAL_FEE_BPS" \
                --min-fee-sats "$MIN_FEE_SATS" \
                --fee-period "$FEE_PERIOD" \
                --transfer-fee-fixed "$TRANSFER_FEE_FIXED" \
                --transfer-fee-rate-bps "$TRANSFER_FEE_RATE_BPS" \
                --advertise-relay "$relay_url" 2>&1)

            if echo "$output" | grep -q "Ledger opened\|opened successfully"; then
                local ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
                store_value "ledger_id_${op}${suffix}" "$ledger_id"
                log_success "$op opened ledger $idx"
                log_info "  Ledger ID: ${ledger_id:0:16}..."
            else
                log_error "$op failed to open ledger $idx"
                echo "    Output: $output"
                return 1
            fi
        done
    done
}

# ============================================================================
# Phase 3a: Start Nostr watchers (background)
# ============================================================================

start_nostr_watchers() {
    log_info ""
    log_info "=== Phase 3a: Start Nostr Watchers ==="
    log_info "(Each operator listens for incoming requests)"
    echo ""

    for op in $OPERATORS; do
        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            local ledger_id=$(get_value "ledger_id_${op}${suffix}")
            if [ -n "$ledger_id" ]; then
                start_nostr_watch "$op" "$ledger_id"
                log_info "Started nostr watch on $op for ledger $idx"
            else
                log_warn "$op has no ledger_id for ledger $idx"
            fi
        done
        log_success "$op nostr watcher(s) started"
    done

    # Give watchers time to connect
    sleep 2
}

cleanup_nostr_watchers() {
    log_info ""
    log_info "=== Cleanup: Stopping Nostr Watchers ==="

    for op in $OPERATORS; do
        stop_nostr_watch "$op"
    done
}

# ============================================================================
# Phase 3b: Add quorum members
# ============================================================================

add_quorum_members() {
    log_info ""
    log_info "=== Phase 3b: Add Quorum Members ==="
    log_info "(Each operator adds the other operators as quorum members for all ledgers)"
    echo ""

    local membership_expires=1000000  # Far future block

    for op in $OPERATORS; do
        local op_node_id=$(get_value "node_id_$op")

        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            local op_ledger_id=$(get_value "ledger_id_${op}${suffix}")

            for member in $OPERATORS; do
                if [ "$op" != "$member" ]; then
                    local member_node_id=$(get_value "node_id_$member")
                    # Use member's first ledger for collateral binding
                    local member_suffix=""
                    [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
                    local member_ledger_id=$(get_value "ledger_id_${member}${member_suffix}")
                    local op_short="$op"
                    local member_short="$member"

                    log_info "$op_short ledger $idx: adding $member_short as quorum member..."

                    # Add member to op's quorum (pass member's ledger ID for collateral binding)
                    local add_output=$(run_bdk_cmd "$op" partner add "$op_ledger_id" "$member_node_id" "$member_ledger_id" 2>&1)

                    if echo "$add_output" | grep -q "Quorum member added\|added"; then
                        # Record the join on member's first ledger
                        local join_output=$(run_bdk_cmd "$member" partner join "$member_ledger_id" "$op_node_id" "$op_ledger_id" "$membership_expires" 2>&1)

                        if echo "$join_output" | grep -q "Quorum join recorded\|recorded"; then
                            log_success "$member_short joined $op_short ledger $idx"
                        else
                            log_warn "$op_short added $member_short to ledger $idx (join record issue)"
                        fi
                    else
                        log_error "$op_short failed to add $member_short to ledger $idx"
                        echo "    Output: $add_output"
                    fi
                fi
            done
        done
    done
}

# ============================================================================
# Phase 3c: Establish collateral deposits
# ============================================================================

establish_collateral() {
    log_info ""
    log_info "=== Phase 3c: Establish Collateral Deposits ==="
    log_info "(Each operator opens and funds collateral deposits on quorum member ledgers)"
    echo ""

    local collateral_amount=$((RESERVES_AMOUNT / 6))  # 1/6th of reserves per member
    log_info "Collateral per member: $collateral_amount sats (1/6 of $RESERVES_AMOUNT)"
    echo ""

    for op in $OPERATORS; do
        for member in $OPERATORS; do
            if [ "$op" != "$member" ]; then
                # Operator opens a collateral deposit on member's first ledger
                local member_suffix=""
                [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
                local member_ledger_id=$(get_value "ledger_id_${member}${member_suffix}")

                if [ -z "$member_ledger_id" ]; then
                    log_warn "No ledger for $member, skipping collateral"
                    continue
                fi

                log_info "$op opening collateral deposit on $member's ledger..."

                # Open collateral deposit — connect to member's relay for the request
                local member_relay="ws://relay-${member}:7777"
                local op_seed=$(get_node_seed "$op")
                local open_output=$(docker exec -e RUST_LOG=error "$op" deposits-wallet open \
                    "$member_ledger_id" "$collateral_amount" \
                    --alias "collateral-$member" --collateral --skip-cosign-verify \
                    --seed "$op_seed" --network regtest \
                    --relay "$member_relay" \
                    --data-dir /data/wallet 2>&1)

                if echo "$open_output" | grep -q "created\|Fund with"; then
                    # Extract funding address
                    local fund_addr=$(echo "$open_output" | grep -E '^  bcrt1|^bcrt1' | head -1 | tr -d ' ')
                    if [ -n "$fund_addr" ]; then
                        bitcoin_cli -rpcwallet=faucet sendtoaddress "$fund_addr" "$(echo "scale=8; $collateral_amount / 100000000" | bc)" >/dev/null 2>&1
                        log_success "$op collateral on $member: $collateral_amount sats"
                    else
                        log_warn "$op collateral on $member: created but no funding address"
                    fi
                else
                    log_warn "$op collateral on $member failed: $(echo "$open_output" | head -1)"
                fi
            fi
        done
    done

    mine_blocks 1

    # Wait for deposits to complete
    sleep 5
    log_info "Bumping operators to complete collateral deposits..."
    for op in $OPERATORS; do
        for member in $OPERATORS; do
            if [ "$op" != "$member" ]; then
                local member_suffix=""
                [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
                local member_ledger_id=$(get_value "ledger_id_${member}${member_suffix}")
                bump_operator "$member" "$member_ledger_id" 2>/dev/null || true
            fi
        done
    done
    mine_blocks 1
    sleep 3

    # Lock collateral and record attestations
    log_info "Locking collateral and recording attestations..."
    local collateral_msats=$((collateral_amount * 1000))
    local lock_blocks=10000  # ~70 days

    for op in $OPERATORS; do
        local op_node_id=$(get_value "node_id_$op")

        for member in $OPERATORS; do
            if [ "$op" != "$member" ]; then
                local member_suffix=""
                [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
                local member_ledger_id=$(get_value "ledger_id_${member}${member_suffix}")

                # Op locks their collateral deposit on member's ledger
                # The deposit was opened with op's seed, so op runs the lock command
                local lock_output=$(run_bdk_cmd "$op" collateral lock \
                    "$member_ledger_id" "$collateral_msats" "$lock_blocks" "$op_node_id" 2>&1)

                local attestation_json=$(echo "$lock_output" | grep "^ATTESTATION_JSON:" | sed 's/^ATTESTATION_JSON://')

                if [ -n "$attestation_json" ]; then
                    # Record attestation on op's first ledger
                    local op_suffix=""
                    [ "$LEDGERS_PER_OP" -gt 1 ] && op_suffix="_1"
                    local op_reserves_id=$(get_value "reserves_id_${op}${op_suffix}")

                    local record_output=$(run_bdk_cmd "$op" collateral record \
                        "$op_reserves_id" "$attestation_json" 2>&1)

                    if echo "$record_output" | grep -q "recorded\|Attestation"; then
                        log_success "$op locked collateral on $member, attestation recorded"
                    else
                        log_warn "$op attestation record issue: $(echo "$record_output" | head -1)"
                    fi
                else
                    log_warn "$op collateral lock on $member failed: $(echo "$lock_output" | tail -1)"
                fi
            fi
        done
    done
    mine_blocks 1
}

# ============================================================================
# Phase 3d: Rotate reserves to quorum-based Taproot
# ============================================================================

rotate_reserves_to_quorum() {
    log_info ""
    log_info "=== Phase 3d: Rotate Reserves to Quorum-Based Taproot ==="
    echo ""

    for op in $OPERATORS; do
        local op_short="$op"

        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            local op_reserves_id=$(get_value "reserves_id_${op}${suffix}")

            log_info "$op_short rotating reserves $idx to quorum-based Taproot..."

            local rotate_output=$(run_bdk_cmd "$op" reserves rotate "$op_reserves_id" 2>&1)

            if echo "$rotate_output" | grep -q "Reserves rotated\|rotated successfully"; then
                local quorum_count=$(echo "$rotate_output" | grep "Quorum Members:" | awk '{print $3}')
                log_success "$op_short ledger $idx rotated with $quorum_count members"
            else
                log_warn "$op_short ledger $idx: $(echo "$rotate_output" | head -1)"
            fi
        done
    done

    mine_blocks 1
}

# ============================================================================
# Print environment summary
# ============================================================================

print_summary() {
    log_info ""
    log_info "=========================================="
    log_info "  Environment Ready!"
    log_info "=========================================="
    echo ""
    log_info "Operators ($LEDGERS_PER_OP ledgers each):"
    for op in $OPERATORS; do
        local node_id=$(get_value "node_id_$op")
        echo "  $op: ${node_id:0:20}..."
        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"
            local ledger_id=$(get_value "ledger_id_${op}${suffix}")
            local reserves_id=$(get_value "reserves_id_${op}${suffix}")
            echo "    Ledger $idx:  ${ledger_id:0:20}..."
            echo "    Reserves $idx: ${reserves_id:0:30}..."
        done
        echo ""
    done

    local total_ledgers=$(( $(echo $OPERATORS | wc -w) * LEDGERS_PER_OP ))
    local current_block=$(get_block_height)
    log_info "Total ledgers: $total_ledgers"
    log_info "Current block height: $current_block"
    log_info "Enforcement delay: $ENFORCEMENT_DELAY blocks"
    log_info "Custody fees: ${ANNUAL_FEE_BPS} bps annual, ${MIN_FEE_SATS} sats min/${FEE_PERIOD}-block period"
    log_info "Transfer fees: ${TRANSFER_FEE_FIXED} sats + ${TRANSFER_FEE_RATE_BPS} bps"
    echo ""
    log_info "Useful commands:"
    echo "  Mine blocks:     docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 10"
    echo "  Alice CLI:       docker exec alice deposits-node <command>"
    echo "  View ledger:     docker exec alice deposits-node ledger show"
    echo "  Nostr relay:     ws://localhost:7801"
    echo ""
    log_info "Nostr watchers are running in background. They will stop when containers restart."
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "=========================================="
    log_info "  Four-Operator Setup"
    log_info "=========================================="
    log_info "Operators: $OPERATORS"
    log_info "Ledgers per operator: $LEDGERS_PER_OP"
    log_info "Reserves: $RESERVES_AMOUNT sats each"
    log_info "Enforcement delay: $ENFORCEMENT_DELAY blocks"
    log_info "Custody fees: ${ANNUAL_FEE_BPS} bps annual, ${MIN_FEE_SATS} sats min, ${FEE_PERIOD}-block period"
    log_info "Transfer fees: ${TRANSFER_FEE_FIXED} sats fixed + ${TRANSFER_FEE_RATE_BPS} bps"
    echo ""

    # Reset data from previous runs (unless skipped)
    if [ "$SKIP_RESET" = false ]; then
        reset_nostr_data
    else
        log_info "Skipping reset (--skip-reset flag)"
    fi

    # Setup phases
    setup_operators
    create_reserves
    open_ledgers

    # Start watchers EARLY - they will dynamically discover QuorumJoin operations
    start_nostr_watchers

    add_quorum_members
    establish_collateral
    rotate_reserves_to_quorum

    # Give watchers a moment to settle
    sleep 2

    # Print summary
    print_summary

    log_success "Setup complete! Environment is ready for testing."
}

main
