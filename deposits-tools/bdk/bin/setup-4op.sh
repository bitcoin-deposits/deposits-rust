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
SKIP_RESET=false

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
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-reset] [--enforcement-delay BLOCKS] [--reserves SATS]"
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
OPERATORS="bdk-alice bdk-bob bdk-charlie bdk-diana"

# ============================================================================
# Reset function - clears Nostr relay and BDK node data
# ============================================================================

reset_nostr_data() {
    log_info "Resetting Nostr relay data..."
    $DC stop nostr-relay >/dev/null 2>&1 || true
    $DC rm -f nostr-relay >/dev/null 2>&1 || true
    docker volume rm bdk_bdk_nostr_data >/dev/null 2>&1 || true
    $DC stop bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1 || true
    $DC rm -f bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1 || true
    docker volume rm bdk_bdk_alice_data bdk_bdk_bob_data bdk_bdk_charlie_data bdk_bdk_diana_data >/dev/null 2>&1 || true
    $DC up -d nostr-relay bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1
    sleep 5
    log_success "Nostr relay and BDK nodes reset"
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
    log_info "=== Phase 2: Create Reserves ($RESERVES_AMOUNT sats each) ==="
    echo ""

    for op in $OPERATORS; do
        log_info "Creating reserves for $op..."

        # Check if already has reserves
        local existing=$(run_bdk_cmd "$op" reserves list 2>&1 | grep -c "Reserves:" || true)
        if [ "$existing" -gt 0 ] && [ "$SKIP_RESET" = true ]; then
            log_info "  $op already has reserves, skipping"
            # Get existing reserves info
            local reserves_output=$(run_bdk_cmd "$op" reserves list 2>&1)
            local reserves_id=$(echo "$reserves_output" | grep "Address:" | head -1 | awk '{print $2}')
            store_value "reserves_id_$op" "$reserves_id"
            continue
        fi

        local output=$(run_bdk_cmd "$op" reserves create $RESERVES_AMOUNT 2>&1)

        if echo "$output" | grep -q "Created reserves\|Reserves created"; then
            local reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
            store_value "reserves_id_$op" "$reserves_id"
            log_success "$op created reserves"
        else
            log_error "$op failed to create reserves"
            echo "    Output: $output"
            return 1
        fi
    done

    mine_blocks 1
}

# ============================================================================
# Phase 3: Open ledgers
# ============================================================================

open_ledgers() {
    log_info ""
    log_info "=== Phase 3: Open Ledgers (enforcement +$ENFORCEMENT_DELAY blocks) ==="
    echo ""

    local current_block=$(get_block_height)
    local enforcement_block=$((current_block + ENFORCEMENT_DELAY))
    log_info "Current block: $current_block, Enforcement: $enforcement_block"
    echo ""

    for op in $OPERATORS; do
        log_info "Opening ledger for $op..."

        # Check if already has ledger
        local existing=$(run_bdk_cmd "$op" ledger list 2>&1 | grep -c "Ledger:" || true)
        if [ "$existing" -gt 0 ] && [ "$SKIP_RESET" = true ]; then
            log_info "  $op already has ledger, skipping"
            local ledger_output=$(run_bdk_cmd "$op" ledger list 2>&1)
            local ledger_id=$(echo "$ledger_output" | grep "Ledger ID:" | head -1 | awk '{print $3}')
            store_value "ledger_id_$op" "$ledger_id"
            continue
        fi

        # Pass enforcement block as positional argument
        local output=$(run_bdk_cmd "$op" ledger open "$enforcement_block" 2>&1)

        if echo "$output" | grep -q "Ledger opened\|opened successfully"; then
            local ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
            store_value "ledger_id_$op" "$ledger_id"
            log_success "$op opened ledger"
            log_info "  Ledger ID: ${ledger_id:0:16}..."
        else
            log_error "$op failed to open ledger"
            echo "    Output: $output"
            return 1
        fi
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
        local ledger_id=$(get_value "ledger_id_$op")
        if [ -n "$ledger_id" ]; then
            start_nostr_watch "$op" "$ledger_id"
            log_info "Started nostr watch on $op for $ledger_id"
            log_success "$op nostr watcher started"
        else
            log_warn "$op has no ledger_id yet"
        fi
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
    log_info "(Each operator adds the other operators as quorum members)"
    echo ""

    local membership_expires=1000000  # Far future block

    for op in $OPERATORS; do
        local op_reserves_id=$(get_value "reserves_id_$op")
        local op_node_id=$(get_value "node_id_$op")
        local op_ledger_id=$(get_value "ledger_id_$op")

        for member in $OPERATORS; do
            if [ "$op" != "$member" ]; then
                local member_node_id=$(get_value "node_id_$member")
                local member_ledger_id=$(get_value "ledger_id_$member")
                local member_reserves_id=$(get_value "reserves_id_$member")
                local op_short=$(echo "$op" | sed 's/bdk-//')
                local member_short=$(echo "$member" | sed 's/bdk-//')

                log_info "$op_short adding $member_short as quorum member..."

                # Add member to op's quorum (pass member's ledger ID for collateral binding)
                local add_output=$(run_bdk_cmd "$op" partner add "$op_ledger_id" "$member_node_id" "$member_ledger_id" 2>&1)

                if echo "$add_output" | grep -q "Quorum member added\|added"; then
                    # Record the join on member's ledger (use ledger_id for both our ledger and target)
                    local join_output=$(run_bdk_cmd "$member" partner join "$member_ledger_id" "$op_node_id" "$op_ledger_id" "$membership_expires" 2>&1)

                    if echo "$join_output" | grep -q "Quorum join recorded\|recorded"; then
                        log_success "$member_short joined $op_short's quorum (both sides recorded)"
                    else
                        log_warn "$op_short added $member_short (join record issue)"
                    fi
                else
                    log_error "$op_short failed to add $member_short as quorum member"
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

            log_success "$op_short rotated to Taproot with $quorum_count members (expiry: block $expiry_block)"
        else
            log_warn "$op_short: Reserves rotation returned: $(echo "$rotate_output" | head -1)"
        fi
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
    log_info "Operators:"
    for op in $OPERATORS; do
        local node_id=$(get_value "node_id_$op")
        local ledger_id=$(get_value "ledger_id_$op")
        local reserves_id=$(get_value "reserves_id_$op")
        echo "  $op:"
        echo "    Node ID:    ${node_id:0:20}..."
        echo "    Ledger ID:  ${ledger_id:0:20}..."
        echo "    Reserves:   ${reserves_id:0:30}..."
        echo ""
    done

    local current_block=$(get_block_height)
    log_info "Current block height: $current_block"
    log_info "Enforcement delay: $ENFORCEMENT_DELAY blocks"
    echo ""
    log_info "Useful commands:"
    echo "  Mine blocks:     docker exec bdk-bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 10"
    echo "  Alice CLI:       docker exec bdk-alice deposits-bdk <command>"
    echo "  View ledger:     docker exec bdk-alice deposits-bdk ledger show"
    echo "  Nostr relay:     ws://localhost:7778"
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
    log_info "Reserves: $RESERVES_AMOUNT sats each"
    log_info "Enforcement delay: $ENFORCEMENT_DELAY blocks"
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
    rotate_reserves_to_quorum

    # Give watchers a moment to settle
    sleep 2

    # Print summary
    print_summary

    log_success "Setup complete! Environment is ready for testing."
}

main
