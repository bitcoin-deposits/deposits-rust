#!/bin/bash
# Multi-operator setup script
#
# Sets up a persistent environment with N operators (default 4) cross-linked:
# 1. Each creates reserves UTXOs (1 BTC each)
# 2. Each opens ledgers with configurable enforcement delay
# 3. Quorum members assigned per ledger (3-5 members, organic topology)
# 4. Rotates reserves to quorum-based Taproot
#
# After this script completes, you have a fully cross-linked network
# ready for manual testing, deposits, or dispute scenarios.
#
# Usage:
#   ./bin/setup-4op.sh [--nodes N] [--skip-reset] [--enforcement-delay BLOCKS]
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
        --nodes|-n)
            NODE_COUNT="$2"
            shift 2
            ;;
        --show-topology)
            SHOW_TOPOLOGY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--nodes N] [--skip-reset] [--enforcement-delay BLOCKS] [--reserves SATS]"
            echo "       [--ledgers-per-op N] [--annual-fee-bps N] [--min-fee-sats N] [--fee-period N]"
            echo "       [--transfer-fee-fixed N] [--transfer-fee-rate-bps N] [--show-topology]"
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

# Re-initialize topology with final config (NODE_COUNT / LEDGERS_PER_OP may have changed)
init_topology

# Generate topology JSON for quorum lookups during setup
python3 "$SCRIPT_DIR/generate-topology.py" --nodes "$NODE_COUNT" --ledgers-per-op "$LEDGERS_PER_OP" > "$STATE_DIR/topology.json"
# Persist topology so redeploy can auto-detect node count
cp "$STATE_DIR/topology.json" "$DATA_ROOT/topology.json"

if [ "${SHOW_TOPOLOGY:-false}" = true ]; then
    python3 "$SCRIPT_DIR/generate-topology.py" --nodes "$NODE_COUNT" --ledgers-per-op "$LEDGERS_PER_OP" --show-graph >/dev/null
    exit 0
fi

# Operators (dynamic from topology)
OPERATORS="${NODES[*]}"

# ============================================================================
# Reset function - clears Nostr relay and node data
# ============================================================================

reset_nostr_data() {
    log_info "Resetting Nostr relay data and node data..."
    # Stop node processes
    stop_all_nodes
    # Stop native relays
    stop_all_relays
    # Clear all data (node + relay)
    rm -rf "$DATA_ROOT"
    # Restart native relays
    start_all_relays
    # Wait for relays to be healthy
    sleep 3
    log_success "Nostr relays reset (nodes will start in Phase 1)"
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
        local info_output=$(run_node_cmd "$op" info 2>&1)
        local balance=$(echo "$info_output" | grep "Wallet balance:" | awk '{print $3}')

        local min_balance=$((RESERVES_AMOUNT * LEDGERS_PER_OP + 50000000))  # reserves + 0.5 BTC for fees
        if [ -z "$balance" ] || [ "$balance" -lt "$min_balance" ]; then
            local address=$(get_node_address "$op")
            bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 10 >/dev/null 2>&1
            mine_blocks 1
            log_info "  Funded $op with 10 BTC"
        fi

        # Get node info
        info_output=$(run_node_cmd "$op" info 2>&1)
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

            local output=$(run_node_cmd "$op" reserves create $RESERVES_AMOUNT 2>&1)

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
            local output=$(run_node_cmd "$op" ledger open "$enforcement_block" \
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

# ============================================================================
# Phase 3b: Add quorum members
# ============================================================================

add_quorum_members() {
    log_info ""
    log_info "=== Phase 3b: Add Quorum Members ==="
    log_info "(Topology-driven quorum assignment per ledger)"
    echo ""

    local membership_expires=1000000  # Far future block
    local topo_file="$STATE_DIR/topology.json"

    for op in $OPERATORS; do
        local op_node_id=$(get_value "node_id_$op")

        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            local op_ledger_id=$(get_value "ledger_id_${op}${suffix}")

            # Get quorum members for this specific ledger from topology
            local members=$(python3 -c "
import json
t = json.load(open('$topo_file'))
print(' '.join(t['quorum'].get('${op}_${idx}', [])))
")

            for member in $members; do
                local member_node_id=$(get_value "node_id_$member")
                # Use member's first ledger for collateral binding
                local member_suffix=""
                [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
                local member_ledger_id=$(get_value "ledger_id_${member}${member_suffix}")

                log_info "$op ledger $idx: adding $member as quorum member..."

                # Add member to op's quorum — the member's node auto-consents,
                # signs, and records QuorumJoin on their own ledger.
                local add_output=$(run_node_cmd "$op" quorum add "$op_ledger_id" "$member_node_id" "$member_ledger_id" 2>&1)

                if echo "$add_output" | grep -q "Quorum member added\|added"; then
                    log_success "$member joined $op ledger $idx"
                else
                    log_error "$op failed to add $member to ledger $idx"
                    echo "    Output: $add_output"
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
    log_info "(Each quorum member opens collateral on ledgers they serve)"
    echo ""

    local topo_file="$STATE_DIR/topology.json"

    # Extract unique (depositor, ledger_owner) pairs and compute collateral amount.
    # Collateral per deposit = (reserves / 2) / num_quorum_members on that ledger.
    # We use the max member count across all owners so a single amount works everywhere.
    local pairs_and_amount=$(python3 -c "
import json
from collections import Counter
t = json.load(open('$topo_file'))
pairs = set()
for key, members in t['quorum'].items():
    op = key.rsplit('_', 1)[0]
    for m in members:
        pairs.add((m, op))
# Count how many deposits each owner's first ledger will receive
owner_counts = Counter(owner for _, owner in pairs)
max_deposits = max(owner_counts.values())
# Half of reserves divided by the number of quorum members
collateral = int($RESERVES_AMOUNT // 2 // max_deposits)
print(collateral)
for depositor, owner in sorted(pairs):
    print(f'{depositor} {owner}')
")
    local collateral_amount=$(echo "$pairs_and_amount" | head -1)
    local pairs=$(echo "$pairs_and_amount" | tail -n +2)
    local num_pairs=$(echo "$pairs" | wc -l | tr -d ' ')
    log_info "Collateral per deposit: $collateral_amount sats ($num_pairs unique pairs)"
    echo ""

    while IFS=' ' read -r depositor owner; do
        # Depositor opens a collateral deposit on owner's first ledger
        local owner_suffix=""
        [ "$LEDGERS_PER_OP" -gt 1 ] && owner_suffix="_1"
        local owner_ledger_id=$(get_value "ledger_id_${owner}${owner_suffix}")

        if [ -z "$owner_ledger_id" ]; then
            log_warn "No ledger for $owner, skipping collateral"
            continue
        fi

        log_info "$depositor opening collateral deposit on $owner's ledger..."

        # Open collateral deposit — send to owner's relay where their nostr watch listens.
        # Retry on timeout (operator watch may be busy with other requests).
        local owner_relay=$(get_node_relay_url "$owner")
        local dep_seed=$(get_node_seed "$depositor")
        local dep_data_dir=$(get_node_data_dir "$depositor")
        local open_output=$(RUST_LOG=error "$DEPOSITS_WALLET" open \
            "$owner_ledger_id" "$collateral_amount" \
            --alias "collateral-${depositor}-on-${owner}" --collateral --skip-cosign-verify \
            --fee-bps "$ANNUAL_FEE_BPS" --fee-fixed "$MIN_FEE_SATS" --fee-period "$FEE_PERIOD" \
            --seed "$dep_seed" --network regtest \
            --relay "$owner_relay" \
            --data-dir "$dep_data_dir/wallet" 2>&1 || true)

        local fund_addr=$(echo "$open_output" | grep -oE 'bcrt1[a-z0-9]+' | head -1)
        if [ -n "$fund_addr" ]; then
            local btc_amount=$(python3 -c "print(f'{$collateral_amount / 100_000_000:.8f}')")
            bitcoin_cli -rpcwallet=faucet sendtoaddress "$fund_addr" "$btc_amount" >/dev/null 2>&1 || true
            log_success "$depositor collateral on $owner: $collateral_amount sats"
        else
            log_warn "$depositor collateral on $owner failed:"
            echo "$open_output" | tail -5
        fi
    done <<< "$pairs"

    mine_blocks 2

    # Poll until all collateral deposits have non-zero balances
    log_info "Waiting for collateral deposits to complete..."
    local expected_deposits="$num_pairs"
    local completed=0
    for attempt in $(seq 1 30); do
        mine_blocks 1
        sleep 3

        completed=0
        for member in $OPERATORS; do
            local member_suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
            local lid=$(get_value "ledger_id_${member}${member_suffix}")
            if [ -n "$lid" ]; then
                local ls_output=$(run_node_cmd "$member" deposit ls "$lid" 2>/dev/null || true)
                local funded=$(echo "$ls_output" | grep "Balance:" | grep -cv "Balance: 0 msats" || true)
                completed=$((completed + funded))
            fi
        done

        if [ "$completed" -ge "$expected_deposits" ]; then
            log_success "All $completed/$expected_deposits collateral deposits funded"
            break
        fi
        log_info "  $completed/$expected_deposits deposits funded (attempt $attempt/30)..."
    done

    if [ "$completed" -lt "$expected_deposits" ]; then
        log_warn "Only $completed/$expected_deposits deposits funded after 30 attempts"
    fi

    # Lock collateral (auto-records attestation on depositor's own ledgers)
    log_info "Locking collateral..."
    local collateral_msats=$((collateral_amount * 1000))
    local lock_blocks=10000  # ~70 days

    while IFS=' ' read -r depositor owner; do
        local dep_node_id=$(get_value "node_id_$depositor")
        local owner_suffix=""
        [ "$LEDGERS_PER_OP" -gt 1 ] && owner_suffix="_1"
        local owner_ledger_id=$(get_value "ledger_id_${owner}${owner_suffix}")

        # Depositor locks collateral on owner's ledger — attestation auto-recorded on all own ledgers
        local lock_output=$(run_node_cmd "$depositor" collateral lock \
            "$owner_ledger_id" "$collateral_msats" "$lock_blocks" "$dep_node_id" 2>&1 || true)

        if echo "$lock_output" | grep -q "Collateral locked"; then
            log_success "$depositor locked collateral on $owner (auto-recorded)"
        else
            log_warn "$depositor collateral lock on $owner failed: $(echo "$lock_output" | tail -1)"
        fi
    done <<< "$pairs"
    mine_blocks 1
}

# ============================================================================
# Phase 3d: Activate quorum-based Taproot spending
# ============================================================================

activate_quorum() {
    log_info ""
    log_info "=== Phase 3d: Activate Quorum (quorum begin) ==="
    echo ""

    for op in $OPERATORS; do
        local op_short="$op"

        for idx in $(seq 1 $LEDGERS_PER_OP); do
            local suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"

            local op_reserves_id=$(get_value "reserves_id_${op}${suffix}")

            log_info "$op_short activating quorum on ledger $idx..."

            local begin_output=$(run_node_cmd "$op" quorum begin "$op_reserves_id" 2>&1)

            if echo "$begin_output" | grep -q "Quorum activated\|rotated successfully"; then
                local quorum_count=$(echo "$begin_output" | grep "Quorum Members:" | awk '{print $3}')
                log_success "$op_short ledger $idx: quorum active with $quorum_count members"
            else
                log_warn "$op_short ledger $idx: $(echo "$begin_output" | head -1)"
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
    echo "  Alice CLI:       source bin/_common.sh && run_node_cmd alice <command>"
    echo "  View ledger:     source bin/_common.sh && run_node_cmd alice ledger show"
    echo "  Nostr relay:     ws://localhost:7801"
    echo ""
    log_info "Nostr watchers are running in background. They will stop when node processes are killed."
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    local num_ops=$(echo $OPERATORS | wc -w | tr -d ' ')
    log_info "=========================================="
    log_info "  ${num_ops}-Operator Setup"
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

    # Start daemons before quorum/collateral phases
    # Daemons handle all Nostr request processing (deposit_open, cosign, collateral_lock, etc.)
    start_all_nodes
    sleep 2

    add_quorum_members
    establish_collateral
    activate_quorum

    # Print summary
    print_summary

    log_success "Setup complete! Environment is ready for testing."
}

main
