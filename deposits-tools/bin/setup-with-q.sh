#!/bin/bash
# Simplified network setup: collateral-in-UTXO model.
#
# Brings up regtest, funds operators, opens ledgers, forms quorums.
# No collateral deposits needed — collateral is part of the UTXO.
#
# Usage:
#   ./bin/setup-with-q.sh Q=5           # 16 operators (3*5+1), Q=5
#   ./bin/setup-with-q.sh Q=3           # 10 operators (3*3+1), Q=3
#   ./bin/setup-with-q.sh Q=7 --nodes 30
#
# Each operator:
#   - Gets 1 BTC UTXO, split 40/60 reserves/collateral per ledger
#   - Runs 3 ledgers with independent Q-member quorums
#   - Quorum members assigned round-robin (dispersed, not adjacent)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Defaults
Q=5
RESERVES_SATS=40000000     # 0.4 BTC reserves per ledger (40% of ~1 BTC)
COLLATERAL_SATS=60000000   # 0.6 BTC collateral per ledger (60%)
LEDGERS_PER_OP=3
ENFORCEMENT_DELAY=200

# Parse Q=N and other args
for arg in "$@"; do
    case $arg in
        Q=*|q=*)
            Q="${arg#*=}"
            ;;
        --nodes|-n)
            shift_next=true
            ;;
        *)
            if [ "${shift_next:-false}" = true ]; then
                NODE_COUNT="$arg"
                shift_next=false
            fi
            ;;
    esac
done

# Default node count: 3*Q + 1 (enough for 3 non-overlapping quorums + 1 spare)
NODE_COUNT="${NODE_COUNT:-$((3 * Q + 1))}"

# Fee defaults
ANNUAL_FEE_BPS=50
MIN_FEE_SATS=100
FEE_PERIOD=2016
TRANSFER_FEE_FIXED=2
TRANSFER_FEE_RATE_BPS=20

# Re-init topology with our node count
export NODE_COUNT LEDGERS_PER_OP
init_topology

STATE_DIR=$(mktemp -d)
trap "rm -rf $STATE_DIR" EXIT

store_value() { echo "$2" > "$STATE_DIR/$1"; }
get_value() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }

# Generate topology
python3 "$SCRIPT_DIR/generate-topology.py" --nodes "$NODE_COUNT" --ledgers-per-op "$LEDGERS_PER_OP" > "$STATE_DIR/topology.json"
cp "$STATE_DIR/topology.json" "$DATA_ROOT/topology.json" 2>/dev/null || true

OPERATORS="${NODES[*]}"
NUM_OPS=$(echo $OPERATORS | wc -w | tr -d ' ')

log_info "=========================================="
log_info "  Setup: $NUM_OPS operators, Q=$Q"
log_info "=========================================="
log_info "Operators: $OPERATORS"
log_info "Ledgers: $LEDGERS_PER_OP per operator"
log_info "Reserves: $RESERVES_SATS sats/ledger ($(( RESERVES_SATS * 100 / (RESERVES_SATS + COLLATERAL_SATS) ))%)"
log_info "Collateral: $COLLATERAL_SATS sats/ledger ($(( COLLATERAL_SATS * 100 / (RESERVES_SATS + COLLATERAL_SATS) ))%)"
log_info "No collateral deposits — collateral is in the UTXO"
echo ""

# ============================================================================
# Phase 1: Reset + Fund
# ============================================================================

log_info "=== Phase 1: Reset and Fund ==="
stop_all_nodes
stop_all_relays
rm -rf "$DATA_ROOT"
start_all_relays
sleep 3

# Fund all operators in one batch
TOTAL_PER_OP=$(python3 -c "print(f'{($RESERVES_SATS + $COLLATERAL_SATS) * $LEDGERS_PER_OP / 100_000_000 + 0.5:.1f}')")
for op in $OPERATORS; do
    run_node_cmd "$op" info >/dev/null 2>&1 || true
    local_address=$(get_node_address "$op")
    bitcoin_cli -rpcwallet=faucet sendtoaddress "$local_address" "$TOTAL_PER_OP" >/dev/null 2>&1
    node_id=$(run_node_cmd "$op" info 2>&1 | grep "Node ID:" | awk '{print $3}')
    store_value "node_id_$op" "$node_id"
    log_success "Funded $op ($TOTAL_PER_OP BTC): ${node_id:0:16}..."
done
mine_blocks 6
echo ""

# ============================================================================
# Phase 2: Create reserves + Open ledgers
# ============================================================================

log_info "=== Phase 2: Create Reserves + Open Ledgers ==="
current_block=$(get_block_height)
enforcement_block=$((current_block + ENFORCEMENT_DELAY))

for op in $OPERATORS; do
    for idx in $(seq 1 $LEDGERS_PER_OP); do
        suffix=""
        [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"
        utxo_sats=$((RESERVES_SATS + COLLATERAL_SATS))

        # Create reserves UTXO
        output=$(run_node_cmd "$op" reserves create "$utxo_sats" 2>&1)
        reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
        store_value "reserves_id_${op}${suffix}" "$reserves_id"

        # Open ledger with reserves + collateral split
        relay_url=$(get_node_relay_url "$op")
        output=$(run_node_cmd "$op" ledger open "$enforcement_block" \
            --annual-fee-bps "$ANNUAL_FEE_BPS" \
            --min-fee-sats "$MIN_FEE_SATS" \
            --fee-period-blocks "$FEE_PERIOD" \
            --transfer-fee-fixed-msats "$TRANSFER_FEE_FIXED" \
            --transfer-fee-rate-bps "$TRANSFER_FEE_RATE_BPS" \
            --advertise-relay "$relay_url" 2>&1)
        ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
        store_value "ledger_id_${op}${suffix}" "$ledger_id"
        log_success "$op ledger $idx: ${ledger_id:0:16}..."
    done
done
mine_blocks 1
echo ""

# ============================================================================
# Phase 3: Start nodes + Add quorum members
# ============================================================================

log_info "=== Phase 3: Start Nodes + Form Quorums (Q=$Q) ==="
start_all_nodes
sleep 2

topo_file="$STATE_DIR/topology.json"
for op in $OPERATORS; do
    op_node_id=$(get_value "node_id_$op")
    for idx in $(seq 1 $LEDGERS_PER_OP); do
        suffix=""
        [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"
        op_ledger_id=$(get_value "ledger_id_${op}${suffix}")

        members=$(python3 -c "
import json
t = json.load(open('$topo_file'))
print(' '.join(t['quorum'].get('${op}_${idx}', [])))
")
        for member in $members; do
            member_node_id=$(get_value "node_id_$member")
            member_suffix=""
            [ "$LEDGERS_PER_OP" -gt 1 ] && member_suffix="_1"
            member_ledger_id=$(get_value "ledger_id_${member}${member_suffix}")

            add_output=$(run_node_cmd "$op" quorum add "$op_ledger_id" "$member_node_id" "$member_ledger_id" 2>&1)
            if echo "$add_output" | grep -q "added"; then
                echo -n "."
            else
                log_warn "$op/$idx: failed to add $member"
            fi
        done
    done
done
echo ""
log_success "Quorum members assigned"
echo ""

# ============================================================================
# Phase 4: Activate quorums (no collateral phase needed!)
# ============================================================================

log_info "=== Phase 4: Activate Quorums ==="
for op in $OPERATORS; do
    for idx in $(seq 1 $LEDGERS_PER_OP); do
        suffix=""
        [ "$LEDGERS_PER_OP" -gt 1 ] && suffix="_$idx"
        reserves_id=$(get_value "reserves_id_${op}${suffix}")

        begin_output=$(run_node_cmd "$op" quorum begin "$reserves_id" 2>&1)
        if echo "$begin_output" | grep -q "activated\|rotated"; then
            quorum_count=$(echo "$begin_output" | grep "Quorum Members:" | awk '{print $3}')
            echo -n "."
        else
            log_warn "$op ledger $idx: $(echo "$begin_output" | head -1)"
        fi
    done
done
mine_blocks 1
echo ""
log_success "All quorums active"
echo ""

# ============================================================================
# Summary
# ============================================================================

log_info "=========================================="
log_info "  Network Ready!"
log_info "=========================================="
echo ""
log_info "  $NUM_OPS operators, $LEDGERS_PER_OP ledgers each, Q=$Q"
log_info "  $(( NUM_OPS * LEDGERS_PER_OP )) total ledgers"
log_info "  Reserves: $RESERVES_SATS sats/ledger"
log_info "  Collateral: $COLLATERAL_SATS sats/ledger (in UTXO)"
log_info "  Block: $(get_block_height)"
echo ""
log_info "Operators:"
for op in $OPERATORS; do
    node_id=$(get_value "node_id_$op")
    echo "  $op: ${node_id:0:20}..."
done
echo ""
log_info "No collateral deposits. No attestations. Just UTXOs and quorums."
echo ""
log_success "Done."
