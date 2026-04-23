#!/bin/bash
# Simplified network setup: collateral-in-UTXO model.
#
# Usage:
#   ./bin/setup-with-q.sh 3       # 10 operators (3*3+1), Q=3
#   ./bin/setup-with-q.sh 5       # 16 operators, Q=5
#   ./bin/setup-with-q.sh 7       # 22 operators, Q=7
#
# Two relays: "ledgers" (durable) + "messaging" (ephemeral, shared).
# Each operator gets 3 ledgers with independent Q-member quorums.
# Collateral is part of the UTXO — no collateral deposit phase.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$TOOLS_DIR")"

DEPOSITS_NODE="${DEPOSITS_NODE:-$REPO_ROOT/target/release/deposits-node}"
DATA_ROOT="${DATA_ROOT:-$TOOLS_DIR/data}"
STRFRY_BIN="${STRFRY_BIN:-$SCRIPT_DIR/strfry}"

BITCOIN_RPC_HOST="localhost"
BITCOIN_RPC_PORT="18543"
BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASS="pass"

bitcoin_cli() { docker exec bitcoind bitcoin-cli -regtest -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS "$@"; }
mine_blocks() { bitcoin_cli -rpcwallet=faucet -generate "$1" >/dev/null 2>&1; }
get_block_height() { bitcoin_cli getblockcount 2>/dev/null; }

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${RED}[WARN]${NC} $*"; }

# ============================================================================
# Config
# ============================================================================

Q="${1:-5}"
NODE_COUNT=$((3 * Q + 1))
LEDGERS_PER_OP=3
RESERVES_SATS=40000000     # 0.4 BTC per ledger (40%)
COLLATERAL_SATS=60000000   # 0.6 BTC per ledger (60%)

LEDGER_RELAY_PORT=7779
MSG_RELAY_PORT=7780

# Generate operator names and seeds
OPERATORS=()
declare -A SEEDS
for i in $(seq 0 $((NODE_COUNT - 1))); do
    OPERATORS+=("op$i")
    # Deterministic 64-char hex seed: "opN" zero-padded
    SEEDS["op$i"]=$(python3 -c "print('op$i'.encode().hex().ljust(64, '0'))")
done

# Electrs (shared)
# Find first available electrs port
ELECTRS_URL="http://localhost:3201"

log_info "=========================================="
log_info "  Setup: $NODE_COUNT operators, Q=$Q"
log_info "=========================================="
log_info "Ledgers: $LEDGERS_PER_OP per operator, $(( NODE_COUNT * LEDGERS_PER_OP )) total"
log_info "Reserves: $RESERVES_SATS sats/ledger (40%)"
log_info "Collateral: $COLLATERAL_SATS sats/ledger (60%, in UTXO)"
log_info "Relays: 2 (ledgers + messaging)"
echo ""

# ============================================================================
# Relay management (just 2 relays)
# ============================================================================

generate_relay_config() {
    local name=$1 port=$2 dir="$DATA_ROOT/relays/$name"
    mkdir -p "$dir"
    cat > "$dir/strfry.conf" << CONF
db = "$dir"
relay {
    bind = "0.0.0.0"
    port = $port
    info {
        name = "$name relay"
    }
}
CONF
}

stop_relays() {
    for name in ledgers messaging; do
        local pidfile="$DATA_ROOT/relays/$name/relay.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
            log_info "Stopped relay $name"
        fi
    done
}

start_relays() {
    for name_port in "ledgers:$LEDGER_RELAY_PORT" "messaging:$MSG_RELAY_PORT"; do
        local name="${name_port%%:*}" port="${name_port##*:}"
        local dir="$DATA_ROOT/relays/$name"
        generate_relay_config "$name" "$port"
        "$STRFRY_BIN" --config "$dir/strfry.conf" relay >> "$dir/relay.log" 2>&1 &
        echo "$!" > "$dir/relay.pid"
        log_ok "Relay $name on port $port"
    done
    sleep 2
}

# ============================================================================
# Node management
# ============================================================================

RELAY_ARGS="--relay ws://localhost:$LEDGER_RELAY_PORT --relay ws://localhost:$MSG_RELAY_PORT"

run_cmd() {
    local idx=$1 cmd=$2; shift 2
    local name="op$idx"
    local seed="${SEEDS[$name]}"
    local data_dir="$DATA_ROOT/$name"
    # Some commands (reserves, quorum) need esplora; info/address don't accept it
    local esplora_arg=""
    case "$cmd" in
        reserves|quorum|ledger|daemon|deposit|collateral) esplora_arg="--esplora $ELECTRS_URL" ;;
    esac
    RUST_LOG=error "$DEPOSITS_NODE" "$cmd" "$@" \
        --seed "$seed" --name "$name" \
        --network regtest --data-dir "$data_dir" \
        $esplora_arg \
        $RELAY_ARGS 2>&1
}

start_node() {
    local idx=$1
    local name="op$idx"
    local seed="${SEEDS[$name]}"
    local data_dir="$DATA_ROOT/$name"
    mkdir -p "$data_dir"
    RUST_LOG=warn "$DEPOSITS_NODE" run \
        --seed "$seed" --name "$name" \
        --network regtest --data-dir "$data_dir" \
        --esplora "$ELECTRS_URL" \
        $RELAY_ARGS >> "$data_dir/daemon.log" 2>&1 &
    echo "$!" > "$data_dir/daemon.pid"
}

stop_nodes() {
    for i in $(seq 0 $((NODE_COUNT - 1))); do
        local pidfile="$DATA_ROOT/op$i/daemon.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
        fi
    done
}

# ============================================================================
# State storage
# ============================================================================

STATE_DIR=$(mktemp -d)
trap "rm -rf $STATE_DIR" EXIT
store() { echo "$2" > "$STATE_DIR/$1"; }
get() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }

# ============================================================================
# Phase 1: Reset + Start relays + Fund
# ============================================================================

log_info "=== Phase 1: Reset + Fund ==="
stop_nodes
stop_relays
rm -rf "$DATA_ROOT"
mkdir -p "$DATA_ROOT"
start_relays

# Fund all operators in one bitcoin batch. `address` and `info` are
# read-only CLI commands that use a short-lived Node instance — they
# don't need a running daemon.
TOTAL_BTC=$(python3 -c "print(f'{($RESERVES_SATS + $COLLATERAL_SATS) * $LEDGERS_PER_OP / 100_000_000 + 0.5:.1f}')")
for i in $(seq 0 $((NODE_COUNT - 1))); do
    address=$(run_cmd "$i" address 2>&1 | grep -oE 'bcrt1[a-z0-9]+' | head -1)
    bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" "$TOTAL_BTC" >/dev/null 2>&1
    node_id=$(run_cmd "$i" info 2>&1 | grep "Node ID:" | awk '{print $3}')
    store "node_id_$i" "$node_id"
done
mine_blocks 6
log_ok "Funded $NODE_COUNT operators ($TOTAL_BTC BTC each)"
echo ""

# ============================================================================
# Phase 1b: Start daemons
# ============================================================================
#
# `reserves create`, `ledger open`, `quorum add`, and `quorum begin` are
# now gift-wrapped Nostr requests that go to the running daemon (commit
# 30c268a). Start the daemons now — *before* Phase 2 — so the requests
# there have a daemon to talk to. Without this, Phase 2 times out after
# 60s with "admin request timeout".

log_info "=== Phase 1b: Start Daemons ==="
for i in $(seq 0 $((NODE_COUNT - 1))); do
    start_node "$i"
done
# Give the daemons time to open relay subscriptions and sync the wallet
# against the funded UTXOs.
sleep 5
log_ok "Started $NODE_COUNT daemons"
echo ""

# ============================================================================
# Phase 2: Create reserves + Open ledgers
# ============================================================================

log_info "=== Phase 2: Reserves + Ledgers ==="
current_block=$(get_block_height)

for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        utxo_sats=$((RESERVES_SATS + COLLATERAL_SATS))
        output=$(run_cmd "$i" reserves create "$utxo_sats" 2>&1 | tee reserves-create.log)
        reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
        store "reserves_${i}_${l}" "$reserves_id"

        output=$(run_cmd "$i" ledger open \
            --advertise-relay "ws://localhost:$MSG_RELAY_PORT" 2>&1)
        ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
        store "ledger_${i}_${l}" "$ledger_id"
    done
    echo -n "."
done
mine_blocks 1
echo ""
log_ok "Created $((NODE_COUNT * LEDGERS_PER_OP)) ledgers"
echo ""

# ============================================================================
# Phase 3: Form quorums
# ============================================================================

log_info "=== Phase 3: Form Quorums (Q=$Q) ==="

# Assign quorum members: for operator i ledger l, pick Q members
# dispersed across the remaining operators (stride-based, skip self)
for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        ledger_id=$(get "ledger_${i}_${l}")
        [ -z "$ledger_id" ] && continue

        # Pick Q members: start from offset based on ledger index, stride to spread
        offset=$(( (l - 1) * Q + 1 ))
        stride=$(( (NODE_COUNT - 1) / Q ))
        [ "$stride" -lt 1 ] && stride=1

        added=0
        for j in $(seq 0 $((Q - 1))); do
            m=$(( (i + offset + j * stride) % NODE_COUNT ))
            [ "$m" -eq "$i" ] && m=$(( (m + 1) % NODE_COUNT ))
            [ "$m" -eq "$i" ] && continue

            member_node_id=$(get "node_id_$m")
            member_ledger_id=$(get "ledger_${m}_1")
            [ -z "$member_node_id" ] && continue

            output=$(run_cmd "$i" quorum add "$ledger_id" "$member_node_id" "$member_ledger_id" 2>&1)
            if echo "$output" | grep -qi "added\|member\|success"; then
                added=$((added + 1))
            else
                log_warn "op$i/L$l add op$m: $output"
            fi
        done
        echo -n "."
    done
done
echo ""
log_ok "Quorum members assigned"
echo ""

# ============================================================================
# Phase 4: Activate quorums
# ============================================================================

log_info "=== Phase 4: Activate Quorums ==="
for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        reserves_id=$(get "reserves_${i}_${l}")
        [ -z "$reserves_id" ] && continue
        run_cmd "$i" quorum begin "$reserves_id" >/dev/null 2>&1 && echo -n "." || echo -n "x"
    done
done
mine_blocks 1
echo ""
log_ok "Quorums active"
echo ""

# ============================================================================
# Summary
# ============================================================================

log_info "=========================================="
log_info "  Network Ready"
log_info "=========================================="
log_info "  $NODE_COUNT operators, Q=$Q, $LEDGERS_PER_OP ledgers each"
log_info "  $(( NODE_COUNT * LEDGERS_PER_OP )) total ledgers"
log_info "  Reserves: $RESERVES_SATS sats/ledger (40%)"
log_info "  Collateral: $COLLATERAL_SATS sats/ledger (60%, in UTXO)"
log_info "  Block: $(get_block_height)"
log_info "  Relays: ws://localhost:$LEDGER_RELAY_PORT (ledgers) ws://localhost:$MSG_RELAY_PORT (messaging)"
echo ""
log_ok "Done. No collateral deposits. No attestations. Just UTXOs and quorums."
