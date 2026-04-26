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

# Relay ports — overridable via env. Default to 17779/17780 to stay
# clear of low-numbered ports that commonly collide with other dev
# services. See bin/_common.sh for the canonical defaults.
LEDGER_RELAY_PORT="${RELAY_LEDGERS_PORT:-17779}"
MSG_RELAY_PORT="${RELAY_MESSAGING_PORT:-17780}"

# Generate operator names and seeds
OPERATORS=()
declare -A SEEDS
for i in $(seq 0 $((NODE_COUNT - 1))); do
    OPERATORS+=("op$i")
    # Deterministic 64-char hex seed: "opN" zero-padded
    SEEDS["op$i"]=$(python3 -c "print('op$i'.encode().hex().ljust(64, '0'))")
done

# Electrs (shared). 3102 matches deposits-tools/docker-compose.yml which
# maps the mempool/electrs container's 3002 → host 3102. Override
# ELECTRS_URL if you run electrs under a different port.
ELECTRS_URL="${ELECTRS_URL:-http://localhost:3102}"

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
    local name=$1 port=$2
    if [ -z "$name" ] || [ -z "$port" ]; then
        log_warn "generate_relay_config: missing name or port (name='$name' port='$port')"
        return 1
    fi
    local dir="$DATA_ROOT/relays/$name"
    mkdir -p "$dir"
    # `nofiles` must fit under the invoking shell's hard RLIMIT_NOFILE;
    # 1_000_000 matches the system's typical hard cap and leaves plenty
    # of headroom for bursty CLI connection churn.
    cat > "$dir/strfry.conf" << CONF
db = "$dir"
relay {
    bind = "0.0.0.0"
    port = $port
    nofiles = 1000000
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
    # `info` and `address` previously skipped `--esplora` based on a
    # stale comment claiming they didn't accept it (they do — see
    # `parse_config`). Without it, the daemon falls back to the public
    # `mempool.space/signet/api` default, which is slow at best and
    # hangs Phase 1 outright when the public endpoint is throttling
    # us. Always pass the local electrs URL.
    RUST_LOG=error "$DEPOSITS_NODE" "$cmd" "$@" \
        --seed "$seed" --name "$name" \
        --network regtest --data-dir "$data_dir" \
        --esplora "$ELECTRS_URL" \
        $RELAY_ARGS 2>&1
}

start_node() {
    local idx=$1
    local name="op$idx"
    local seed="${SEEDS[$name]}"
    local data_dir="$DATA_ROOT/$name"
    local metrics_port=$((9100 + idx))
    mkdir -p "$data_dir"
    RUST_LOG=warn "$DEPOSITS_NODE" run \
        --seed "$seed" --name "$name" \
        --network regtest --data-dir "$data_dir" \
        --esplora "$ELECTRS_URL" \
        --metrics-port "$metrics_port" \
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

# Persisted under $DATA_ROOT so a partial run can be resumed via
# ./bin/setup-resume.sh without losing the ledger/reserves/node_id
# IDs that were resolved on the first try.
STATE_DIR="$DATA_ROOT/state"
store() { echo "$2" > "$STATE_DIR/$1"; }
get() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }

# ============================================================================
# Phase 1: Reset + Start relays + Fund
# ============================================================================

log_info "=== Phase 1: Reset + Fund ==="
stop_nodes
stop_relays
rm -rf "$DATA_ROOT"
mkdir -p "$DATA_ROOT" "$STATE_DIR"
start_relays

# Ensure the faucet wallet exists with mature coinbase funds. bitcoind
# comes up with zero wallets; we either load an existing "faucet" from
# a previous run or create it, then mine 101 blocks (coinbase maturity)
# on first init. Without this, every `bitcoin_cli -rpcwallet=faucet
# sendtoaddress` below returns error -18 and, because stderr is
# redirected to /dev/null, `set -e` silently kills the script right
# after start_relays with no diagnostic.
if ! bitcoin_cli loadwallet "faucet" >/dev/null 2>&1; then
    bitcoin_cli createwallet "faucet" >/dev/null 2>&1 || true
fi
faucet_balance=$(bitcoin_cli -rpcwallet=faucet getbalance 2>/dev/null || echo "0")
# `< 1` check as integer — bash comparison on decimal doesn't work, but
# any real balance above 1 BTC is plenty for any Q we support.
if [ "${faucet_balance%.*}" = "0" ]; then
    log_info "Mining 101 blocks for coinbase maturity..."
    bitcoin_cli -rpcwallet=faucet -generate 101 >/dev/null
    faucet_balance=$(bitcoin_cli -rpcwallet=faucet getbalance 2>/dev/null || echo "0")
fi
log_ok "Faucet wallet: $faucet_balance BTC available"

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

# Diagnostic-mode Phase 2: on the first failure, print op/ledger index,
# which CLI call failed, and the captured output. The pipe-through-tee
# absorbs the non-zero exit status of the inner CLI (so `set -e` doesn't
# kill the script before we can check the output) and persists the full
# output to a log file for post-mortem.
PHASE2_LOG="$DATA_ROOT/phase2.log"
: > "$PHASE2_LOG"
for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        utxo_sats=$((RESERVES_SATS + COLLATERAL_SATS))
        output=$(run_cmd "$i" reserves create "$utxo_sats" 2>&1 | tee -a "$PHASE2_LOG")
        reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
        if [ -z "$reserves_id" ]; then
            log_warn "op$i/L$l: reserves create produced no Address — full output:"
            echo "$output" | sed 's/^/    /' >&2
            log_warn "full Phase 2 transcript at $PHASE2_LOG"
            exit 1
        fi
        store "reserves_${i}_${l}" "$reserves_id"

        output=$(run_cmd "$i" ledger open 2>&1 | tee -a "$PHASE2_LOG")
        ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
        if [ -z "$ledger_id" ]; then
            log_warn "op$i/L$l: ledger open produced no Ledger ID — full output:"
            echo "$output" | sed 's/^/    /' >&2
            log_warn "full Phase 2 transcript at $PHASE2_LOG"
            exit 1
        fi
        store "ledger_${i}_${l}" "$ledger_id"
        # Confirm before the next reserves create and let the daemon's
        # wallet finish its post-mine esplora sync. Without the mine the
        # wallet may pick the same input for the next reserves tx and
        # collide in mempool ("insufficient fee, rejecting replacement").
        # Without the sleep the daemon hasn't yet observed the new tip
        # and may still serve the now-spent UTXO ("bad-txns-inputs-
        # missingorspent"). Both surfaced on Q=3 runs.
        mine_blocks 1
        # 3s gives electrs time to index the new block and BDK time to
        # pull it via esplora. 1s wasn't enough on Q=3 retries.
        sleep 3
    done
    # Per-op advertisement pass — `ledger advertise` walks the operator's
    # ledgers and publishes a kind:39100 for each. Without this, wallet
    # `discover` returns nothing because `ledger open` doesn't advertise
    # on its own. Send to the durable relay so the ad survives the
    # duration of the test run; the messaging relay drops events.
    run_cmd "$i" ledger advertise \
        --name "op$i" \
        --advertise-relay "ws://localhost:$LEDGER_RELAY_PORT" \
        >> "$PHASE2_LOG" 2>&1 || {
            log_warn "op$i: ledger advertise failed — see $PHASE2_LOG"
        }
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

# Same set-e trap as Phase 2: `output=$(cmd)` with a failing cmd kills
# the script before the grep + log_warn branch can run. Pipe through
# tee so the substitution always exits 0 and the full transcript is
# preserved for post-mortem.
PHASE3_LOG="$DATA_ROOT/phase3.log"
: > "$PHASE3_LOG"

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

            echo "--- op$i/L$l add op$m ---" >> "$PHASE3_LOG"
            output=$(run_cmd "$i" quorum add "$ledger_id" "$member_node_id" "$member_ledger_id" 2>&1 \
                | tee -a "$PHASE3_LOG")
            if echo "$output" | grep -qi "added\|member\|success"; then
                added=$((added + 1))
            else
                log_warn "op$i/L$l add op$m failed — see $PHASE3_LOG"
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

# Each `quorum begin`:
#   1. broadcasts the rotation tx on-chain (goes to the mempool),
#   2. waits for it to reach `default_quorum_begin_confs` (1 on regtest)
#      before requesting staged-member cosigs — staged members independently
#      verify the outpoint has enough depth, and refuse to cosign otherwise,
#   3. runs the cosign round and commits the QuorumBegin update.
#
# Step 2 will hang forever in regtest if nobody mines. So: background all
# the begin calls (they broadcast, then block in step 2 together), mine a
# block to confirm the batch of rotation txs, then wait for the backgrounded
# calls to drain.

BEGIN_LOG_DIR="$DATA_ROOT/quorum_begin_logs"
mkdir -p "$BEGIN_LOG_DIR"
begin_pids=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        # Pass the stable ledger_id rather than reserves_id: after a
        # successful rotation the reserves_key is the new Taproot
        # address and the daemon no longer resolves the old bcrt1q
        # address to a ledger. ledger_id is fixed from LedgerOpen and
        # survives rotations, so a retry via setup-resume.sh works.
        ledger_id=$(get "ledger_${i}_${l}")
        [ -z "$ledger_id" ] && continue
        run_cmd "$i" quorum begin "$ledger_id" \
            > "$BEGIN_LOG_DIR/op${i}_l${l}.log" 2>&1 &
        begin_pids+=("$!")
    done
done

# Mine periodically while begin calls drain. Some daemons broadcast
# their rotation tx later than others (16 ops × 3 ledgers, all racing
# for the wallet/network), so a single early `mine_blocks 1` only
# confirms whoever happened to broadcast in the first few seconds.
# Daemons that broadcast later see their tx sitting in mempool while
# the drain proceeds, then time out their cosign deadline. Loop:
# tick once a second, and every few ticks drop a block so any newly
# broadcast tx gets included quickly. Keep going until every begin
# pid has exited.
ok=0
fail=0
done_count=0
total=${#begin_pids[@]}
tick=0
while [ $done_count -lt $total ]; do
    sleep 1
    tick=$((tick + 1))
    # Mine every 3 ticks. Multiple blocks during a long drain confirm
    # any rotation tx that hit mempool after the previous mine.
    if [ $((tick % 3)) -eq 0 ]; then
        mine_blocks 1 2>/dev/null
    fi
    # Reap any pids that have exited; can't `wait` blockingly here
    # because we still need to mine concurrently with the drain.
    new_done=0
    for pid in "${begin_pids[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            new_done=$((new_done + 1))
        fi
    done
    done_count=$new_done
    # Hard cap: don't loop forever if a daemon is wedged.
    if [ $tick -gt 120 ]; then
        break
    fi
done

# Now harvest exit codes. Pids that died with non-zero status =
# Phase 4 failures we'll surface in the resume log.
for pid in "${begin_pids[@]}"; do
    if wait "$pid" 2>/dev/null; then
        ok=$((ok + 1))
        echo -n "."
    else
        fail=$((fail + 1))
        echo -n "x"
    fi
done
echo ""
log_ok "Quorums active ($ok ok, $fail failed — see $BEGIN_LOG_DIR/)"
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
