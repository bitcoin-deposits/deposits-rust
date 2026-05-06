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

    # Optional: provision a co-located deposits-signer when
    # DEPOSITS_USE_SIGNER=1 is set in the environment. Mirrors the
    # _common.sh::start_node logic.
    local signer_flags=""
    if [ "${DEPOSITS_USE_SIGNER:-}" = "1" ]; then
        local signer_data_dir="$data_dir/signer"
        local signer_socket="$data_dir/signer.sock"
        local signer_bin="${DEPOSITS_SIGNER:-$REPO_ROOT/target/release/deposits-signer}"
        if [ ! -f "$signer_data_dir/transport_secret" ]; then
            local seed_file="$data_dir/_signer_seed.tmp"
            echo "$seed" > "$seed_file"
            chmod 0600 "$seed_file"
            "$signer_bin" init \
                --data-dir "$signer_data_dir" \
                --seed-file "$seed_file" >/dev/null
            rm -f "$seed_file"
        fi
        local node_transport_pubkey
        node_transport_pubkey=$("$DEPOSITS_NODE" transport-pubkey --data-dir "$data_dir" 2>/dev/null)
        "$signer_bin" trust add \
            --data-dir "$signer_data_dir" \
            "$node_transport_pubkey" >/dev/null 2>&1 || true
        local signer_pubkey
        signer_pubkey=$("$signer_bin" pubkey --data-dir "$signer_data_dir")
        rm -f "$signer_socket"
        RUST_LOG=info "$signer_bin" run \
            --data-dir "$signer_data_dir" \
            --socket "$signer_socket" \
            > "$data_dir/signer.log" 2>&1 &
        echo "$!" > "$data_dir/signer.pid"
        local waited=0
        while [ ! -S "$signer_socket" ] && [ "$waited" -lt 30 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        signer_flags="--signer-pubkey $signer_pubkey --signer-socket $signer_socket"
    fi

    RUST_LOG="${SETUP_RUST_LOG:-warn}" LDK_CLI="$LDK_CLI" LDK_REAL_CLI="$LDK_REAL_CLI" \
        LDK_HOST="$LDK_HOST" LDK_PORT="$LDK_PORT" \
        LDK_API_KEY="$LDK_API_KEY" LDK_TLS_CERT="$LDK_TLS_CERT" \
        LDK_SELF_PAY_DIR="$LDK_SELF_PAY_DIR" \
        "$DEPOSITS_NODE" run \
        --seed "$seed" --name "$name" \
        --network regtest --data-dir "$data_dir" \
        --esplora "$ELECTRS_URL" \
        --metrics-port "$metrics_port" \
        --fast-poll \
        $RELAY_ARGS \
        $signer_flags >> "$data_dir/daemon.log" 2>&1 &
    echo "$!" > "$data_dir/daemon.pid"
}

stop_nodes() {
    for i in $(seq 0 $((NODE_COUNT - 1))); do
        local pidfile="$DATA_ROOT/op$i/daemon.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
        fi
        # Co-located signer (DEPOSITS_USE_SIGNER=1).
        local signer_pidfile="$DATA_ROOT/op$i/signer.pid"
        if [ -f "$signer_pidfile" ] && kill -0 "$(cat "$signer_pidfile")" 2>/dev/null; then
            kill "$(cat "$signer_pidfile")" 2>/dev/null || true
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
# `ledger open`, `quorum add`, and `quorum begin` are gift-wrapped Nostr
# requests that go to the running daemon. Start the daemons now —
# *before* Phase 2 — so the requests there have a daemon to talk to.
# Without this, Phase 2 times out after 60s with "admin request timeout".

log_info "=== Phase 1b: Start Daemons ==="

# LDK wiring (optional). When the `lightning` container is up, refresh
# the TLS cert from inside it (ldk-server regenerates self-signed certs
# on every container start) and export LDK_* so each operator's
# `make_invoice` / `pay_invoice` handler can talk to it. Without this,
# operators fall through to "ldk-server-cli not in PATH" and any
# Lightning-touching test fails. Mirrors `_common.sh:start_node`'s
# block but lives here because setup.sh has its own start_node copy.
LDK_CLI=""; LDK_REAL_CLI=""; LDK_HOST=""; LDK_PORT=""
LDK_API_KEY=""; LDK_TLS_CERT=""; LDK_SELF_PAY_DIR=""
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^lightning$'; then
    mkdir -p "$TOOLS_DIR/certs"
    if docker cp lightning:/ldk/tls.crt "$TOOLS_DIR/certs/lightning.crt" 2>/dev/null; then
        log_ok "Refreshed LDK TLS cert from lightning container"
    fi
    LDK_CLI="$TOOLS_DIR/bin/ldk-cli-wrapper.sh"
    LDK_REAL_CLI="${LDK_SERVER_CLI:-$HOME/ldk-server/target/release/ldk-server-cli}"
    [ -x "$LDK_REAL_CLI" ] || log_warn "ldk-server-cli not found at $LDK_REAL_CLI"
    LDK_HOST="localhost"
    LDK_PORT="3111"
    LDK_API_KEY=$(docker exec lightning sh -c "cat /ldk/regtest/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null || echo "")
    LDK_TLS_CERT="$TOOLS_DIR/certs/lightning.crt"
    LDK_SELF_PAY_DIR="$DATA_ROOT/self-pay"
    mkdir -p "$LDK_SELF_PAY_DIR"
fi
export LDK_CLI LDK_REAL_CLI LDK_HOST LDK_PORT LDK_API_KEY LDK_TLS_CERT LDK_SELF_PAY_DIR

for i in $(seq 0 $((NODE_COUNT - 1))); do
    start_node "$i"
done
# Give the daemons time to open relay subscriptions and sync the wallet
# against the funded UTXOs. 10 daemons coming up at once need esplora
# enough time to index — 5s wasn't always enough; 12s is the new floor.
# Override via DEPOSITS_PHASE1B_SYNC_SLEEP if your host's electrs is
# slow.
sleep "${DEPOSITS_PHASE1B_SYNC_SLEEP:-12}"
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
# Per-ledger funding amount: reserves + collateral (legacy split kept
# for documentation; the on-chain Taproot vault no longer separates
# them, but the total reflects the same intent).
PER_LEDGER_SATS=$((RESERVES_SATS + COLLATERAL_SATS))
PER_LEDGER_BTC=$(python3 -c "print('{:.8f}'.format($PER_LEDGER_SATS / 100000000))")

for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        # `ledger open` is a pure declaration. The on-chain commitment
        # happens later at `quorum begin`, which draws inputs from the
        # ledger's *own* per-ledger BDK wallet (introduced in phase 1).
        # Each ledger has an isolated UTXO set, so multiple `quorum
        # begin` calls on the same operator can't race for the same
        # coins.
        output=$(run_cmd "$i" ledger open 2>&1 | tee -a "$PHASE2_LOG")
        ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
        if [ -z "$ledger_id" ]; then
            log_warn "op$i/L$l: ledger open produced no Ledger ID — full output:"
            echo "$output" | sed 's/^/    /' >&2
            log_warn "full Phase 2 transcript at $PHASE2_LOG"
            exit 1
        fi
        store "ledger_${i}_${l}" "$ledger_id"

        # Pre-fund the ledger from the faucet. `ledger address` returns
        # a fresh receive address from the per-ledger wallet; the
        # bitcoin-core faucet wallet sends $PER_LEDGER_BTC there.
        # External pre-funding by design — the daemon never needs to
        # juggle a shared wallet, and the funding source is the
        # operator's choice (here: the regtest faucet).
        addr=$(run_cmd "$i" ledger address "$ledger_id" 2>>"$PHASE2_LOG" | tail -1)
        if [ -z "$addr" ]; then
            log_warn "op$i/L$l ($ledger_id): ledger address produced no output"
            log_warn "full Phase 2 transcript at $PHASE2_LOG"
            exit 1
        fi
        bitcoin_cli -rpcwallet=faucet sendtoaddress "$addr" "$PER_LEDGER_BTC" \
            >> "$PHASE2_LOG" 2>&1 || {
                log_warn "op$i/L$l: faucet sendtoaddress $addr failed — see $PHASE2_LOG"
                exit 1
            }
    done
    # Per-op advertisement pass — `ledger advertise` walks the operator's
    # ledgers and publishes a kind:39100 for each.
    run_cmd "$i" ledger advertise \
        --name "op$i" \
        --advertise-relay "ws://localhost:$LEDGER_RELAY_PORT" \
        >> "$PHASE2_LOG" 2>&1 || {
            log_warn "op$i: ledger advertise failed — see $PHASE2_LOG"
        }
    echo -n "."
done
# Confirm all the pre-funding txs in one block. With per-ledger
# wallets each tx pays a distinct address — no UTXO contention with
# previous iterations, no need to mine between iterations.
mine_blocks 6
echo ""
log_ok "Created + pre-funded $((NODE_COUNT * LEDGERS_PER_OP)) ledgers ($PER_LEDGER_BTC BTC each)"
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
        # Activation amount = exactly what we pre-funded, minus a fee
        # buffer. Without this, the daemon defaults to spending the
        # ledger wallet's full balance — which on a re-run also
        # includes leftover UTXOs from previous setups (the address
        # is deterministic from the operator seed), inflating the
        # spend past available coins.
        ACTIVATION_SATS=$((PER_LEDGER_SATS - 1000))
        run_cmd "$i" quorum begin "$ledger_id" --amount-sats $ACTIVATION_SATS \
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
