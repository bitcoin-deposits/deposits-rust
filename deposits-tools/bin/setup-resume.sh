#!/bin/bash
# Idempotent follow-up to ./bin/setup.sh — re-attempts Phases 3 and 4
# against an existing $DATA_ROOT without destroying prior state.
#
# Use this when setup.sh died partway through the quorum_add loop or
# the quorum_begin loop and you want to pick up where it left off
# (partial topology, some ledgers missing members, some ledgers not
# yet activated). Every CLI call is safe to re-run: the daemon-side
# state machine dedupes QuorumAddMember against active + staged sets,
# and quorum_begin is skipped per-ledger when the daemon reports it's
# already active.
#
# Assumes ./bin/setup.sh has already written $DATA_ROOT/state/ with
# the node_id / reserves_* / ledger_* lookups, and the relays + 16
# daemon processes are still running (or will be started if their
# pidfiles are stale).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$TOOLS_DIR")"

DEPOSITS_NODE="${DEPOSITS_NODE:-$REPO_ROOT/target/release/deposits-node}"
DATA_ROOT="${DATA_ROOT:-$TOOLS_DIR/data}"
STRFRY_BIN="${STRFRY_BIN:-$SCRIPT_DIR/strfry}"
ELECTRS_URL="${ELECTRS_URL:-http://localhost:3102}"

bitcoin_cli() { docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass "$@"; }
mine_blocks() { bitcoin_cli -rpcwallet=faucet -generate "$1" >/dev/null 2>&1; }

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${RED}[WARN]${NC} $*"; }

# Must match setup.sh; override via env if you ran setup.sh with a
# different value.
Q="${Q:-${1:-5}}"
NODE_COUNT=$((3 * Q + 1))
LEDGERS_PER_OP="${LEDGERS_PER_OP:-3}"

LEDGER_RELAY_PORT="${RELAY_LEDGERS_PORT:-17779}"
MSG_RELAY_PORT="${RELAY_MESSAGING_PORT:-17780}"
RELAY_ARGS="--relay ws://localhost:$LEDGER_RELAY_PORT --relay ws://localhost:$MSG_RELAY_PORT"

STATE_DIR="$DATA_ROOT/state"
if [ ! -d "$STATE_DIR" ]; then
    log_warn "No $STATE_DIR — nothing to resume. Run ./bin/setup.sh first."
    exit 1
fi
get() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }

# ============================================================================
# Seed lookup (reconstructed from op index, matching setup.sh convention)
# ============================================================================

declare -A SEEDS
for i in $(seq 0 $((NODE_COUNT - 1))); do
    SEEDS["op$i"]=$(python3 -c "print('op$i'.encode().hex().ljust(64, '0'))")
done

run_cmd() {
    local idx=$1 cmd=$2; shift 2
    local name="op$idx"
    local seed="${SEEDS[$name]}"
    local data_dir="$DATA_ROOT/$name"
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

# ============================================================================
# Relay + daemon liveness (start if pidfile is stale)
# ============================================================================

ensure_relay() {
    local name=$1 port=$2
    if [ -z "$name" ] || [ -z "$port" ]; then
        log_warn "ensure_relay: missing name or port (name='$name' port='$port')"
        return 1
    fi
    local dir="$DATA_ROOT/relays/$name"
    local pidfile="$dir/relay.pid"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        return 0
    fi
    mkdir -p "$dir"
    if [ ! -f "$dir/strfry.conf" ]; then
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
    fi
    "$STRFRY_BIN" --config "$dir/strfry.conf" relay >> "$dir/relay.log" 2>&1 &
    echo "$!" > "$pidfile"
    log_ok "(re)started relay $name on port $port"
}

ensure_daemon() {
    local idx=$1
    local name="op$idx"
    local seed="${SEEDS[$name]}"
    local data_dir="$DATA_ROOT/$name"
    local pidfile="$data_dir/daemon.pid"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        return 0
    fi
    mkdir -p "$data_dir"
    RUST_LOG=warn "$DEPOSITS_NODE" run \
        --seed "$seed" --name "$name" \
        --network regtest --data-dir "$data_dir" \
        --esplora "$ELECTRS_URL" \
        $RELAY_ARGS >> "$data_dir/daemon.log" 2>&1 &
    echo "$!" > "$pidfile"
    log_ok "(re)started $name"
}

log_info "=== Liveness check ==="
ensure_relay ledgers "$LEDGER_RELAY_PORT"
ensure_relay messaging "$MSG_RELAY_PORT"
started_any=0
for i in $(seq 0 $((NODE_COUNT - 1))); do
    before=$(cat "$DATA_ROOT/op$i/daemon.pid" 2>/dev/null || echo "")
    ensure_daemon "$i"
    after=$(cat "$DATA_ROOT/op$i/daemon.pid" 2>/dev/null || echo "")
    if [ "$before" != "$after" ]; then
        started_any=1
    fi
done
# Give the daemons time to open relay subs if any were restarted.
[ "$started_any" = "1" ] && sleep 5
echo ""

# ============================================================================
# Phase 3 (idempotent): ensure every ledger has Q quorum members staged.
# ============================================================================

log_info "=== Phase 3 resume: quorum_add for missing members ==="

PHASE3_LOG="$DATA_ROOT/phase3-resume.log"
: > "$PHASE3_LOG"

# Query op's current quorum membership via `quorum list`. Prints
# "ledger_id member_pubkey" pairs (one per line) for ledgers this
# operator owns. Empty on error.
current_members_for() {
    local idx=$1
    local out
    out=$(run_cmd "$idx" quorum list 2>&1 | tee -a "$PHASE3_LOG") || true
    # Parse the "Our ledgers:" section. Format:
    #   Our ledgers:
    #     <ledger_id>...
    #       <member_pubkey>... (active)
    #       ...
    echo "$out" | awk '
        /^Our ledgers:/ { in_ours = 1; next }
        /^Serving on quorums:/ { in_ours = 0 }
        in_ours && /^  [0-9a-f]+\.\.\./ { ledger = $1; sub(/\.\.\./, "", ledger) }
        in_ours && /^    [0-9a-f]+\.\.\./ { mem = $1; sub(/\.\.\./, "", mem); print ledger, mem }
    '
}

added_total=0
skipped_total=0
for i in $(seq 0 $((NODE_COUNT - 1))); do
    # One `quorum list` per operator gets all their ledgers at once.
    members_snapshot=$(current_members_for "$i")

    for l in $(seq 1 $LEDGERS_PER_OP); do
        ledger_id=$(get "ledger_${i}_${l}")
        [ -z "$ledger_id" ] && continue

        # Prefix match (daemon truncates ledger_ids to 16 hex chars in list output).
        ledger_prefix="${ledger_id:0:16}"
        current_for_this_ledger=$(echo "$members_snapshot" | awk -v p="$ledger_prefix" '$1 == p { print $2 }')

        # Same stride formula as setup.sh.
        offset=$(( (l - 1) * Q + 1 ))
        stride=$(( (NODE_COUNT - 1) / Q ))
        [ "$stride" -lt 1 ] && stride=1

        for j in $(seq 0 $((Q - 1))); do
            m=$(( (i + offset + j * stride) % NODE_COUNT ))
            [ "$m" -eq "$i" ] && m=$(( (m + 1) % NODE_COUNT ))
            [ "$m" -eq "$i" ] && continue

            member_node_id=$(get "node_id_$m")
            member_ledger_id=$(get "ledger_${m}_1")
            [ -z "$member_node_id" ] && continue

            member_prefix="${member_node_id:0:16}"
            if echo "$current_for_this_ledger" | grep -q "^$member_prefix$"; then
                skipped_total=$((skipped_total + 1))
                continue
            fi

            echo "--- op$i/L$l add op$m ---" >> "$PHASE3_LOG"
            output=$(run_cmd "$i" quorum add "$ledger_id" "$member_node_id" "$member_ledger_id" 2>&1 \
                | tee -a "$PHASE3_LOG")
            if echo "$output" | grep -qi "added\|member\|success"; then
                added_total=$((added_total + 1))
                echo -n "+"
            else
                log_warn "op$i/L$l add op$m failed — see $PHASE3_LOG"
                echo -n "x"
            fi
        done
    done
done
echo ""
log_ok "Phase 3 resume: $added_total added, $skipped_total already-present"
echo ""

# ============================================================================
# Phase 4 (idempotent): attempt quorum_begin for every ledger.
# The daemon errors if already active — we treat that as "already done".
# ============================================================================

log_info "=== Phase 4 resume: quorum_begin per ledger ==="

PHASE4_LOG_DIR="$DATA_ROOT/quorum_begin_resume_logs"
mkdir -p "$PHASE4_LOG_DIR"

# Give the daemons a moment to broadcast any QuorumAddMember events
# we just appended in Phase 3 resume. Without this, cosigners may not
# have them imported yet when they're asked to cosign QuorumBegin,
# which surfaces as "No quorum members to rotate to" on the operator
# side for the staged-member consumer that's still catching up.
sleep 5

begin_pids=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
    for l in $(seq 1 $LEDGERS_PER_OP); do
        # ledger_id is stable; reserves_id changes on rotation. Using
        # ledger_id lets this succeed whether or not a prior
        # QuorumBegin already rotated this ledger.
        ledger_id=$(get "ledger_${i}_${l}")
        [ -z "$ledger_id" ] && continue
        run_cmd "$i" quorum begin "$ledger_id" \
            > "$PHASE4_LOG_DIR/op${i}_l${l}.log" 2>&1 &
        begin_pids+=("$!")
    done
done

# Same rationale as setup.sh Phase 4: regtest needs a block mined
# during the confs-wait for the batch to drain.
sleep 3
mine_blocks 1

ok=0
already=0
fail=0
i=0
for pid in "${begin_pids[@]}"; do
    if wait "$pid"; then
        ok=$((ok + 1))
        echo -n "."
    else
        # Determine which log belongs to this pid via the iteration
        # position — the pid array was filled in the same order as
        # (i, l) pairs. Read the matching log; if the error message
        # indicates the ledger is already Active, that's a benign
        # skip. Anything else is real.
        fail_log=""
        idx=0
        for ii in $(seq 0 $((NODE_COUNT - 1))); do
            for ll in $(seq 1 $LEDGERS_PER_OP); do
                if [ -f "$PHASE4_LOG_DIR/op${ii}_l${ll}.log" ] && [ "$idx" = "$i" ]; then
                    fail_log="$PHASE4_LOG_DIR/op${ii}_l${ll}.log"
                fi
                idx=$((idx + 1))
            done
        done
        # A prior successful QuorumBegin surfaces on retry as one of:
        #   - "No existing reserves to rotate"  (wallet: P2WSH already spent)
        #   - "already active" / "already a quorum member"
        #   - "Ledger not found for: bcrt1q..."  (obsolete reserves_key
        #     lookup; shouldn't happen now that we pass ledger_id, but
        #     included defensively for state written by older setup.sh)
        # All three mean "the rotation is done, nothing to do here."
        if [ -n "$fail_log" ] && grep -qi \
            "already\|no existing reserves\|ledger not found for:" \
            "$fail_log"; then
            already=$((already + 1))
            echo -n "a"
        else
            fail=$((fail + 1))
            echo -n "x"
        fi
    fi
    i=$((i + 1))
done
echo ""
log_ok "Phase 4 resume: $ok ok, $already already-active, $fail failed (see $PHASE4_LOG_DIR/)"
echo ""

log_info "=== Resume complete ==="
