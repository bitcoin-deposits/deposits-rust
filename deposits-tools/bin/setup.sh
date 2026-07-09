#!/bin/bash
# Regtest cluster setup — thin wrapper over `deposits-hub bootstrap`.
#
# FULL CONVERGENCE: the regtest cluster is now the SAME shape production
# runs. `deposits-hub bootstrap` is the canonical stand-up; this script
# just supplies the regtest-only bits bootstrap can't do itself (start the
# two strfry relays, ensure the docker chain infra is up, fund the
# treasury from the faucet, and mine while bootstrap waits on
# confirmations). The resulting layout is the production one:
#
#   deposits-tools/data/bootstrap-nodes/node{0..N-1}/   (each: seed.hex,
#                                                        wallet/ledgers/, …)
#   deposits-tools/data/bootstrap-treasury/
#   deposits-tools/data/bootstrap-state.json            (topology of record)
#
# so sweep-all / `deposits-node archive` / hub admin work against regtest
# exactly as against mainnet — NO layout adapter.
#
# Usage:
#   ./bin/setup.sh            # default: 10 nodes, Q=3
#   ./bin/setup.sh 10         # N nodes (each an operator + cosigner), Q=3
#   ./bin/setup.sh --fresh 10 # wipe bitcoind + electrs chain first
#
# The node count is the number of operators. Bootstrap cross-wires Q=3
# cosigners per ledger (protocol floor), so N ≥ 4. The integration tests
# reference operators up to op9 and assume several cosigners per ledger,
# so the default is 10 (op{i} ↔ node{i}, 1:1).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$TOOLS_DIR")"

DEPOSITS_NODE="${DEPOSITS_NODE:-$REPO_ROOT/target/release/deposits-node}"
DEPOSITS_HUB="${DEPOSITS_HUB:-$REPO_ROOT/target/release/deposits-hub}"
DATA_ROOT="${DATA_ROOT:-$TOOLS_DIR/data}"
STRFRY_BIN="${STRFRY_BIN:-$SCRIPT_DIR/strfry}"

BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASS="pass"

bitcoin_cli() { docker exec bitcoind bitcoin-cli -regtest -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS "$@"; }
mine_blocks() { bitcoin_cli -rpcwallet=faucet -generate "$1" >/dev/null 2>&1 || true; }
get_block_height() { bitcoin_cli getblockcount 2>/dev/null; }

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${RED}[WARN]${NC} $*"; }

# ============================================================================
# Args
# ============================================================================

# --fresh / --reset-chain → wipe bitcoind + electrs data volumes before
# anything else (see the block below). --fresh also implies a full
# `bootstrap --reset` so the cluster is rebuilt from scratch.
FRESH=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --fresh|--reset-chain)
            FRESH=1
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done
set -- "${ARGS[@]}"

# First positional is the node count (operators). Historically this slot
# was "Q"; it is now the operator count directly. Default 10 so op{i} ↔
# node{i} is 1:1 up to op9 (the highest index the tests reference).
NODES="${1:-10}"
if [ "$NODES" -lt 4 ]; then
    log_warn "node count must be ≥ 4 (each ledger needs Q=3 cosigners); bumping to 4"
    NODES=4
fi
PER_LEDGER_SATS="${PER_LEDGER_SATS:-100000000}"   # 1 BTC per ledger

# Relay ports — overridable via env. Canonical defaults in bin/_common.sh.
LEDGER_RELAY_PORT="${RELAY_LEDGERS_PORT:-17779}"
MSG_RELAY_PORT="${RELAY_MESSAGING_PORT:-17780}"
LEDGER_RELAY_URL="ws://localhost:$LEDGER_RELAY_PORT"
MSG_RELAY_URL="ws://localhost:$MSG_RELAY_PORT"

# Electrs (shared). 3102 matches deposits-tools/docker-compose.yml.
ELECTRS_URL="${ELECTRS_URL:-http://localhost:3102}"

HUB_DATA_DIR="$DATA_ROOT"

log_info "=========================================="
log_info "  Regtest cluster via deposits-hub bootstrap"
log_info "=========================================="
log_info "  $NODES operators, Q=3 (cross-wired), 1 ledger each"
log_info "  Layout: $DATA_ROOT/bootstrap-nodes/node{0..$((NODES-1))}"
log_info "  Relays: $LEDGER_RELAY_URL (ledgers) $MSG_RELAY_URL (messaging)"
log_info "  Esplora: $ELECTRS_URL"
echo ""

# ============================================================================
# Relay management (2 strfry relays)
# ============================================================================

generate_relay_config() {
    local name=$1 port=$2
    local dir="$DATA_ROOT/relays/$name"
    mkdir -p "$dir"
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
# Phase 0: chain infra + faucet + relays
# ============================================================================

log_info "=== Phase 0: chain infra + relays + faucet ==="
stop_relays

if [ "$FRESH" = "1" ]; then
    # Wipe bitcoind + electrs chain state (long-running regtest chains make
    # generatetoaddress slow, which drags out confiscation tests). Also do a
    # full bootstrap --reset so the cluster rebuilds from scratch.
    log_info "[fresh] resetting bitcoind + electrs state + bootstrap cluster"
    "$DEPOSITS_HUB" bootstrap --reset --data-dir "$HUB_DATA_DIR" >/dev/null 2>&1 || true
    pushd "$TOOLS_DIR" >/dev/null
    docker compose stop bitcoin miner electrs >/dev/null 2>&1 || true
    docker compose rm -f bitcoin miner electrs >/dev/null 2>&1 || true
    docker volume rm -f deposits-tools_bitcoin_data deposits-tools_electrs_data >/dev/null 2>&1 || true
    docker compose up -d bitcoin >/dev/null 2>&1
    fresh_waited=0
    until bitcoin_cli getblockchaininfo >/dev/null 2>&1; do
        sleep 1
        fresh_waited=$((fresh_waited + 1))
        [ "$fresh_waited" -ge 30 ] && { log_warn "[fresh] bitcoind RPC didn't come back within 30s"; break; }
    done
    docker compose up -d miner electrs >/dev/null 2>&1
    popd >/dev/null
    log_ok "[fresh] bitcoind + electrs at empty regtest chain"
fi

# Ensure the docker chain stack is up (idempotent).
pushd "$TOOLS_DIR" >/dev/null
docker compose up -d bitcoin miner electrs >/dev/null 2>&1 || true
popd >/dev/null

# Ensure the faucet wallet exists with mature coinbase funds.
if ! bitcoin_cli loadwallet "faucet" >/dev/null 2>&1; then
    bitcoin_cli createwallet "faucet" >/dev/null 2>&1 || true
fi
faucet_balance=$(bitcoin_cli -rpcwallet=faucet getbalance 2>/dev/null || echo "0")
if [ "${faucet_balance%.*}" = "0" ]; then
    log_info "Mining 101 blocks for coinbase maturity..."
    bitcoin_cli -rpcwallet=faucet -generate 101 >/dev/null
    faucet_balance=$(bitcoin_cli -rpcwallet=faucet getbalance 2>/dev/null || echo "0")
fi
log_ok "Faucet wallet: $faucet_balance BTC available"

start_relays
echo ""

# ============================================================================
# Phase 1: background faucet + miner (feeds bootstrap's confirmation waits)
# ============================================================================
#
# `deposits-hub bootstrap` prints a treasury address and POLLS esplora until
# it confirms; later it broadcasts a disbursement tx + N quorum-begin
# activation txs and waits for THOSE to confirm. On regtest nothing mines
# unless we do — so run a background loop that:
#   1. Once bootstrap has written the treasury address to
#      bootstrap-state.json, sends it the required funding (one time).
#   2. Mines a block every few seconds so every confirmation wait advances.
# The loop exits when bootstrap finishes (its state file records all
# quorums Active) or when this script's main process goes away.

STATE_JSON="$HUB_DATA_DIR/bootstrap-state.json"
# Required funding: per_ledger * N + a generous fee/vsize pad. Bootstrap's
# own estimate is smaller; we overshoot so the single treasury UTXO can
# cover the disbursement with change.
FUND_SATS=$(( PER_LEDGER_SATS * NODES + 10000000 ))
FUND_BTC=$(python3 -c "print('{:.8f}'.format($FUND_SATS / 100000000))")

faucet_miner_loop() {
    local funded=0
    while :; do
        # Fund the treasury once its address is known and not yet funded.
        if [ "$funded" -eq 0 ] && [ -f "$STATE_JSON" ]; then
            local addr
            addr=$(python3 -c "import json,sys; d=json.load(open('$STATE_JSON')); print(d.get('treasury_address') or '')" 2>/dev/null || echo "")
            if [ -n "$addr" ]; then
                bitcoin_cli -rpcwallet=faucet sendtoaddress "$addr" "$FUND_BTC" >/dev/null 2>&1 \
                    && funded=1
            fi
        fi
        mine_blocks 1
        sleep 2
    done
}

faucet_miner_loop &
MINER_LOOP_PID=$!
# Kill the loop when the script exits for any reason.
trap 'kill "$MINER_LOOP_PID" 2>/dev/null || true' EXIT
log_ok "Background faucet+miner running (pid $MINER_LOOP_PID)"
echo ""

# ============================================================================
# Phase 2: deposits-hub bootstrap (the canonical cluster stand-up)
# ============================================================================

log_info "=== Phase 2: deposits-hub bootstrap --nodes $NODES ==="

# Lightning backend wiring, forwarded to every spawned daemon via
# --daemon-env. Default (`LIGHTNING_BACKEND` unset or `ldk`) exports LDK_*
# so operators' make_invoice / pay_invoice talk to the shared `lightning`
# (LDK) container. Mirrors the old setup.sh backend gate.
BOOTSTRAP_ENV_ARGS=()
add_env() { [ -n "$2" ] && BOOTSTRAP_ENV_ARGS+=(--daemon-env "$1=$2"); }

case "${LIGHTNING_BACKEND:-ldk}" in
    ldk)
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^lightning$'; then
            mkdir -p "$TOOLS_DIR/certs"
            docker cp lightning:/ldk/tls.crt "$TOOLS_DIR/certs/lightning.crt" 2>/dev/null \
                && log_ok "Refreshed LDK TLS cert from lightning container"
            add_env LDK_CLI "$TOOLS_DIR/bin/ldk-cli-wrapper.sh"
            add_env LDK_REAL_CLI "${LDK_SERVER_CLI:-$HOME/ldk-server/target/release/ldk-server-cli}"
            add_env LDK_HOST "localhost"
            add_env LDK_PORT "3111"
            add_env LDK_API_KEY "$(docker exec lightning sh -c 'cat /ldk/regtest/api_key | od -A n -t x1 | tr -d " \n"' 2>/dev/null || echo '')"
            add_env LDK_TLS_CERT "$TOOLS_DIR/certs/lightning.crt"
            add_env LDK_SELF_PAY_DIR "$DATA_ROOT/self-pay"
            mkdir -p "$DATA_ROOT/self-pay"
        fi
        ;;
    lnd|cln)
        add_env LIGHTNING_BACKEND "$LIGHTNING_BACKEND"
        log_warn "LIGHTNING_BACKEND=$LIGHTNING_BACKEND: ensure the container is up + pass its env via --daemon-env."
        ;;
esac

# Run bootstrap. It is idempotent/resumable, so a transient relay hiccup is
# recoverable by re-running. --node-bin pins the (release) daemon binary.
# `set +e` around it so a non-zero exit doesn't skip the miner-loop cleanup
# below (bootstrap can be re-run to resume).
set +e
RUST_LOG="${SETUP_RUST_LOG:-warn}" \
    "$DEPOSITS_HUB" bootstrap \
    --data-dir "$HUB_DATA_DIR" \
    --nodes "$NODES" \
    --network regtest \
    --relay "$LEDGER_RELAY_URL" \
    --relay "$MSG_RELAY_URL" \
    --esplora "$ELECTRS_URL" \
    --per-ledger-sats "$PER_LEDGER_SATS" \
    --node-bin "$DEPOSITS_NODE" \
    "${BOOTSTRAP_ENV_ARGS[@]}"
BOOTSTRAP_RC=$?
set -e

# Stop the background miner now that bootstrap has returned.
kill "$MINER_LOOP_PID" 2>/dev/null || true
trap - EXIT

echo ""
if [ "$BOOTSTRAP_RC" -ne 0 ]; then
    log_warn "bootstrap exited $BOOTSTRAP_RC — re-run ./bin/setup.sh $NODES to resume (idempotent)."
    exit "$BOOTSTRAP_RC"
fi

# ============================================================================
# Summary
# ============================================================================

log_info "=========================================="
log_info "  Network Ready"
log_info "=========================================="
log_info "  $NODES operators, Q=3, 1 ledger each"
log_info "  Layout: $DATA_ROOT/bootstrap-nodes/node{0..$((NODES-1))}"
log_info "  Block: $(get_block_height)"
log_info "  Relays: $LEDGER_RELAY_URL (ledgers) $MSG_RELAY_URL (messaging)"
echo ""
log_ok "Done. One regtest shape = production. Tools (sweep-all, archive, hub admin) work uniformly."
