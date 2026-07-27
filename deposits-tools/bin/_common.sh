#!/bin/bash
# Common functions for test scripts
# Source this file from other scripts: source "$(dirname "$0")/_common.sh"

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory containing this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$TOOLS_DIR")"

# Docker compose command (infrastructure services only)
DC="docker compose -f $TOOLS_DIR/docker-compose.yml"

# Binary paths (host-compiled)
DEPOSITS_NODE="${DEPOSITS_NODE:-$REPO_ROOT/target/release/deposits-node}"
DEPOSITS_WALLET="${DEPOSITS_WALLET:-$REPO_ROOT/target/release/deposits-wallet}"
DEPOSITS_SIGNER="${DEPOSITS_SIGNER:-$REPO_ROOT/target/release/deposits-signer}"

# Data directory root for all nodes
DATA_ROOT="${DATA_ROOT:-$TOOLS_DIR/data}"

# Bitcoin RPC settings (matching docker-compose mapped ports)
BITCOIN_RPC_HOST="localhost"
BITCOIN_RPC_PORT="18543"
BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASS="pass"

# Electrs settings
# Per-node Electrs: each pair of nodes shares an Electrs instance.
# Group G = ceil(index/2), host port = 3200 + G.
# The legacy shared Electrs (port 3102) is kept for ad-hoc use.
ELECTRS_HOST="localhost"
ELECTRS_PORT="3102"
ELECTRS_URL="http://$ELECTRS_HOST:$ELECTRS_PORT"
ELECTRS_IMAGE="mempool/electrs:v3.2.0"
ELECTRS_DOCKER_NETWORK="deposits-tools_regtest"

# ── Relay endpoints ──────────────────────────────────────────────────
#
# Single source of truth for the durable "ledgers" relay and the
# ephemeral "messaging" relay. Override any of these env vars before
# sourcing this file (or before running setup.sh / cargo test) to
# point the cluster at different ports — e.g. when 17779/17780 are
# already in use, or when running multiple clusters side-by-side.
#
# Everything else (setup scripts, docker-compose, integration tests,
# CI) reads from these — no other place in the tree should hardcode a
# port number for these relays.
export RELAY_LEDGERS_PORT="${RELAY_LEDGERS_PORT:-17779}"
export RELAY_MESSAGING_PORT="${RELAY_MESSAGING_PORT:-17780}"
export RELAY_LEDGERS="${RELAY_LEDGERS:-ws://localhost:$RELAY_LEDGERS_PORT}"
export RELAY_MESSAGING="${RELAY_MESSAGING:-ws://localhost:$RELAY_MESSAGING_PORT}"

ALL_RELAYS=()
# Legacy aliases (set by init_topology for backward compat when NODE_COUNT=4)
RELAY_ALICE=""
RELAY_BOB=""
RELAY_CHARLIE=""
RELAY_DIANA=""

# Native strfry relay binary
STRFRY_BIN="${STRFRY_BIN:-$SCRIPT_DIR/strfry}"

# Get the port for a relay by name
get_relay_port() {
    local name=$1
    if [ "$name" = "ledgers" ]; then
        echo "$RELAY_LEDGERS_PORT"
        return
    fi
    if [ "$name" = "messaging" ]; then
        echo "$RELAY_MESSAGING_PORT"
        return
    fi
    local idx=$(get_node_index "$name")
    if [ -n "$idx" ]; then
        echo $((7800 + idx))
    else
        return 1
    fi
}

# Generate a strfry config for a relay and write it to the relay data dir.
# Usage: generate_relay_config <name>
generate_relay_config() {
    local name=$1
    if [ -z "$name" ]; then
        log_error "generate_relay_config: missing relay name"
        return 1
    fi
    local port=$(get_relay_port "$name")
    local db_dir="$DATA_ROOT/relays/$name"
    local conf="$db_dir/strfry.conf"

    mkdir -p "$db_dir"

    # Base config from the relay config templates
    local src_conf="$REPO_ROOT/deposits-tools/config/strfry.conf"
    if [ "$name" = "ledgers" ]; then
        src_conf="$REPO_ROOT/deposits-tools/config/strfry-slow.conf"
    fi

    # Copy and patch: db path, port, and write policy path
    sed \
        -e "s|^db = .*|db = \"$db_dir/\"|" \
        -e "s|port = 7777|port = $port|" \
        -e "s|plugin = \"/app/drop-ephemeral-policy.sh\"|plugin = \"$TOOLS_DIR/drop-ephemeral-policy.sh\"|" \
        "$src_conf" > "$conf"

    # Node relays are real-time message buses — keep events only 30 seconds
    # (the template defaults to 300s which accumulates too much LMDB data).
    # Also cap mapsize to 256MB so a burst can't eat all disk.
    if [ "$name" != "ledgers" ]; then
        sed -i \
            -e "s|ephemeralEventsLifetimeSeconds = 300|ephemeralEventsLifetimeSeconds = 30|" \
            -e "s|mapsize = 10995116277760|mapsize = 268435456|" \
            "$conf"
    fi
}

# Start a native strfry relay process.
# Usage: start_relay <name>
start_relay() {
    local name=$1
    if [ -z "$name" ]; then
        log_error "start_relay: missing relay name"
        return 1
    fi
    local port=$(get_relay_port "$name")
    local db_dir="$DATA_ROOT/relays/$name"
    local conf="$db_dir/strfry.conf"
    local pidfile="$db_dir/relay.pid"
    local logfile="$db_dir/relay.log"

    # Don't start if already running
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        log_info "Relay $name already running (pid $(cat "$pidfile"))"
        return 0
    fi

    generate_relay_config "$name"

    "$STRFRY_BIN" --config "$conf" relay >> "$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"
    log_success "Started relay $name (pid $pid, port $port)"

    # For the ledgers relay, also start stream processes from each fast relay
    if [ "$name" = "ledgers" ]; then
        # Wait for relay to be listening
        local attempts=0
        while ! curl -s "http://localhost:$port" >/dev/null 2>&1; do
            sleep 1
            attempts=$((attempts + 1))
            if [ $attempts -ge 15 ]; then
                log_error "Ledgers relay not ready after 15s"
                return 1
            fi
        done
        # Stream from each fast relay
        for op in "${NODES[@]}"; do
            local op_port=$(get_relay_port "$op")
            "$STRFRY_BIN" --config "$conf" stream "ws://localhost:$op_port" --dir=down >> "$logfile" 2>&1 &
            echo "$!" >> "$db_dir/stream.pids"
        done
        log_success "Started ledgers relay streams from all fast relays"
    fi
}

# Stop a native strfry relay process.
# Usage: stop_relay <name>
stop_relay() {
    local name=$1
    local db_dir="$DATA_ROOT/relays/$name"
    local pidfile="$db_dir/relay.pid"

    # Kill stream processes first (ledgers relay)
    if [ -f "$db_dir/stream.pids" ]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$db_dir/stream.pids"
        rm -f "$db_dir/stream.pids"
    fi

    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            local attempts=0
            while kill -0 "$pid" 2>/dev/null && [ $attempts -lt 10 ]; do
                sleep 0.5
                attempts=$((attempts + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            log_info "Stopped relay $name (pid $pid)"
        fi
        rm -f "$pidfile"
    fi

    # Belt and suspenders
    pkill -f "strfry.*--config.*relays/$name" 2>/dev/null || true
}

# Start all relays (fast + ledgers)
start_all_relays() {
    for name in "${NODES[@]}"; do
        start_relay "$name"
    done
    # Start ledgers after fast relays are up
    start_relay ledgers
}

# Stop all relays
stop_all_relays() {
    stop_relay ledgers
    for name in "${NODES[@]}"; do
        stop_relay "$name"
    done
}

# ─── Topology-driven node infrastructure ─────────────────────────────────────
# NODE_COUNT can be set before sourcing _common.sh (default: 4).
# TOPOLOGY_FILE can point to a pre-generated topology JSON.
# If neither is set, init_topology generates a default 4-node topology.

export NODE_COUNT="${NODE_COUNT:-4}"
TOPOLOGY_FILE="${TOPOLOGY_FILE:-}"

# Internal arrays populated by init_topology()
NODES=()
declare -A _NODE_SEEDS 2>/dev/null || true
declare -A _NODE_INDICES 2>/dev/null || true

# Initialize topology: populate NODES, ALL_RELAYS, and lookup tables.
# Call this after setting NODE_COUNT or TOPOLOGY_FILE.
init_topology() {
    local topo_json
    if [ -n "$TOPOLOGY_FILE" ] && [ -f "$TOPOLOGY_FILE" ]; then
        topo_json=$(cat "$TOPOLOGY_FILE")
    else
        topo_json=$(python3 "$SCRIPT_DIR/generate-topology.py" --nodes "$NODE_COUNT" --ledgers-per-op "${LEDGERS_PER_OP:-3}")
    fi

    # Parse into bash arrays using python (robust, no jq dependency)
    eval "$(echo "$topo_json" | python3 -c "
import json, sys
t = json.load(sys.stdin)
names = []
for n in t['nodes']:
    names.append(n['name'])
    print(f'_NODE_SEEDS[{n[\"name\"]}]=\"{n[\"seed\"]}\"')
    print(f'_NODE_INDICES[{n[\"name\"]}]={n[\"index\"]}')
print('NODES=(' + ' '.join(names) + ')')
print('ALL_RELAYS=(' + ' '.join(f'\"ws://localhost:{n[\"relay_port\"]}\"' for n in t['nodes']) + ')')
")"

    # Legacy aliases for scripts that reference RELAY_ALICE etc.
    for node in "${NODES[@]}"; do
        local upper=$(echo "$node" | tr '[:lower:]' '[:upper:]')
        local port=$((7800 + ${_NODE_INDICES[$node]}))
        eval "RELAY_${upper}=\"ws://localhost:${port}\""
    done
}

# Get 1-based index for a node name
get_node_index() {
    local node=$1
    echo "${_NODE_INDICES[$node]:-}"
}

# Metrics port for a node
get_node_metrics_port() {
    local node=$1
    local idx=$(get_node_index "$node")
    echo $((9100 + ${idx:-0}))
}

# Get data directory for a node
get_node_data_dir() {
    local node=$1
    echo "$DATA_ROOT/$node"
}

# Get seed for a node
get_node_seed() {
    local node=$1
    echo "${_NODE_SEEDS[$node]:-}"
}

# Get display name for a node (capitalized)
get_node_name() {
    local node=$1
    echo "$node" | python3 -c "print(input().title())"
}

# Get external relay URL for a node (host-accessible port)
get_node_relay_url() {
    local node=$1
    local idx=$(get_node_index "$node")
    if [ -n "$idx" ]; then
        echo "ws://localhost:$((7800 + idx))"
    fi
}

# Electrs group for a node (1 instance per 2 nodes)
get_node_electrs_group() {
    local node=$1
    local idx=$(get_node_index "$node")
    echo $(( (idx + 1) / 2 ))
}

# Electrs host port for a node
get_node_electrs_port() {
    local node=$1
    echo $((3200 + $(get_node_electrs_group "$node")))
}

# Electrs URL for a node
get_node_electrs_url() {
    local node=$1
    echo "http://localhost:$(get_node_electrs_port "$node")"
}

# Start per-node Electrs container (shared per pair)
# Usage: start_node_electrs <node>
start_node_electrs() {
    local node=$1
    local group=$(get_node_electrs_group "$node")
    local host_port=$(get_node_electrs_port "$node")
    local container="electrs-g${group}"

    # Skip if already running
    if docker ps -q --filter "name=^${container}$" 2>/dev/null | grep -q .; then
        return 0
    fi
    # Remove stopped container with same name
    docker rm "$container" 2>/dev/null || true

    docker run -d \
        --name "$container" \
        --network "$ELECTRS_DOCKER_NETWORK" \
        --platform linux/amd64 \
        -p "${host_port}:3002" \
        "$ELECTRS_IMAGE" \
        -vvvv --timestamp --jsonrpc-import --cookie=user:pass \
        --network=regtest --daemon-rpc-addr=bitcoin:18443 \
        --http-addr=0.0.0.0:3002 >/dev/null

    log_success "Started $container (port $host_port)"
}

# Start Electrs instances for all nodes
start_all_electrs() {
    local started=()
    for node in "${NODES[@]}"; do
        local group=$(get_node_electrs_group "$node")
        # Only start once per group
        local already=false
        for g in "${started[@]:-}"; do
            [ "$g" = "$group" ] && already=true
        done
        if ! $already; then
            start_node_electrs "$node"
            started+=("$group")
        fi
    done
}

# Stop all per-node Electrs containers
stop_all_electrs() {
    for container in $(docker ps -a --filter "name=electrs-g" --format '{{.Names}}' 2>/dev/null); do
        docker stop "$container" 2>/dev/null || true
        docker rm "$container" 2>/dev/null || true
    done
}

# Wait for all per-node Electrs instances to be ready
wait_for_all_electrs() {
    log_info "Waiting for per-node Electrs instances..."
    local ports_checked=()
    for node in "${NODES[@]}"; do
        local port=$(get_node_electrs_port "$node")
        local already=false
        for p in "${ports_checked[@]:-}"; do
            [ "$p" = "$port" ] && already=true
        done
        if $already; then continue; fi
        ports_checked+=("$port")

        local attempt=0
        while ! curl -s "http://localhost:$port" >/dev/null 2>&1; do
            attempt=$((attempt + 1))
            if [ $attempt -ge 60 ]; then
                log_error "Electrs on port $port not ready after 60s"
                return 1
            fi
            sleep 2
        done
    done
    log_success "All Electrs instances ready"
}

# Initialize with defaults (callers can re-init after setting NODE_COUNT)
init_topology

# Get the wallet-derived deposit secret for a node's deposit on a target ledger
# Usage: get_deposit_secret <depositor_node> [<target_ledger_id>]
# If target_ledger_id is provided, looks up the key_index from deposits.json
# Otherwise uses index 0 (for backward compatibility)
get_deposit_secret() {
    local node=$1
    local target_ledger=${2:-}
    local seed=$(get_node_seed "$node")
    if [ -z "$seed" ]; then
        return 1
    fi

    local data_dir=$(get_node_data_dir "$node")
    local key_index=0
    if [ -n "$target_ledger" ]; then
        # Look up key_index from deposits.json for this ledger
        local idx_output
        idx_output=$(cat "$data_dir/wallet/deposits.json" 2>/dev/null | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
target = sys.argv[1] if len(sys.argv) > 1 else ''
found = 0
for d in data:
    lid = d.get('ledger_id', '')
    if target and (lid.startswith(target[:16]) or target.startswith(lid[:16])):
        found = d.get('key_index', 0)
        break
print(found)
" "${target_ledger}" 2>/dev/null)
        # Extract just the first line, strip whitespace
        key_index=$(echo "$idx_output" | head -1 | tr -d '[:space:]')
        key_index=${key_index:-0}
    fi

    # Use deposits-node to derive the key at the correct index
    RUST_LOG=error "$DEPOSITS_NODE" derive-deposit-key \
        --seed "$seed" \
        --network regtest \
        --index "$key_index" 2>&1 | grep "^[0-9a-f]\{64\}$" | head -1
}

# Filter out Rust tracing log lines from output
# Removes timestamp-prefixed log lines (preserves colors for tree visualization)
filter_logs() {
    grep -v -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}|^\x1b\[[0-9;]*m[0-9]{4}-[0-9]{2}-[0-9]{2}T'
}

# Print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Run bitcoin-cli command (bitcoind still runs in Docker)
bitcoin_cli() {
    docker exec bitcoind bitcoin-cli -regtest -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS "$@"
}

# Wait for bitcoin to be ready
wait_for_bitcoin() {
    log_info "Waiting for Bitcoin Core to be ready..."
    local max_attempts=30
    local attempt=0
    while ! bitcoin_cli getblockchaininfo >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            log_error "Bitcoin Core not ready after $max_attempts attempts"
            return 1
        fi
        sleep 1
    done
    log_success "Bitcoin Core is ready"
}

# Wait for electrs to be ready
wait_for_electrs() {
    log_info "Waiting for Electrs to be ready..."
    local max_attempts=60
    local attempt=0
    while ! curl -s "http://$ELECTRS_HOST:$ELECTRS_PORT" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            log_error "Electrs not ready after $max_attempts attempts"
            return 1
        fi
        sleep 2
    done
    log_success "Electrs is ready"
}

# Wait for nostr relay to be ready
wait_for_nostr() {
    log_info "Waiting for Nostr relays to be ready..."
    local max_attempts=30
    local ports=()
    for node in "${NODES[@]}"; do
        ports+=("$(get_relay_port "$node")")
    done
    ports+=("$RELAY_LEDGERS_PORT")  # ledgers relay
    for port in "${ports[@]}"; do
        local attempt=0
        while ! curl -s "http://localhost:$port" >/dev/null 2>&1; do
            attempt=$((attempt + 1))
            if [ $attempt -ge $max_attempts ]; then
                log_error "Nostr relay on port $port not ready after $max_attempts attempts"
                return 1
            fi
            sleep 1
        done
    done
    log_success "All Nostr relays are ready"
}

# Create faucet wallet and mine initial blocks
setup_faucet() {
    log_info "Setting up faucet wallet..."

    # Try to load existing wallet, or create if it doesn't exist
    if ! bitcoin_cli loadwallet "faucet" 2>/dev/null; then
        bitcoin_cli createwallet "faucet" 2>/dev/null || true
    fi

    # Mine initial blocks for maturity
    log_info "Mining 101 blocks for coinbase maturity..."
    bitcoin_cli -rpcwallet=faucet -generate 101 >/dev/null

    log_success "Faucet ready with $(bitcoin_cli -rpcwallet=faucet getbalance) BTC"
}

# Get a new address from faucet wallet
faucet_address() {
    bitcoin_cli -rpcwallet=faucet getnewaddress
}

# Send BTC from faucet to an address
send_btc() {
    local address=$1
    local amount=${2:-1}

    log_info "Sending $amount BTC to $address"
    local txid=$(bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" "$amount")
    log_success "Sent: $txid"
    echo "$txid"
}

# Mine blocks
mine_blocks() {
    local count=${1:-1}
    log_info "Mining $count block(s)..."
    bitcoin_cli -rpcwallet=faucet -generate "$count" >/dev/null
    log_success "Mined $count block(s)"
}

# Ensure deposits-node binary exists
ensure_deposits_node() {
    if [ ! -f "$DEPOSITS_NODE" ]; then
        log_info "Building deposits-node..."
        cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin deposits-node 2>&1 | tail -3
    fi
}

# Ensure deposits-wallet binary exists
ensure_deposits_wallet() {
    if [ ! -f "$DEPOSITS_WALLET" ]; then
        log_info "Building deposits-wallet..."
        cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin deposits-wallet 2>&1 | tail -3
    fi
}

# Run a deposits-node command on a node with correct args
run_node_cmd() {
    local node=$1
    shift
    local cmd=$1
    shift

    local seed=$(get_node_seed "$node")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $node"
        return 1
    fi

    local name=$(get_node_name "$node")
    local data_dir=$(get_node_data_dir "$node")

    # Build relay args dynamically
    local relay_args=()
    for r in "${ALL_RELAYS[@]}"; do
        relay_args+=(--relay "$r")
    done

    # Run command with positional args first, then config args at the end
    # Use RUST_LOG=error to suppress INFO logs from CLI output
    # Connect to all operator relays so CLI can reach any daemon's primary relay
    local esplora_url=$(get_node_electrs_url "$node")
    RUST_LOG=error "$DEPOSITS_NODE" "$cmd" \
        "$@" \
        --seed "$seed" \
        --name "$name" \
        --network regtest \
        --esplora "$esplora_url" \
        "${relay_args[@]}" \
        --slow-relay "$RELAY_LEDGERS" \
        --data-dir "$data_dir" 2>&1
}

# Get node address
get_node_address() {
    local node=$1
    local seed=$(get_node_seed "$node")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $node"
        return 1
    fi

    local data_dir=$(get_node_data_dir "$node")

    # Run address command and extract just the address
    local esplora_url=$(get_node_electrs_url "$node")
    local own_relay=$(get_node_relay_url "$node")
    RUST_LOG=error "$DEPOSITS_NODE" address \
        --seed "$seed" \
        --network regtest \
        --esplora "$esplora_url" \
        --relay "$own_relay" \
        --data-dir "$data_dir" 2>&1 | grep -E '^bcrt1' | head -1
}

# Get node info
get_node_info() {
    local node=$1
    run_node_cmd "$node" info
}

# Fund a node (sends BTC but does NOT mine — caller must mine to confirm)
fund_node() {
    local node=$1
    local amount=${2:-1}

    log_info "Funding $node with $amount BTC..."

    local address=$(get_node_address "$node")
    if [ -z "$address" ]; then
        log_error "Could not get address for $node"
        return 1
    fi

    send_btc "$address" "$amount"

    log_success "Funded $node"
}

# Fund multiple nodes in batch (parallel address lookup, single mine pass)
# Usage: fund_nodes_batch <amount> [node1 node2 ...]
# If no nodes specified, uses NODES array
fund_nodes_batch() {
    local amount=${1:-1}
    shift || true
    local nodes=("$@")
    if [ ${#nodes[@]} -eq 0 ]; then
        nodes=("${NODES[@]}")
    fi

    local count=${#nodes[@]}
    log_info "Funding $count node(s) with $amount BTC each..."

    # Get all addresses in parallel
    local tmpdir=$(mktemp -d)
    local pids=()

    for node in "${nodes[@]}"; do
        get_node_address "$node" > "$tmpdir/$node" &
        pids+=($!)
    done

    # Wait for all address lookups
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    # Send all transactions (fast RPC calls, no mining yet)
    local funded=0
    for node in "${nodes[@]}"; do
        local address=$(cat "$tmpdir/$node" 2>/dev/null)
        if [ -z "$address" ]; then
            log_warn "Could not get address for $node"
            continue
        fi
        send_btc "$address" "$amount"
        funded=$((funded + 1))
    done

    rm -rf "$tmpdir"

    # Single mine pass to confirm all transactions
    mine_blocks 1

    log_success "Funded $funded/$count node(s)"
}

# Get block height
get_block_height() {
    bitcoin_cli getblockcount
}

# Show all services status
show_status() {
    log_info "Infrastructure services:"
    $DC ps
    echo ""
    log_info "Relay processes:"
    for name in "${NODES[@]}" ledgers; do
        local pidfile="$DATA_ROOT/relays/$name/relay.pid"
        local port=$(get_relay_port "$name")
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            log_success "relay-$name running (pid $(cat "$pidfile"), port $port)"
        else
            log_warn "relay-$name not running"
        fi
    done
    echo ""
    log_info "Node processes:"
    for node in "${NODES[@]}"; do
        local pidfile="$DATA_ROOT/$node/node.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            log_success "$node running (pid $(cat "$pidfile"))"
        else
            log_warn "$node not running"
        fi
    done
}

# Show node logs
show_logs() {
    local node=${1:-""}
    if [ -z "$node" ]; then
        for n in "${NODES[@]}"; do
            local logfile="$DATA_ROOT/$n/node.log"
            if [ -f "$logfile" ]; then
                echo "=== $n ==="
                tail -50 "$logfile"
            fi
        done
    else
        local logfile="$DATA_ROOT/$node/node.log"
        if [ -f "$logfile" ]; then
            tail -50 "$logfile"
        else
            log_warn "No log file for $node"
        fi
    fi
}

# Follow node logs
follow_logs() {
    local node=${1:-""}
    if [ -z "$node" ]; then
        tail -f "$DATA_ROOT"/*/node.log
    else
        tail -f "$DATA_ROOT/$node/node.log"
    fi
}

# Generate a keypair using deposits-node keygen (no extra args needed)
# Returns: secret_hex pubkey_hex
run_keygen() {
    RUST_LOG=error "$DEPOSITS_NODE" keygen 2>&1
}

# Run a nostr request from one node to a ledger
# Usage: run_nostr_request <from_node> <ledger_id> <action> [params...]
# Returns the response JSON
run_nostr_request() {
    local node=$1
    shift
    local ledger_id=$1
    shift
    local action=$1
    shift

    local seed=$(get_node_seed "$node")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $node"
        return 1
    fi

    local data_dir=$(get_node_data_dir "$node")

    # Run nostr request command
    local esplora_url=$(get_node_electrs_url "$node")
    local own_relay=$(get_node_relay_url "$node")
    RUST_LOG=error "$DEPOSITS_NODE" nostr request \
        "$ledger_id" "$action" "$@" \
        --seed "$seed" \
        --network regtest \
        --esplora "$esplora_url" \
        --relay "$own_relay" \
        --data-dir "$data_dir" 2>&1
}

# Run a deposits-wallet command on a node
# Usage: run_wallet_cmd <node> <command> [args...]
# The node name determines the wallet seed/identity
run_wallet_cmd() {
    local node=$1
    shift

    local seed=$(get_node_seed "$node")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $node"
        return 1
    fi

    local data_dir=$(get_node_data_dir "$node")

    # Build relay args dynamically
    local relay_args=()
    for r in "${ALL_RELAYS[@]}"; do
        relay_args+=(--relay "$r")
    done

    # Run deposits-wallet with the node's seed
    # Connect to all operator relays so wallet can reach any operator's daemon
    RUST_LOG=error "$DEPOSITS_WALLET" "$@" \
        --seed "$seed" \
        --network regtest \
        "${relay_args[@]}" \
        --data-dir "$data_dir/wallet" 2>&1
}

# Send a bump request to trigger immediate wallet sync and deposit completion
# Usage: bump_operator <from_node> <ledger_id>
bump_operator() {
    local node=$1
    local ledger_id=$2
    run_nostr_request "$node" "$ledger_id" bump 2>&1
}

# Start a deposits-node daemon for a given node
# Usage: start_node <node>
start_node() {
    local node=$1
    local seed=$(get_node_seed "$node")
    local data_dir=$(get_node_data_dir "$node")
    local metrics_port=$(get_node_metrics_port "$node")

    mkdir -p "$data_dir"

    # Copy allowlist if it exists
    if [ -f "$TOOLS_DIR/config/deposit_allowlist.txt" ]; then
        cp "$TOOLS_DIR/config/deposit_allowlist.txt" "$data_dir/deposit_allowlist.txt"
    fi

    # Put this node's own relay first — the first relay is the "primary" (publish target).
    # Other relays are for subscriptions/reads only.
    local own_relay=$(get_node_relay_url "$node")
    local relay_args="--relay $own_relay"
    for r in "${ALL_RELAYS[@]}"; do
        [ "$r" != "$own_relay" ] && relay_args="$relay_args --relay $r"
    done

    # Lightning backend wiring. Default (or LIGHTNING_BACKEND=ldk) wires the
    # shared LDK self-pay node. `=lnd` extracts the macaroon from the lnd
    # container and points operators at its REST endpoint. `=cln` exposes
    # CLN's lightning-rpc Unix socket via the bind-mounted host path.
    case "${LIGHTNING_BACKEND:-ldk}" in
        ldk)
            # All operators share a single LDK node via self-pay wrapper.
            if [ -f "$TOOLS_DIR/certs/lightning.crt" ]; then
                local ldk_real_cli="${LDK_SERVER_CLI:-$HOME/ldk-server/target/release/ldk-server-cli}"
                if [ ! -x "$ldk_real_cli" ]; then
                    log_warn "ldk-server-cli not found at $ldk_real_cli"
                fi

                local ldk_api_key
                ldk_api_key=$(docker exec lightning sh -c "cat /ldk/\$(printenv NETWORK)/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null || echo "")

                export LDK_CLI="$TOOLS_DIR/bin/ldk-cli-wrapper.sh"
                export LDK_REAL_CLI="$ldk_real_cli"
                export LDK_HOST="localhost"
                export LDK_PORT="3111"
                [ -n "$ldk_api_key" ] && export LDK_API_KEY="$ldk_api_key"
                export LDK_TLS_CERT="$TOOLS_DIR/certs/lightning.crt"
                export LDK_SELF_PAY_DIR="$DATA_ROOT/self-pay"
                mkdir -p "$DATA_ROOT/self-pay"
            fi
            ;;
        lnd)
            # Shared LND container — extract macaroon + cert each start, in
            # case the container was recreated.
            mkdir -p "$TOOLS_DIR/certs"
            local lnd_macaroon_path="/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"
            export LND_MACAROON_HEX=$(docker exec lnd xxd -p -c 0 "$lnd_macaroon_path" 2>/dev/null | tr -d '\n')
            docker cp lnd:/root/.lnd/tls.cert "$TOOLS_DIR/certs/lnd.cert" 2>/dev/null \
                || log_warn "Failed to extract LND TLS cert (is the lnd container running?)"
            export LND_REST_URL="https://localhost:8081"
            export LND_TLS_CERT_FILE="$TOOLS_DIR/certs/lnd.cert"
            export LIGHTNING_BACKEND=lnd
            ;;
        cln)
            # CLN's lightning-rpc socket is bind-mounted to ./data/cln on the host.
            export CLN_SOCKET_PATH="$TOOLS_DIR/data/cln/regtest/lightning-rpc"
            export LIGHTNING_BACKEND=cln
            ;;
        *)
            log_warn "Unknown LIGHTNING_BACKEND=$LIGHTNING_BACKEND; falling back to default"
            ;;
    esac

    # Chain backend wiring. Default `esplora` keeps existing behaviour
    # (operators talk to electrs at port 3102). `bitcoind` points at the
    # regtest bitcoind container's RPC; `electrum` points at electrs's
    # electrum-protocol port. Parallel to the LIGHTNING_BACKEND case above.
    case "${CHAIN_BACKEND:-esplora}" in
        esplora)
            : # operators already get --esplora from elsewhere; nothing extra
            ;;
        bitcoind)
            export BITCOIND_RPC_URL="http://127.0.0.1:18543"
            export BITCOIND_RPC_USER="user"
            export BITCOIND_RPC_PASS="pass"
            export CHAIN_BACKEND=bitcoind
            ;;
        electrum)
            export ELECTRUM_HOST="127.0.0.1"
            export ELECTRUM_PORT="50101"
            export CHAIN_BACKEND=electrum
            ;;
        *)
            log_warn "Unknown CHAIN_BACKEND=$CHAIN_BACKEND; falling back to default"
            ;;
    esac

    local esplora_url=$(get_node_electrs_url "$node")

    # Optionally provision a per-operator deposits-signer.
    # Triggered by DEPOSITS_USE_SIGNER=1 in the environment. When set, we
    # spawn a signer process co-located with the daemon (separate process,
    # same host) and pass --signer-pubkey/--signer-socket to the daemon.
    # Deliberately co-located rather than separate-host: this exercises
    # the full wire protocol end-to-end while keeping the test setup
    # tractable. The point of the env-gate is opt-in coverage; existing
    # tests stay on the simpler LocalSigner path by default.
    local signer_flags=""
    if [ "${DEPOSITS_USE_SIGNER:-}" = "1" ]; then
        local signer_data_dir="$data_dir/signer"
        local signer_socket="$data_dir/signer.sock"

        # 1. Init signer with the same seed as the daemon's wallet.
        #    Idempotent — `init` refuses if the dir is already initialized,
        #    which is the recovery / re-deploy case we want.
        if [ ! -f "$signer_data_dir/transport_secret" ]; then
            local seed_file="$data_dir/_signer_seed.tmp"
            echo "$seed" > "$seed_file"
            chmod 0600 "$seed_file"
            "$DEPOSITS_SIGNER" init \
                --data-dir "$signer_data_dir" \
                --seed-file "$seed_file" >/dev/null
            rm -f "$seed_file"
        fi

        # 2. Pre-generate the daemon's transport pubkey via the
        #    transport-pubkey subcommand so we can allowlist it before
        #    either process talks to a socket.
        local node_transport_pubkey
        node_transport_pubkey=$("$DEPOSITS_NODE" transport-pubkey --data-dir "$data_dir" 2>/dev/null)

        # 3. Allowlist the daemon on the signer (idempotent).
        "$DEPOSITS_SIGNER" trust add \
            --data-dir "$signer_data_dir" \
            "$node_transport_pubkey" >/dev/null 2>&1 || true

        # 4. Capture the signer's pubkey for daemon CLI.
        local signer_pubkey
        signer_pubkey=$("$DEPOSITS_SIGNER" pubkey --data-dir "$signer_data_dir")

        # 5. Spawn the signer in the background.
        rm -f "$signer_socket"
        RUST_LOG=info \
        "$DEPOSITS_SIGNER" run \
            --data-dir "$signer_data_dir" \
            --socket "$signer_socket" \
            > "$data_dir/signer.log" 2>&1 &
        local signer_pid=$!
        echo "$signer_pid" > "$data_dir/signer.pid"

        # 6. Wait for the socket to come up. ~3s ceiling — first-launch
        #    rust binary loads + starts listening fast on warm caches.
        local waited=0
        while [ ! -S "$signer_socket" ] && [ $waited -lt 30 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        if [ ! -S "$signer_socket" ]; then
            log_warn "$node: deposits-signer socket never appeared at $signer_socket"
        fi

        signer_flags="--signer-pubkey $signer_pubkey --signer-socket $signer_socket"
        log_info "$node: signer spawned (pid $signer_pid, socket $signer_socket, pubkey ${signer_pubkey:0:16}...)"
    fi

    RUST_LOG=info,nostr_relay_pool=warn,nostr_sdk=warn \
    DEPOSITS_ENABLE_METRICS_EMITTER=1 \
    "$DEPOSITS_NODE" run \
        --seed "$seed" \
        --network regtest \
        --electrum "$esplora_url" \
        $relay_args \
        --slow-relay "$RELAY_LEDGERS" \
        --data-dir "$data_dir" \
        --metrics-port "$metrics_port" \
        --fast-poll \
        --skip-nostr-verify \
        $signer_flags \
        > "$data_dir/node.log" 2>&1 &

    local pid=$!
    echo "$pid" > "$data_dir/node.pid"
    log_success "Started $node (pid $pid, metrics :$metrics_port, data $data_dir)"
}

# Stop a node daemon
# Usage: stop_node <node>
stop_node() {
    local node=$1
    local data_dir=$(get_node_data_dir "$node")

    # Stop nostr watch processes for this node first
    stop_nostr_watch "$node"

    local pidfile="$DATA_ROOT/$node/node.pid"
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            # Wait for graceful shutdown
            local attempts=0
            while kill -0 "$pid" 2>/dev/null && [ $attempts -lt 10 ]; do
                sleep 0.5
                attempts=$((attempts + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            log_info "Stopped $node (pid $pid)"
        fi
        rm -f "$pidfile"
    fi

    # Belt and suspenders: kill any remaining deposits-node processes for this node
    pkill -f "deposits-node.*--data-dir $data_dir" 2>/dev/null || true

    # If a co-located signer was spawned (DEPOSITS_USE_SIGNER=1), kill it too.
    local signer_pidfile="$data_dir/signer.pid"
    if [ -f "$signer_pidfile" ]; then
        local signer_pid=$(cat "$signer_pidfile")
        if kill -0 "$signer_pid" 2>/dev/null; then
            kill "$signer_pid" 2>/dev/null || true
            local attempts=0
            while kill -0 "$signer_pid" 2>/dev/null && [ $attempts -lt 10 ]; do
                sleep 0.5
                attempts=$((attempts + 1))
            done
            if kill -0 "$signer_pid" 2>/dev/null; then
                kill -9 "$signer_pid" 2>/dev/null || true
            fi
            log_info "Stopped $node deposits-signer (pid $signer_pid)"
        fi
        rm -f "$signer_pidfile"
    fi
    pkill -f "deposits-signer.*--data-dir $data_dir/signer" 2>/dev/null || true
    rm -f "$data_dir/signer.sock"
}

# Start all node daemons
start_all_nodes() {
    for node in "${NODES[@]}"; do
        start_node "$node"
    done
}

# Stop all node daemons
stop_all_nodes() {
    for node in "${NODES[@]}"; do
        stop_node "$node"
    done
}

# Start nostr watch on a node in the background
# Usage: start_nostr_watch <node> <ledger_id>
start_nostr_watch() {
    local node=$1
    local ledger_id=$2

    local seed=$(get_node_seed "$node")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $node"
        return 1
    fi

    local data_dir=$(get_node_data_dir "$node")

    # Start watch in background — use node's own relay as primary
    local own_relay=$(get_node_relay_url "$node")
    local esplora_url=$(get_node_electrs_url "$node")
    RUST_LOG=error "$DEPOSITS_NODE" nostr watch \
        "$ledger_id" \
        --seed "$seed" \
        --network regtest \
        --esplora "$esplora_url" \
        --relay "$own_relay" \
        --data-dir "$data_dir" &

    log_info "Started nostr watch on $node for $ledger_id"
}

# Stop all nostr watch processes for a node
stop_nostr_watch() {
    local node=$1
    local data_dir=$(get_node_data_dir "$node")
    # Kill any deposits-node processes that have "nostr watch" and this node's data dir
    pkill -9 -f "deposits-node nostr watch.*--data-dir $data_dir" 2>/dev/null || true
    sleep 0.5
}

# Check if all services are healthy
check_health() {
    local unhealthy=0

    # Check bitcoin
    if ! bitcoin_cli getblockchaininfo >/dev/null 2>&1; then
        log_error "Bitcoin Core unhealthy"
        unhealthy=1
    else
        log_success "Bitcoin Core healthy"
    fi

    # Check per-node electrs
    local electrs_ok=0
    local electrs_total=0
    for node in "${NODES[@]}"; do
        local port=$(get_node_electrs_port "$node")
        # Deduplicate (pairs share a port)
        if curl -s "http://localhost:$port" >/dev/null 2>&1; then
            electrs_ok=$((electrs_ok + 1))
        fi
        electrs_total=$((electrs_total + 1))
    done
    if [ "$electrs_ok" -ge "$electrs_total" ]; then
        log_success "Electrs healthy ($electrs_ok instances reachable)"
    else
        log_error "Electrs: only $electrs_ok/$electrs_total nodes can reach their Electrs"
        unhealthy=1
    fi

    # Check nostr relay
    if ! curl -s "http://localhost:7801" >/dev/null 2>&1; then
        log_error "Nostr relay unhealthy"
        unhealthy=1
    else
        log_success "Nostr relay healthy"
    fi

    # Check node processes
    for node in "${NODES[@]}"; do
        local pidfile="$DATA_ROOT/$node/node.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            log_success "$node running (pid $(cat "$pidfile"))"
        else
            log_warn "$node not running"
        fi
    done

    return $unhealthy
}

# Wait for a marker file to appear in any of the specified node data dirs.
# Usage: wait_for_marker <glob_pattern> <timeout_secs> <node1> [node2 ...]
# Prints the name of the node where the marker was found.
# Returns 0 on success, 1 on timeout.
wait_for_marker() {
    local pattern=$1
    local timeout=$2
    shift 2
    local nodes=("$@")

    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        for node in "${nodes[@]}"; do
            local data_dir=$(get_node_data_dir "$node")
            local found=$(ls "$data_dir"/${pattern} 2>/dev/null | head -1)
            if [ -n "$found" ]; then
                echo "$node"
                return 0
            fi
        done
        sleep 5
        elapsed=$((elapsed + 5))
    done
    return 1
}

# Backward compatibility alias
wait_for_docker_marker() {
    wait_for_marker "$@"
}
