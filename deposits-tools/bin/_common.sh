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
BDK_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$(dirname "$BDK_DIR")"
REPO_ROOT="$(dirname "$TOOLS_DIR")"

# Docker compose command
DC="docker compose -f $BDK_DIR/docker-compose.yml"

# Bitcoin RPC settings (matching docker-compose)
BITCOIN_RPC_HOST="localhost"
BITCOIN_RPC_PORT="18543"
BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASS="pass"

# Electrs settings
ELECTRS_HOST="localhost"
ELECTRS_PORT="3102"

# Node containers
NODES=("alice" "bob" "charlie" "diana")

# Get seed for a node (compatible with bash 3.x)
get_node_seed() {
    local node=$1
    case "$node" in
        "alice")     echo "416c696365000000000000000000000000000000000000000000000000000001" ;;
        "bob")       echo "426f620000000000000000000000000000000000000000000000000000000002" ;;
        "charlie")   echo "436861726c696500000000000000000000000000000000000000000000000003" ;;
        "diana")     echo "4469616e61000000000000000000000000000000000000000000000000000004" ;;
        "eve")       echo "4576650000000000000000000000000000000000000000000000000000000005" ;;
        *) echo "" ;;
    esac
}

# Get operator name for a node
get_node_name() {
    local node=$1
    case "$node" in
        "alice")     echo "Alice" ;;
        "bob")       echo "Bob" ;;
        "charlie")   echo "Charlie" ;;
        "diana")     echo "Diana" ;;
        "eve")       echo "Eve" ;;
        *) echo "" ;;
    esac
}

# Get external relay URL for a node (host-accessible port)
get_node_relay_url() {
    local node=$1
    case "$node" in
        "alice")     echo "ws://localhost:7801" ;;
        "bob")       echo "ws://localhost:7802" ;;
        "charlie")   echo "ws://localhost:7803" ;;
        "diana")     echo "ws://localhost:7804" ;;
        *) echo "" ;;
    esac
}

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

    local key_index=0
    if [ -n "$target_ledger" ]; then
        # Look up key_index from deposits.json for this ledger
        # The python script outputs just the index number, nothing else
        local idx_output
        idx_output=$(docker exec "$node" sh -c "cat /data/wallet/deposits.json 2>/dev/null" | \
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
    docker exec -e RUST_LOG=error "$node" deposits-node derive-deposit-key \
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

# Run bitcoin-cli command
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
    log_info "Waiting for Nostr relay to be ready..."
    local max_attempts=30
    local attempt=0
    while ! curl -s "http://localhost:7801" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            log_error "Nostr relay not ready after $max_attempts attempts"
            return 1
        fi
        sleep 1
    done
    log_success "Nostr relay is ready"
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

# Run a deposits-node command on a node with correct args
run_bdk_cmd() {
    local container=$1
    shift
    local cmd=$1
    shift

    local seed=$(get_node_seed "$container")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $container"
        return 1
    fi

    local name=$(get_node_name "$container")

    # Run command with positional args first, then config args at the end
    # This supports subcommands like: ledger open <block> --seed ...
    # Use RUST_LOG=error to suppress INFO logs from CLI output
    # Connect to all operator relays so CLI can reach any daemon's primary relay
    docker exec -e RUST_LOG=error "$container" deposits-node "$cmd" \
        "$@" \
        --seed "$seed" \
        --name "$name" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://relay-alice:7777 \
        --relay ws://relay-bob:7777 \
        --relay ws://relay-charlie:7777 \
        --relay ws://relay-diana:7777 \
        --data-dir /data 2>&1
}

# Get node address
get_node_address() {
    local container=$1
    local seed=$(get_node_seed "$container")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $container"
        return 1
    fi

    # Run address command and extract just the address
    docker exec -e RUST_LOG=error "$container" deposits-node address \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://relay-alice:7777 \
        --data-dir /data 2>&1 | grep -E '^bcrt1' | head -1
}

# Get node info
get_node_info() {
    local container=$1
    run_bdk_cmd "$container" info
}

# Create reserves UTXO on a node
create_node_reserves() {
    local container=$1
    local amount_sats=${2:-100000000}  # Default 1 BTC

    log_info "Creating reserves on $container: $amount_sats sats..."

    local output=$(run_bdk_cmd "$container" reserves "$amount_sats")

    if echo "$output" | grep -q "Reserves created"; then
        local txid=$(echo "$output" | grep "TXID:" | awk '{print $2}')
        log_success "$container reserves created: $txid"
        echo "$txid"
        return 0
    else
        log_error "$container reserves failed: $output"
        return 1
    fi
}

# Fund a node (sends BTC but does NOT mine — caller must mine to confirm)
fund_node() {
    local container=$1
    local amount=${2:-1}

    log_info "Funding $container with $amount BTC..."

    local address=$(get_node_address "$container")
    if [ -z "$address" ]; then
        log_error "Could not get address for $container"
        return 1
    fi

    send_btc "$address" "$amount"

    log_success "Funded $container"
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
    log_info "Service status:"
    $DC ps
}

# Show node logs
show_logs() {
    local container=${1:-""}
    if [ -z "$container" ]; then
        $DC logs --tail=50
    else
        $DC logs --tail=50 "$container"
    fi
}

# Follow node logs
follow_logs() {
    local container=${1:-""}
    if [ -z "$container" ]; then
        $DC logs -f
    else
        $DC logs -f "$container"
    fi
}

# Generate a keypair using deposits-node keygen (no extra args needed)
# Returns: secret_hex pubkey_hex
run_keygen() {
    local container=$1
    # keygen doesn't need seed/network/etc - it just generates a random keypair
    docker exec -e RUST_LOG=error "$container" deposits-node keygen 2>&1
}

# Run a nostr request from one node to a ledger
# Usage: run_nostr_request <from_container> <ledger_id> <action> [params...]
# Returns the response JSON
run_nostr_request() {
    local container=$1
    shift
    local ledger_id=$1
    shift
    local action=$1
    shift

    local seed=$(get_node_seed "$container")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $container"
        return 1
    fi

    # Run nostr request command
    docker exec -e RUST_LOG=error "$container" deposits-node nostr request \
        "$ledger_id" "$action" "$@" \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://relay-alice:7777 \
        --data-dir /data 2>&1
}

# Run a deposits-wallet command on a node
# Usage: run_wallet_cmd <container> <command> [args...]
# The container name determines the wallet seed/identity
run_wallet_cmd() {
    local container=$1
    shift

    local seed=$(get_node_seed "$container")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $container"
        return 1
    fi

    # Run deposits-wallet with the node's seed
    # Connect to all operator relays so wallet can reach any operator's daemon
    docker exec -e RUST_LOG=error "$container" deposits-wallet "$@" \
        --seed "$seed" \
        --network regtest \
        --relay ws://relay-alice:7777 \
        --relay ws://relay-bob:7777 \
        --relay ws://relay-charlie:7777 \
        --relay ws://relay-diana:7777 \
        --data-dir /data/wallet 2>&1
}

# Send a bump request to trigger immediate wallet sync and deposit completion
# Usage: bump_operator <from_container> <ledger_id>
bump_operator() {
    local container=$1
    local ledger_id=$2
    run_nostr_request "$container" "$ledger_id" bump 2>&1
}

# Start nostr watch on a node in the background
# Usage: start_nostr_watch <container> <ledger_id>
# Returns the background process name for later cleanup
start_nostr_watch() {
    local container=$1
    local ledger_id=$2

    local seed=$(get_node_seed "$container")
    if [ -z "$seed" ]; then
        log_error "Unknown node: $container"
        return 1
    fi

    # Start watch in background inside the container
    docker exec -d -e RUST_LOG=error "$container" deposits-node nostr watch \
        "$ledger_id" \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://relay-alice:7777 \
        --data-dir /data

    log_info "Started nostr watch on $container for $ledger_id"
}

# Stop all nostr watch processes on a node
stop_nostr_watch() {
    local container=$1
    # pkill may not be available, so use kill with grep from /proc
    # Use SIGKILL (-9) to ensure processes die
    docker exec "$container" sh -c '
        for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do
            if [ -f /proc/$pid/cmdline ] && grep -q "nostr watch" /proc/$pid/cmdline 2>/dev/null; then
                kill -9 $pid 2>/dev/null || true
            fi
        done
    ' 2>/dev/null || true
    # Give processes time to die
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

    # Check electrs
    if ! curl -s "http://$ELECTRS_HOST:$ELECTRS_PORT" >/dev/null 2>&1; then
        log_error "Electrs unhealthy"
        unhealthy=1
    else
        log_success "Electrs healthy"
    fi

    # Check nostr relay
    if ! curl -s "http://localhost:7801" >/dev/null 2>&1; then
        log_error "Nostr relay unhealthy"
        unhealthy=1
    else
        log_success "Nostr relay healthy"
    fi

    # Check nodes are running
    for node in "${NODES[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
            log_success "$node running"
        else
            log_warn "$node not running"
        fi
    done

    return $unhealthy
}

# Wait for a marker file to appear inside any of the specified Docker containers.
# Usage: wait_for_docker_marker <glob_pattern> <timeout_secs> <node1> [node2 ...]
# Prints the name of the node where the marker was found.
# Returns 0 on success, 1 on timeout.
wait_for_docker_marker() {
    local pattern=$1
    local timeout=$2
    shift 2
    local nodes=("$@")

    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        for node in "${nodes[@]}"; do
            local found=$(docker exec "$node" sh -c "ls /data/${pattern} 2>/dev/null | head -1" 2>/dev/null)
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
