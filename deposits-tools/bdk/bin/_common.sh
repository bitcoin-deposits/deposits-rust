#!/bin/bash
# Common functions for BDK test scripts
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
NODES=("bdk-alice" "bdk-bob" "bdk-charlie")

# Get seed for a node (compatible with bash 3.x)
get_node_seed() {
    local node=$1
    case "$node" in
        "bdk-alice")   echo "416c696365000000000000000000000000000000000000000000000000000001" ;;
        "bdk-bob")     echo "426f620000000000000000000000000000000000000000000000000000000002" ;;
        "bdk-charlie") echo "436861726c696500000000000000000000000000000000000000000000000003" ;;
        "bdk-diana")   echo "4469616e61000000000000000000000000000000000000000000000000000004" ;;
        "bdk-eve")     echo "4576650000000000000000000000000000000000000000000000000000000005" ;;
        *) echo "" ;;
    esac
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
    docker exec bdk-bitcoind bitcoin-cli -regtest -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS "$@"
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
    while ! curl -s "http://localhost:7778" >/dev/null 2>&1; do
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

    # Create wallet if it doesn't exist
    bitcoin_cli createwallet "faucet" 2>/dev/null || true

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

# Run a deposits-bdk command on a node with correct args
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

    # Run command with positional args first, then config args at the end
    # This supports subcommands like: ledger open <block> --seed ...
    # Use RUST_LOG=error to suppress INFO logs from CLI output
    docker exec -e RUST_LOG=error "$container" deposits-bdk "$cmd" \
        "$@" \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
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
    docker exec -e RUST_LOG=error "$container" deposits-bdk address \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
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

# Fund a BDK node
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
    mine_blocks 1

    log_success "Funded $container"
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

# Generate a keypair using deposits-bdk keygen (no extra args needed)
# Returns: secret_hex pubkey_hex
run_keygen() {
    local container=$1
    # keygen doesn't need seed/network/etc - it just generates a random keypair
    docker exec -e RUST_LOG=error "$container" deposits-bdk keygen 2>&1
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
    docker exec -e RUST_LOG=error "$container" deposits-bdk nostr request \
        "$ledger_id" "$action" "$@" \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data 2>&1
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
    docker exec -d -e RUST_LOG=error "$container" deposits-bdk nostr watch \
        "$ledger_id" \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data

    log_info "Started nostr watch on $container for $ledger_id"
}

# Stop all nostr watch processes on a node
stop_nostr_watch() {
    local container=$1
    docker exec "$container" pkill -f "nostr watch" 2>/dev/null || true
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
    if ! curl -s "http://localhost:7778" >/dev/null 2>&1; then
        log_error "Nostr relay unhealthy"
        unhealthy=1
    else
        log_success "Nostr relay healthy"
    fi

    # Check BDK nodes are running
    for node in "${NODES[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
            log_success "$node running"
        else
            log_warn "$node not running"
        fi
    done

    return $unhealthy
}
