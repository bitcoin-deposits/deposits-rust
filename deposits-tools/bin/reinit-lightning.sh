#!/bin/bash
# Reinitialize the BDK test network with Lightning sidecars
#
# This script:
# 1. Stops and removes all containers and volumes
# 2. Rebuilds both deposits-node and ldk-node images
# 3. Starts all services including LDK nodes
# 4. Sets up the faucet wallet
# 5. Funds both BDK and LDK nodes
# 6. Opens a Lightning channel between Alice and Bob
#
# Usage:
#   ./bin/reinit-lightning.sh           # Full reinit
#   ./bin/reinit-lightning.sh --quick   # Skip rebuild, just restart

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Lightning-specific docker compose command
DC_LIGHTNING="docker compose -f $BDK_DIR/docker-compose.yml -f $BDK_DIR/docker-compose.lightning.yml"

# Parse arguments
QUICK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick|-q)
            QUICK=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick, -q   Skip rebuild, just restart containers"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info "=== Reinitializing BDK + Lightning Test Network ==="

# Stop any eve containers from setup-scale.sh (not managed by compose)
log_info "Cleaning up eve containers..."
for c in $(docker ps -aq --filter 'name=eve'); do
    docker stop "$c" 2>/dev/null || true
    docker rm "$c" 2>/dev/null || true
done
# Remove eve volumes
for v in $(docker volume ls -q --filter 'name=bdk_eve'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Stop BDK and LDK containers explicitly (may not be managed by compose if started by setup-scale)
log_info "Cleaning up BDK and LDK containers..."
for node in alice bob charlie diana; do
    docker stop "${node}" 2>/dev/null || true
    docker rm "${node}" 2>/dev/null || true
    docker stop "${node}-ln" 2>/dev/null || true
    docker rm "${node}-ln" 2>/dev/null || true
done
# Remove LDK volumes
for v in $(docker volume ls -q --filter 'name=ldk_'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Stop everything
log_info "Stopping all containers..."
$DC_LIGHTNING down -v --remove-orphans 2>/dev/null || true

# Clear wallet data (deposits become invalid after reinit)
WALLET_DATA_DIR="${WALLET_DATA_DIR:-$HOME/.deposits-wallet}"
if [ -d "$WALLET_DATA_DIR" ]; then
    log_info "Clearing wallet data ($WALLET_DATA_DIR)..."
    rm -rf "$WALLET_DATA_DIR"
fi

# Remove any dangling images
docker image prune -f 2>/dev/null || true

if ! $QUICK; then
    # Build local wallet binary for ./bin/wallet.sh
    log_info "Building local deposits-wallet binary..."
    cargo build --release --manifest-path "$BDK_DIR/../../Cargo.toml" -p deposits-node --bin deposits-wallet 2>&1 | tail -3

    # Rebuild deposits-node image
    log_info "Building deposits-node image..."
    $DC_LIGHTNING build --no-cache alice

    # Rebuild ldk-node image (build context is ~/workspace/ for access to ldk-server, ldk-node, rust-lightning)
    log_info "Building ldk-node image..."
    docker build -f "$BDK_DIR/Dockerfile.ldk-node" -t ldk-node:latest "$HOME/workspace/"
fi

# Start infrastructure services first
log_info "Starting infrastructure (bitcoin, electrs, relays)..."
$DC_LIGHTNING up -d bitcoin electrs relay-alice relay-bob relay-charlie relay-diana relay-ledgers

wait_for_bitcoin
wait_for_electrs
wait_for_nostr

# Start BDK nodes
log_info "Starting BDK nodes..."
$DC_LIGHTNING up -d alice bob charlie diana

# Start LDK nodes
log_info "Starting LDK nodes..."
$DC_LIGHTNING up -d alice-ln bob-ln charlie-ln diana-ln

# Start monitoring stack
log_info "Starting monitoring (Prometheus + Grafana)..."
$DC_LIGHTNING up -d prometheus grafana

# Wait for LDK nodes to start and generate TLS certs
log_info "Waiting for LDK nodes to initialize..."
sleep 10

# Copy TLS certs for ldk-cli (needed before we can use CLI)
log_info "Copying TLS certificates..."
rm -rf "$BDK_DIR/certs"
mkdir -p "$BDK_DIR/certs"
for node in alice bob charlie diana; do
    for attempt in 1 2 3 4 5; do
        if docker cp "${node}-ln:/ldk/tls.crt" "$BDK_DIR/certs/${node}.crt" 2>/dev/null; then
            log_success "Copied TLS cert for $node"
            break
        fi
        sleep 2
    done
done

# Setup faucet
setup_faucet

# Fund BDK nodes (parallel address lookup, batch send)
fund_nodes_batch 10

# Fund LDK nodes - they need on-chain funds for channel opening
log_info "Funding LDK nodes..."

# Helper to call ldk-cli
ldk_cli() {
    "$SCRIPT_DIR/ldk-cli.sh" "$@"
}

fund_ldk_node() {
    local node=$1
    local amount=${2:-1}

    # Get address from LDK node using CLI
    local address
    for i in 1 2 3 4 5; do
        local result=$(ldk_cli "$node" onchain-receive 2>/dev/null || echo "")
        address=$(echo "$result" | jq -r '.address // empty' 2>/dev/null || echo "")
        if [ -n "$address" ]; then
            break
        fi
        sleep 2
    done

    if [ -z "$address" ]; then
        log_warn "Could not get address for $node-ln"
        return 1
    fi

    log_info "Funding $node-ln at ${address:0:20}... with $amount BTC..."
    send_btc "$address" "$amount"
}

fund_ldk_node "alice" 2
fund_ldk_node "bob" 2
fund_ldk_node "charlie" 2
fund_ldk_node "diana" 2

# Mine blocks
mine_blocks 6

# Wait for LDK on-chain wallets to sync
wait_for_ldk_balance() {
    local node=$1
    local min_sats=${2:-100000000}  # Default 1 BTC
    log_info "Waiting for $node-ln on-chain wallet to sync..."
    # With LDK_ONCHAIN_WALLET_SYNC_INTERVAL_SECS=10, wait up to 30 seconds
    for i in $(seq 1 15); do
        local balance=$(ldk_cli "$node" get-balances 2>/dev/null | jq -r '.spendable_onchain_balance_sats // 0' 2>/dev/null || echo "0")
        if [ "$balance" -ge "$min_sats" ]; then
            log_success "$node-ln balance: $balance sats"
            return 0
        fi
        sleep 2
    done
    log_warn "$node-ln wallet sync timeout (balance: $balance sats)"
    return 1
}

wait_for_ldk_balance "alice"
wait_for_ldk_balance "bob"
wait_for_ldk_balance "charlie"
wait_for_ldk_balance "diana"

# Open channels in a ring: Alice <-> Bob <-> Charlie <-> Diana <-> Alice
log_info "Opening Lightning channels (ring topology)..."

CHANNEL_AMOUNT=5000000  # 5M sats

open_channel() {
    local from=$1
    local to=$2
    local to_port=$3

    local to_pubkey=$(ldk_cli "$to" get-node-info 2>/dev/null | jq -r '.node_id // empty' || echo "")
    if [ -z "$to_pubkey" ]; then
        log_warn "Could not get $to's pubkey, skipping channel"
        return 1
    fi

    # Check if channel already exists
    local existing=$(ldk_cli "$from" list-channels 2>/dev/null | jq -r ".channels[] | select(.counterparty_node_id == \"$to_pubkey\") | .channel_id" 2>/dev/null || echo "")
    if [ -n "$existing" ]; then
        log_info "Channel $from -> $to already exists"
        return 0
    fi

    log_info "Opening channel: $from -> $to..."
    local push_msat=$((CHANNEL_AMOUNT * 500))
    local result=$(ldk_cli "$from" open-channel \
        --node-pubkey "$to_pubkey" \
        --address "${to}-ln:${to_port}" \
        --channel-amount-sats "$CHANNEL_AMOUNT" \
        --push-to-counterparty-msat "$push_msat" \
        --announce-channel 2>&1) || true

    local user_channel_id=$(echo "$result" | jq -r '.user_channel_id // empty' 2>/dev/null || echo "")
    if [ -n "$user_channel_id" ]; then
        log_success "Channel $from -> $to opening: ${user_channel_id:0:16}..."
        return 0
    else
        log_warn "Channel $from -> $to failed: $result"
        return 1
    fi
}

# Open ring: Alice -> Bob -> Charlie -> Diana -> Alice
open_channel "alice" "bob" "9736"
open_channel "bob" "charlie" "9737"
open_channel "charlie" "diana" "9738"
open_channel "diana" "alice" "9735"

# Mine blocks to confirm all channels
mine_blocks 6

# Wait for channels to be ready
log_info "Waiting for channels to be ready..."
sleep 10

log_success "=== BDK + Lightning Test Network Ready ==="

echo ""
log_info "Service status:"
$DC_LIGHTNING ps

echo ""
log_info "Block height: $(get_block_height)"

echo ""
log_info "Useful commands:"
echo "  Follow logs:    $DC_LIGHTNING logs -f"
echo "  Alice logs:     $DC_LIGHTNING logs -f alice"
echo "  Mine blocks:    docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 1"

echo ""
log_info "Services:"
echo "  Nostr relay:    ws://localhost:7801"
echo "  Electrs:        http://localhost:3102"
echo "  Prometheus:     http://localhost:9090"
echo "  Grafana:        http://localhost:3010 (admin/admin)"

echo ""
log_info "LDK Lightning nodes:"
echo "  alice-ln:   API at https://localhost:3111"
echo "  bob-ln:     API at https://localhost:3112"
echo "  charlie-ln: API at https://localhost:3113"
echo "  diana-ln:   API at https://localhost:3114"
echo ""
echo "Channel topology: Alice <-> Bob <-> Charlie <-> Diana <-> Alice (ring)"

echo ""
log_info "Next steps:"
echo "  1. Run payment simulator: ./bin/payment-simulator.py --lightning --network regtest"
echo "  2. Run full test: ./bin/test-lightning.sh"
