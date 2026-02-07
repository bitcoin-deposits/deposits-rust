#!/bin/bash
# Reinitialize the BDK test network with Lightning sidecars
#
# This script:
# 1. Stops and removes all containers and volumes
# 2. Rebuilds both deposits-bdk and ldk-node images
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
    # Rebuild deposits-bdk image
    log_info "Building deposits-bdk image..."
    $DC_LIGHTNING build --no-cache bdk-alice

    # Rebuild ldk-node image
    log_info "Building ldk-node image..."
    $DC_LIGHTNING build --no-cache bdk-alice-ln
fi

# Start infrastructure services first
log_info "Starting infrastructure (bitcoin, electrs, nostr-relay)..."
$DC_LIGHTNING up -d bitcoin electrs nostr-relay

wait_for_bitcoin
wait_for_electrs
wait_for_nostr

# Start BDK nodes
log_info "Starting BDK nodes..."
$DC_LIGHTNING up -d bdk-alice bdk-bob bdk-charlie bdk-diana

# Start LDK nodes
log_info "Starting LDK nodes..."
$DC_LIGHTNING up -d bdk-alice-ln bdk-bob-ln

# Wait for LDK nodes to start and generate TLS certs
log_info "Waiting for LDK nodes to initialize..."
sleep 10

# Copy TLS certs for ldk-cli (needed before we can use CLI)
log_info "Copying TLS certificates..."
rm -rf "$BDK_DIR/certs"
mkdir -p "$BDK_DIR/certs"
for node in alice bob; do
    for attempt in 1 2 3 4 5; do
        if docker cp "bdk-${node}-ln:/ldk/tls.crt" "$BDK_DIR/certs/${node}.crt" 2>/dev/null; then
            log_success "Copied TLS cert for $node"
            break
        fi
        sleep 2
    done
done

# Setup faucet
setup_faucet

# Fund BDK nodes
for node in "${NODES[@]}"; do
    fund_node "$node" 10 || log_warn "Could not fund $node"
done

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
        log_warn "Could not get address for bdk-$node-ln"
        return 1
    fi

    log_info "Funding bdk-$node-ln at ${address:0:20}... with $amount BTC..."
    send_btc "$address" "$amount"
}

fund_ldk_node "alice" 2
fund_ldk_node "bob" 2

# Mine blocks
mine_blocks 6

# Wait for LDK on-chain wallets to sync
wait_for_ldk_balance() {
    local node=$1
    local min_sats=${2:-100000000}  # Default 1 BTC
    log_info "Waiting for bdk-$node-ln on-chain wallet to sync..."
    # With LDK_ONCHAIN_WALLET_SYNC_INTERVAL_SECS=10, wait up to 30 seconds
    for i in $(seq 1 15); do
        local balance=$(ldk_cli "$node" get-balances 2>/dev/null | jq -r '.spendable_onchain_balance_sats // 0' 2>/dev/null || echo "0")
        if [ "$balance" -ge "$min_sats" ]; then
            log_success "bdk-$node-ln balance: $balance sats"
            return 0
        fi
        sleep 2
    done
    log_warn "bdk-$node-ln wallet sync timeout (balance: $balance sats)"
    return 1
}

wait_for_ldk_balance "alice"
wait_for_ldk_balance "bob"

# Open channel between Alice and Bob
log_info "Opening Lightning channel between bdk-alice-ln and bdk-bob-ln..."

CHANNEL_AMOUNT=5000000  # 5M sats

# Get Bob's pubkey
bob_pubkey=$(ldk_cli bob get-node-info 2>/dev/null | jq -r '.node_id // empty' || echo "")
if [ -z "$bob_pubkey" ]; then
    log_warn "Could not get Bob's pubkey, skipping channel open"
else
    # Check if channel already exists
    existing=$(ldk_cli alice list-channels 2>/dev/null | jq -r ".channels[] | select(.counterparty_node_id == \"$bob_pubkey\") | .channel_id" 2>/dev/null || echo "")

    if [ -n "$existing" ]; then
        log_info "Channel already exists: ${existing:0:16}..."
    else
        # Open channel with 50/50 balance
        push_msat=$((CHANNEL_AMOUNT * 500))
        result=$(ldk_cli alice open-channel \
            --node-pubkey "$bob_pubkey" \
            --address "bdk-bob-ln:9736" \
            --channel-amount-sats "$CHANNEL_AMOUNT" \
            --push-to-counterparty-msat "$push_msat" \
            --announce-channel 2>&1) || true

        user_channel_id=$(echo "$result" | jq -r '.user_channel_id // empty' 2>/dev/null || echo "")
        if [ -n "$user_channel_id" ]; then
            log_info "Channel opening: ${user_channel_id:0:16}..."

            # Mine blocks to confirm
            mine_blocks 6

            # Wait for channel to be ready
            log_info "Waiting for channel to be ready..."
            for i in 1 2 3 4 5 6 7 8 9 10; do
                ready=$(ldk_cli alice list-channels 2>/dev/null | jq -r ".channels[] | select(.counterparty_node_id == \"$bob_pubkey\") | .is_channel_ready" 2>/dev/null || echo "false")
                if [ "$ready" = "true" ]; then
                    log_success "Channel opened and ready!"
                    break
                fi
                sleep 3
            done
        else
            log_warn "Channel open response: $result"
        fi
    fi
fi

log_success "=== BDK + Lightning Test Network Ready ==="

log_info "Service status:"
$DC_LIGHTNING ps

log_info "Block height: $(get_block_height)"

log_info ""
log_info "LDK nodes:"
log_info "  bdk-alice-ln: API at https://localhost:3111"
log_info "  bdk-bob-ln:   API at https://localhost:3112"
log_info ""
log_info "Next steps:"
log_info "  1. Open channel: ./bin/test-lightning.sh open-channel"
log_info "  2. Run full test: ./bin/test-lightning.sh"
