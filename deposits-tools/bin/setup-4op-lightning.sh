#!/bin/bash
# Four-operator setup with Lightning sidecars
#
# Runs setup-4op.sh first, then adds LDK Lightning nodes in a ring topology.
# Each operator gets an LDK sidecar connected via environment variables.
#
# Usage:
#   ./bin/setup-4op-lightning.sh [--skip-reset] [--channel-size SATS]
#
# Prerequisites:
#   - ldk-node image built (docker build -f deposits-tools/Dockerfile.ldk-node -t ldk-node:latest ~/workspace/)
#   - ldk-server-cli available (cd ~/workspace/ldk-server && cargo build --release)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Lightning-specific docker compose
DC="docker compose -f $BDK_DIR/docker-compose.yml --profile lightning"

# Configuration
CHANNEL_AMOUNT=5000000  # 5M sats per channel
SKIP_BASE_SETUP=false
SETUP_ARGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --channel-size)
            CHANNEL_AMOUNT="$2"
            shift 2
            ;;
        --skip-base)
            SKIP_BASE_SETUP=true
            shift
            ;;
        *)
            # Pass through to setup-4op.sh
            SETUP_ARGS+=("$1")
            shift
            ;;
    esac
done

OPERATORS="alice bob charlie diana"

# LDK port mapping
ldk_host_port() {
    case "$1" in
        "alice")   echo "3111" ;;
        "bob")     echo "3112" ;;
        "charlie") echo "3113" ;;
        "diana")   echo "3114" ;;
    esac
}

ldk_listen_port() {
    case "$1" in
        "alice")   echo "9735" ;;
        "bob")     echo "9736" ;;
        "charlie") echo "9737" ;;
        "diana")   echo "9738" ;;
    esac
}

# ldk-cli helper (runs inside container)
ldk_cli() {
    local node=$1
    shift
    docker exec "${node}-ln" ldk-server-cli -b "localhost:3000" -a test_api_key -t /ldk/tls.crt "$@" 2>/dev/null
}

# ============================================================================
# Phase 1: Run base 4-operator setup
# ============================================================================

if [ "$SKIP_BASE_SETUP" = false ]; then
    log_info "=========================================="
    log_info "  Phase 1: Base 4-Operator Setup"
    log_info "=========================================="
    echo ""
    "$SCRIPT_DIR/setup-4op.sh" "${SETUP_ARGS[@]}"
    echo ""
fi

# ============================================================================
# Phase 2: Start LDK Lightning sidecars
# ============================================================================

log_info "=========================================="
log_info "  Lightning Setup"
log_info "=========================================="
echo ""

log_info "=== Starting Lightning sidecars ==="

# Stop existing LDK containers and wipe stale data
for node in $OPERATORS; do
    docker stop "${node}-ln" 2>/dev/null || true
    docker rm "${node}-ln" 2>/dev/null || true
done
# Remove old LDK volumes to prevent stale channel state conflicts
for v in $(docker volume ls -q --filter 'name=ldk_'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Start LDK sidecars via compose overlay
$DC up -d alice-ln bob-ln charlie-ln diana-ln

# Wait for LDK nodes to initialize and generate TLS certs
log_info "Waiting for LDK nodes to initialize..."
sleep 10

# Copy TLS certs
log_info "Copying TLS certificates..."
rm -rf "$BDK_DIR/certs"
mkdir -p "$BDK_DIR/certs"
for node in $OPERATORS; do
    for attempt in 1 2 3 4 5; do
        if docker cp "${node}-ln:/ldk/tls.crt" "$BDK_DIR/certs/${node}.crt" 2>/dev/null; then
            log_success "  $node TLS cert ready"
            break
        fi
        sleep 2
    done
done

# Restart BDK nodes with LDK environment (compose overlay adds LDK_HOST etc.)
log_info "Restarting operator nodes with Lightning sidecar config..."
$DC up -d alice bob charlie diana
sleep 5

# ============================================================================
# Phase 3: Fund LDK nodes
# ============================================================================

log_info ""
log_info "=== Funding Lightning nodes ==="

for node in $OPERATORS; do
    local_address=""
    for i in 1 2 3 4 5; do
        result=$(ldk_cli "$node" onchain-receive 2>/dev/null || echo "")
        local_address=$(echo "$result" | jq -r '.address // empty' 2>/dev/null || echo "")
        if [ -n "$local_address" ]; then
            break
        fi
        sleep 2
    done

    if [ -z "$local_address" ]; then
        log_warn "Could not get address for ${node}-ln"
        continue
    fi

    bitcoin_cli -rpcwallet=faucet sendtoaddress "$local_address" 2 >/dev/null 2>&1
    log_info "  Funded ${node}-ln at ${local_address:0:20}..."
done

mine_blocks 6

# Wait for LDK wallet sync
log_info "Waiting for Lightning wallet sync..."
for node in $OPERATORS; do
    for i in $(seq 1 15); do
        balance=$(ldk_cli "$node" get-balances 2>/dev/null | jq -r '.spendable_onchain_balance_sats // 0' 2>/dev/null || echo "0")
        balance=${balance:-0}
        if [ "$balance" -ge 100000000 ] 2>/dev/null; then
            log_success "  ${node}-ln balance: $balance sats"
            break
        fi
        sleep 2
    done
done

# ============================================================================
# Phase 4: Open Lightning channels (ring topology)
# ============================================================================

log_info ""
log_info "=== Opening Lightning channels (ring) ==="
log_info "Topology: Alice <-> Bob <-> Charlie <-> Diana <-> Alice"
log_info "Channel size: $CHANNEL_AMOUNT sats"
echo ""

open_channel() {
    local from=$1
    local to=$2

    local to_pubkey=$(ldk_cli "$to" get-node-info 2>/dev/null | jq -r '.node_id // empty' || echo "")
    if [ -z "$to_pubkey" ]; then
        log_warn "Could not get $to's pubkey, skipping channel"
        return 1
    fi

    # Check if channel already exists
    local existing=$(ldk_cli "$from" list-channels 2>/dev/null | jq -r ".channels[] | select(.counterparty_node_id == \"$to_pubkey\") | .channel_id" 2>/dev/null || echo "")
    if [ -n "$existing" ]; then
        log_info "  Channel $from -> $to already exists"
        return 0
    fi

    local to_port=$(ldk_listen_port "$to")
    local push_msat=$((CHANNEL_AMOUNT * 500))

    log_info "  Opening channel: $from -> $to..."
    local result=$(ldk_cli "$from" open-channel \
        --node-pubkey "$to_pubkey" \
        --address "${to}-ln:${to_port}" \
        --channel-amount-sats "$CHANNEL_AMOUNT" \
        --push-to-counterparty-msat "$push_msat" \
        --announce-channel 2>&1) || true

    local user_channel_id=$(echo "$result" | jq -r '.user_channel_id // empty' 2>/dev/null || echo "")
    if [ -n "$user_channel_id" ]; then
        log_success "  Channel $from -> $to pending: ${user_channel_id:0:16}..."
        return 0
    else
        log_warn "  Channel $from -> $to failed: $(echo "$result" | head -1)"
        return 1
    fi
}

# Ring: Alice -> Bob -> Charlie -> Diana -> Alice
open_channel "alice" "bob"
open_channel "bob" "charlie"
open_channel "charlie" "diana"
open_channel "diana" "alice"

# Also open reverse channels to force peer reconnection (acceptors need this)
log_info ""
log_info "Opening reverse channels (ensures peer connectivity)..."
ALICE_KEY=$(ldk_cli alice get-node-info | jq -r .node_id)
BOB_KEY=$(ldk_cli bob get-node-info | jq -r .node_id)
CHARLIE_KEY=$(ldk_cli charlie get-node-info | jq -r .node_id)
DIANA_KEY=$(ldk_cli diana get-node-info | jq -r .node_id)

ldk_cli bob open-channel --node-pubkey "$ALICE_KEY" --address alice-ln:9735 --channel-amount-sats 100000 --announce-channel >/dev/null 2>&1 || true
ldk_cli charlie open-channel --node-pubkey "$BOB_KEY" --address bob-ln:9736 --channel-amount-sats 100000 --announce-channel >/dev/null 2>&1 || true
ldk_cli diana open-channel --node-pubkey "$CHARLIE_KEY" --address charlie-ln:9737 --channel-amount-sats 100000 --announce-channel >/dev/null 2>&1 || true
ldk_cli alice open-channel --node-pubkey "$DIANA_KEY" --address diana-ln:9738 --channel-amount-sats 100000 --announce-channel >/dev/null 2>&1 || true

# Confirm all channels
mine_blocks 6
log_info "Waiting for channels to confirm..."

# Wait until all nodes have at least 2 usable channels (or timeout after 60s)
for attempt in $(seq 1 12); do
    all_ready=true
    for node in $OPERATORS; do
        usable=$(ldk_cli "$node" list-channels 2>/dev/null | jq '[.channels[] | select(.is_usable==true)] | length' 2>/dev/null || echo "0")
        usable=${usable:-0}
        if [ "$usable" -lt 2 ] 2>/dev/null; then
            all_ready=false
        fi
    done
    if $all_ready; then break; fi
    sleep 5
done

# ============================================================================
# Summary
# ============================================================================

log_info ""
log_info "=========================================="
log_info "  Lightning Setup Complete!"
log_info "=========================================="
echo ""

# Show channel status
for node in $OPERATORS; do
    channels=$(ldk_cli "$node" list-channels 2>/dev/null | jq -r '.channels | length' 2>/dev/null || echo "0")
    ready=$(ldk_cli "$node" list-channels 2>/dev/null | jq -r '[.channels[] | select(.is_channel_ready == true)] | length' 2>/dev/null || echo "0")
    echo "  ${node}-ln: $ready/$channels channels ready"
done

echo ""
log_info "LDK Lightning nodes:"
echo "  alice-ln:   API at https://localhost:3111"
echo "  bob-ln:     API at https://localhost:3112"
echo "  charlie-ln: API at https://localhost:3113"
echo "  diana-ln:   API at https://localhost:3114"
echo ""
echo "Channel topology: Alice <-> Bob <-> Charlie <-> Diana <-> Alice (ring)"
echo "Channel size: $CHANNEL_AMOUNT sats each (50/50 balance)"
echo ""
log_info "Next steps:"
echo "  Test lightning:   ./bin/test-lightning.sh"
echo "  Payment sim:      ./bin/payment-simulator.py --lightning"
echo ""

log_success "Done! 4 operators with Lightning sidecars ready."
