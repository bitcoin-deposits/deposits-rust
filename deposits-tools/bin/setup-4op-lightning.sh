#!/bin/bash
# Four-operator setup with shared Lightning node
#
# Runs setup-4op.sh first, then starts a single LDK Lightning node shared by
# all operators via the self-pay wrapper (subwallet approach).
#
# Usage:
#   ./bin/setup-4op-lightning.sh [--skip-reset]
#
# Prerequisites:
#   - ldk-node image built (docker build -f deposits-tools/Dockerfile.ldk-node -t ldk-node:latest ~/workspace/)
#   - ldk-server-cli available (cd ~/ldk-server && cargo build --release)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Lightning-specific docker compose
DC="docker compose -f $TOOLS_DIR/docker-compose.yml --profile lightning"

# ldk-server-cli binary (host-side, talks to LDK container)
LDK_SERVER_CLI="${LDK_SERVER_CLI:-$HOME/ldk-server/target/release/ldk-server-cli}"
if [ ! -x "$LDK_SERVER_CLI" ]; then
    log_warn "ldk-server-cli not found at $LDK_SERVER_CLI — building..."
    (cd "$HOME/ldk-server" && cargo build --release --bin ldk-server-cli) || {
        log_warn "Failed to build ldk-server-cli; lightning invoices will not work"
        LDK_SERVER_CLI="ldk-server-cli"  # fall back to PATH
    }
fi

# Configuration
SKIP_BASE_SETUP=false
SETUP_ARGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-base)
            SKIP_BASE_SETUP=true
            shift
            ;;
        --nodes|-n)
            NODE_COUNT="$2"
            SETUP_ARGS+=(--nodes "$2")
            shift 2
            ;;
        *)
            # Pass through to setup-4op.sh
            SETUP_ARGS+=("$1")
            shift
            ;;
    esac
done

# Re-initialize topology (NODE_COUNT may have changed from --nodes)
init_topology

OPERATORS="${NODES[*]}"

# ldk-cli helper (runs inside the shared lightning container)
ldk_cli() {
    local network=$(docker exec lightning printenv NETWORK 2>/dev/null || echo "regtest")
    local api_key=$(docker exec lightning sh -c "cat /ldk/${network}/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null)
    docker exec lightning ldk-server-cli -b "localhost:3000" -a "$api_key" -t /ldk/tls.crt "$@" 2>/dev/null
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
# Phase 2: Start Lightning node
# ============================================================================

log_info "=========================================="
log_info "  Lightning Setup"
log_info "=========================================="
echo ""

log_info "=== Starting Lightning node ==="

# Stop existing LDK container and wipe stale data
docker stop lightning 2>/dev/null || true
docker rm lightning 2>/dev/null || true
for v in $(docker volume ls -q --filter 'name=ldk_'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Start LDK node via compose
$DC up -d lightning

# Wait for LDK node to initialize and generate TLS cert
log_info "Waiting for Lightning node to initialize..."
sleep 10

# Copy TLS cert
log_info "Copying TLS certificate..."
rm -rf "$TOOLS_DIR/certs"
mkdir -p "$TOOLS_DIR/certs"
for attempt in 1 2 3 4 5; do
    if docker cp "lightning:/ldk/tls.crt" "$TOOLS_DIR/certs/lightning.crt" 2>/dev/null; then
        log_success "  TLS cert ready"
        break
    fi
    sleep 2
done

# Restart deposit nodes with shared Lightning node via self-pay wrapper
log_info "Restarting operator nodes with shared Lightning node..."

LN_NETWORK=$(docker exec lightning printenv NETWORK 2>/dev/null || echo "regtest")
LN_API_KEY=$(docker exec lightning sh -c "cat /ldk/${LN_NETWORK}/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null)

LDK_WRAPPER="$TOOLS_DIR/bin/ldk-cli-wrapper.sh"
SELF_PAY_DIR="$DATA_ROOT/self-pay"
mkdir -p "$SELF_PAY_DIR"

for node in $OPERATORS; do
    stop_node "$node"
done
sleep 2
for node in $OPERATORS; do
    data_dir=$(get_node_data_dir "$node")
    seed=$(get_node_seed "$node")
    metrics_port=$(get_node_metrics_port "$node")

    mkdir -p "$data_dir"

    # Own relay first (primary for publishing), then the rest for reads
    own_relay=$(get_node_relay_url "$node")
    relay_args="--relay $own_relay"
    for r in "${ALL_RELAYS[@]}"; do
        [ "$r" != "$own_relay" ] && relay_args="$relay_args --relay $r"
    done

    LDK_CLI="$LDK_WRAPPER" \
    LDK_REAL_CLI="$LDK_SERVER_CLI" \
    LDK_HOST="localhost" \
    LDK_PORT="3111" \
    LDK_API_KEY="$LN_API_KEY" \
    LDK_TLS_CERT="$TOOLS_DIR/certs/lightning.crt" \
    LDK_SELF_PAY_DIR="$SELF_PAY_DIR" \
    RUST_LOG=info,nostr_relay_pool=warn,nostr_sdk=warn \
    DEPOSITS_ENABLE_METRICS_EMITTER=1 \
    "$DEPOSITS_NODE" run \
        --seed "$seed" \
        --network regtest \
        --electrum "$(get_node_electrs_url "$node")" \
        $relay_args \
        --slow-relay "$RELAY_LEDGERS" \
        --data-dir "$data_dir" \
        --metrics-port "$metrics_port" \
        --fast-poll \
        --skip-nostr-verify \
        > "$data_dir/node.log" 2>&1 &

    pid=$!
    echo "$pid" > "$data_dir/node.pid"
    log_success "Restarted $node (pid $pid)"
done
sleep 5

# ============================================================================
# Phase 3: Fund Lightning node
# ============================================================================

log_info ""
log_info "=== Funding Lightning node ==="

local_address=""
for i in 1 2 3 4 5; do
    result=$(ldk_cli onchain-receive 2>/dev/null || echo "")
    local_address=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('address',''))" 2>/dev/null || echo "")
    if [ -n "$local_address" ]; then
        break
    fi
    sleep 2
done

if [ -z "$local_address" ]; then
    log_warn "Could not get address for lightning node"
else
    bitcoin_cli -rpcwallet=faucet sendtoaddress "$local_address" 2 >/dev/null 2>&1
    log_info "  Funded at ${local_address:0:20}..."

    mine_blocks 6

    # Wait for wallet sync
    log_info "Waiting for Lightning wallet sync..."
    for i in $(seq 1 15); do
        balance=$(ldk_cli get-balances 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('spendable_onchain_balance_sats',0))" 2>/dev/null || echo "0")
        balance=${balance:-0}
        if [ "$balance" -ge 100000000 ] 2>/dev/null; then
            log_success "  Lightning balance: $balance sats"
            break
        fi
        sleep 2
    done
fi

# ============================================================================
# Phase 4: HTLC Agent — cross-ledger routing
# ============================================================================

"$SCRIPT_DIR/setup-htlc-agent.sh"

AGENT_DATA_DIR="$DATA_ROOT/htlc-agent"

# ============================================================================
# Summary
# ============================================================================

log_info ""
log_info "=========================================="
log_info "  Lightning Setup Complete!"
log_info "=========================================="
echo ""

log_info "Lightning node:"
echo "  Container: lightning"
echo "  API:       https://localhost:3111"
echo "  Self-pay:  $TOOLS_DIR/bin/ldk-cli-wrapper.sh"
echo "  State:     $DATA_ROOT/self-pay/"
echo ""

# HTLC agent status
if [ -f "$AGENT_DATA_DIR/agent.pid" ] && kill -0 "$(cat "$AGENT_DATA_DIR/agent.pid")" 2>/dev/null; then
    log_info "HTLC Agent:"
    echo "  PID:  $(cat "$AGENT_DATA_DIR/agent.pid")"
    echo "  Log:  $AGENT_DATA_DIR/agent.log"
    echo ""
fi

log_info "Next steps:"
echo "  Test lightning:   ./bin/test-lightning.sh"
echo "  Agent logs:       tail -f $DATA_ROOT/htlc-agent/agent.log"
echo ""

num_ops=$(echo $OPERATORS | wc -w | tr -d ' ')
log_success "Done! $num_ops operators with shared Lightning node + HTLC agent ready."
