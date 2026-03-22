#!/bin/bash
# Reinitialize the test network
#
# This script:
# 1. Stops node processes and infrastructure containers
# 2. Rebuilds the deposits-node binaries
# 3. Starts infrastructure services (bitcoin, electrs, relays)
# 4. Starts operator nodes as bare processes
# 5. Sets up the faucet wallet and funds the nodes
#
# Usage:
#   ./bin/reinit.sh           # Full reinit
#   ./bin/reinit.sh --quick   # Skip rebuild, just restart
#   ./bin/reinit.sh --fund    # Just fund the nodes (assumes running)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
QUICK=false
FUND_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick|-q)
            QUICK=true
            shift
            ;;
        --fund|-f)
            FUND_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick, -q   Skip rebuild, just restart"
            echo "  --fund, -f    Just fund the nodes (assumes services are running)"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

if $FUND_ONLY; then
    log_info "Funding nodes only..."
    wait_for_bitcoin
    wait_for_electrs

    fund_nodes_batch 10
    mine_blocks 6
    log_success "All nodes funded"
    exit 0
fi

log_info "=== Reinitializing Test Network ==="

# Stop node processes
log_info "Stopping node processes..."
stop_all_nodes

# Stop infrastructure
log_info "Stopping infrastructure containers..."
$DC down -v --remove-orphans 2>/dev/null || true

# Clear node data
log_info "Clearing node data ($DATA_ROOT)..."
rm -rf "$DATA_ROOT"

# Clear wallet data (deposits become invalid after reinit)
WALLET_DATA_DIR="${WALLET_DATA_DIR:-$HOME/.deposits-wallet}"
if [ -d "$WALLET_DATA_DIR" ]; then
    log_info "Clearing wallet data ($WALLET_DATA_DIR)..."
    rm -rf "$WALLET_DATA_DIR"
fi

# Remove any dangling images
docker image prune -f 2>/dev/null || true

if ! $QUICK; then
    # Build binaries
    log_info "Building deposits-node and deposits-wallet binaries..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin deposits-node --bin deposits-wallet 2>&1 | tail -3
fi

# Verify binaries exist
if [ ! -f "$DEPOSITS_NODE" ]; then
    log_error "deposits-node binary not found at $DEPOSITS_NODE"
    log_error "Run: cargo build --release -p deposits-node --bin deposits-node --bin deposits-wallet"
    exit 1
fi

# Start infrastructure services first
log_info "Starting infrastructure services..."
$DC up -d bitcoin
wait_for_bitcoin

# Ensure relay data dirs exist (wiped by rm -rf above)
mkdir -p "$DATA_ROOT/relays/alice" "$DATA_ROOT/relays/bob" "$DATA_ROOT/relays/charlie" "$DATA_ROOT/relays/diana" "$DATA_ROOT/relays/ledgers"

$DC up -d relay-alice relay-bob relay-charlie relay-diana
$DC up -d relay-ledgers
wait_for_nostr

$DC up -d electrs
wait_for_electrs

# Setup faucet
setup_faucet

# Start block miner (1 block/sec for regtest)
$DC up -d miner

# Start nodes as bare processes
log_info "Starting node processes..."
start_all_nodes

# Start monitoring stack
log_info "Starting monitoring (Prometheus + Grafana)..."
$DC up -d prometheus grafana

# Give nodes time to start
log_info "Waiting for nodes to initialize..."
sleep 10

# Fund all nodes in parallel, then mine to confirm
log_info "Funding nodes..."
fund_nodes_batch 10
mine_blocks 6

# Show status
echo ""
log_success "=== Test Network Ready ==="
echo ""
show_status
echo ""
log_info "Block height: $(get_block_height)"
echo ""
log_info "Useful commands:"
echo "  Follow logs:    tail -f $DATA_ROOT/alice/node.log"
echo "  All logs:       tail -f $DATA_ROOT/*/node.log"
echo "  Mine blocks:    docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 1"
echo "  Nostr relay:    ws://localhost:7801"
echo "  Electrs:        http://localhost:3102"
echo "  Prometheus:     http://localhost:9090"
echo "  Grafana:        http://localhost:3010 (admin/admin)"
echo "  Stop nodes:     source bin/_common.sh && stop_all_nodes"
