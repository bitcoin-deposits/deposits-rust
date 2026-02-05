#!/bin/bash
# Reinitialize the BDK test network
#
# This script:
# 1. Stops and removes all containers and volumes
# 2. Rebuilds the deposits-bdk image
# 3. Starts all services
# 4. Sets up the faucet wallet
# 5. Funds the BDK nodes
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
            echo "  --quick, -q   Skip rebuild, just restart containers"
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

    for node in "${NODES[@]}"; do
        fund_node "$node" 10 || log_warn "Could not fund $node"
    done

    mine_blocks 6
    log_success "All nodes funded"
    exit 0
fi

log_info "=== Reinitializing BDK Test Network ==="

# Stop everything
log_info "Stopping all containers..."
$DC down -v --remove-orphans 2>/dev/null || true

# Remove any dangling images
docker image prune -f 2>/dev/null || true

if ! $QUICK; then
    # Rebuild deposits-bdk image (shared by all nodes)
    log_info "Building deposits-bdk image..."
    $DC build --no-cache bdk-alice
fi

# Start infrastructure services first
log_info "Starting infrastructure services..."
$DC up -d bitcoin
wait_for_bitcoin

$DC up -d nostr-relay
wait_for_nostr

$DC up -d electrs
wait_for_electrs

# Setup faucet
setup_faucet

# Start BDK nodes
log_info "Starting BDK nodes..."
$DC up -d bdk-alice bdk-bob bdk-charlie bdk-diana

# Give nodes time to start
log_info "Waiting for nodes to initialize..."
sleep 10

# Fund each node
log_info "Funding BDK nodes..."
for node in "${NODES[@]}"; do
    fund_node "$node" 10 || log_warn "Could not fund $node (may need address command)"
done

# Mine some blocks to confirm
mine_blocks 6

# Show status
echo ""
log_success "=== BDK Test Network Ready ==="
echo ""
show_status
echo ""
log_info "Block height: $(get_block_height)"
echo ""
log_info "Useful commands:"
echo "  Follow logs:    $DC logs -f"
echo "  Alice logs:     $DC logs -f bdk-alice"
echo "  Mine blocks:    docker exec bdk-bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=faucet -generate 1"
echo "  Nostr relay:    ws://localhost:7778"
echo "  Electrs:        http://localhost:3102"
