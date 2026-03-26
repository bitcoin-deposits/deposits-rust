#!/bin/bash
# Reinitialize the test network
#
# Tears down everything, optionally rebuilds binaries, starts infrastructure,
# then runs setup-4op.sh for the full setup (reserves, ledgers, quorum, collateral).
#
# Usage:
#   ./bin/reinit.sh              # Full teardown + rebuild + setup
#   ./bin/reinit.sh --quick      # Skip rebuild, just teardown + setup
#   ./bin/reinit.sh --nodes 6    # 6-operator network

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
QUICK=false
PASSTHROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick|-q)
            QUICK=true
            shift
            ;;
        --nodes|-n)
            NODE_COUNT="$2"
            PASSTHROUGH_ARGS+=(--nodes "$2")
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick, -q      Skip rebuild, just teardown + setup"
            echo "  --nodes, -n N    Number of operator nodes (default: 4)"
            echo "  --help, -h       Show this help message"
            echo ""
            echo "Additional options are passed through to setup-4op.sh:"
            echo "  --enforcement-delay BLOCKS   (default: 200)"
            echo "  --reserves SATS              (default: 100000000)"
            echo "  --ledgers-per-op N           (default: 3)"
            echo "  --show-topology              Print topology and exit"
            exit 0
            ;;
        *)
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

# Re-initialize topology (NODE_COUNT may have changed from --nodes)
init_topology

log_info "=== Reinitializing Test Network ==="

# Stop node processes
log_info "Stopping node processes..."
stop_all_nodes
pkill -f "htlc-agent" 2>/dev/null || true

# Stop native relays
log_info "Stopping native relays..."
stop_all_relays

# Stop per-node Electrs containers
log_info "Stopping per-node Electrs..."
stop_all_electrs

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

# Start infrastructure services
log_info "Starting infrastructure services..."
$DC up -d bitcoin
wait_for_bitcoin

# Start per-node Electrs instances (1 per 2 nodes)
log_info "Starting per-node Electrs instances..."
start_all_electrs
wait_for_all_electrs

# Start native strfry relays
log_info "Starting native strfry relays..."
start_all_relays
wait_for_nostr

# Setup faucet
setup_faucet

# Start block miner (1 block/sec for regtest)
$DC up -d miner

# Start monitoring stack
log_info "Starting monitoring (Prometheus + Grafana)..."
$DC up -d prometheus grafana

# Run the full operator setup (reserves, ledgers, quorum, collateral, rotation)
exec "$SCRIPT_DIR/setup-4op.sh" "${PASSTHROUGH_ARGS[@]}"
