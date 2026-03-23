#!/bin/bash
# Reinitialize the full test network with Lightning sidecars
#
# Tears down everything, optionally rebuilds binaries, then runs setup-4op-lightning.sh.
#
# Usage:
#   ./bin/reinit-lightning.sh           # Full teardown + rebuild + setup
#   ./bin/reinit-lightning.sh --quick   # Skip rebuild, just teardown + setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

DC_LIGHTNING="docker compose -f $TOOLS_DIR/docker-compose.yml --profile lightning"

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
            echo "  --quick, -q   Skip rebuild, just teardown + setup"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info "=== Reinitializing + Lightning Test Network ==="

# Stop node processes
log_info "Stopping node processes..."
stop_all_nodes

# Stop any eve scale node processes
pkill -f "deposits-node run.*eve" 2>/dev/null || true

# Stop HTLC agent
pkill -f "htlc-agent" 2>/dev/null || true

# Stop and remove all containers (including lightning sidecars)
log_info "Stopping all containers..."
$DC_LIGHTNING down -v --remove-orphans 2>/dev/null || true

# Clean up LDK containers/volumes not managed by compose
for node in alice bob charlie diana; do
    docker stop "${node}-ln" 2>/dev/null || true
    docker rm "${node}-ln" 2>/dev/null || true
done
for v in $(docker volume ls -q --filter 'name=ldk_'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Clear node data
log_info "Clearing node data ($DATA_ROOT)..."
rm -rf "$DATA_ROOT"

# Clear wallet data
WALLET_DATA_DIR="${WALLET_DATA_DIR:-$HOME/.deposits-wallet}"
if [ -d "$WALLET_DATA_DIR" ]; then
    log_info "Clearing wallet data ($WALLET_DATA_DIR)..."
    rm -rf "$WALLET_DATA_DIR"
fi

docker image prune -f 2>/dev/null || true

if ! $QUICK; then
    log_info "Building deposits-node, deposits-wallet, and htlc-agent binaries..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin deposits-node --bin deposits-wallet --bin htlc-agent 2>&1 | tail -3

    log_info "Building ldk-node image..."
    docker build -f "$TOOLS_DIR/Dockerfile.ldk-node" -t ldk-node:latest "$HOME/workspace/"
fi

# Create relay bind-mount directories
mkdir -p "$DATA_ROOT/relays/alice" "$DATA_ROOT/relays/bob" "$DATA_ROOT/relays/charlie" "$DATA_ROOT/relays/diana" "$DATA_ROOT/relays/ledgers"

# Start infrastructure (including lightning sidecars)
log_info "Starting infrastructure..."
$DC_LIGHTNING up -d bitcoin electrs relay-alice relay-bob relay-charlie relay-diana relay-ledgers wallet

wait_for_bitcoin
wait_for_electrs
wait_for_nostr

# Setup faucet
setup_faucet

# Run the full 4-operator + lightning setup
exec "$SCRIPT_DIR/setup-4op-lightning.sh" "$@"
