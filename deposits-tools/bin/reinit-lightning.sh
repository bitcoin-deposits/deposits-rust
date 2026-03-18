#!/bin/bash
# Reinitialize the full test network with Lightning sidecars
#
# Tears down everything, optionally rebuilds images, then runs setup-4op-lightning.sh.
#
# Usage:
#   ./bin/reinit-lightning.sh           # Full teardown + rebuild + setup
#   ./bin/reinit-lightning.sh --quick   # Skip rebuild, just teardown + setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"
TOOLS_DIR="${SCRIPT_DIR}/.."

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

# Stop any eve containers from setup-scale.sh
for c in $(docker ps -aq --filter 'name=eve'); do
    docker stop "$c" 2>/dev/null || true
    docker rm "$c" 2>/dev/null || true
done
for v in $(docker volume ls -q --filter 'name=eve'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Stop and remove everything
log_info "Stopping all containers..."
$DC_LIGHTNING down -v --remove-orphans 2>/dev/null || true

# Clean up containers not managed by compose
for node in alice bob charlie diana; do
    docker stop "${node}" "${node}-ln" 2>/dev/null || true
    docker rm "${node}" "${node}-ln" 2>/dev/null || true
done
for v in $(docker volume ls -q --filter 'name=ldk_'); do
    docker volume rm "$v" 2>/dev/null || true
done

# Clear wallet data
WALLET_DATA_DIR="${WALLET_DATA_DIR:-$HOME/.deposits-wallet}"
if [ -d "$WALLET_DATA_DIR" ]; then
    log_info "Clearing wallet data ($WALLET_DATA_DIR)..."
    rm -rf "$WALLET_DATA_DIR"
fi

docker image prune -f 2>/dev/null || true

if ! $QUICK; then
    log_info "Building local deposits-wallet binary..."
    cargo build --release --manifest-path "$TOOLS_DIR/../Cargo.toml" -p deposits-node --bin deposits-wallet 2>&1 | tail -3

    log_info "Building deposits-node image..."
    $DC_LIGHTNING build --no-cache alice

    log_info "Building ldk-node image..."
    docker build -f "$TOOLS_DIR/Dockerfile.ldk-node" -t ldk-node:latest "$HOME/workspace/"
fi

# Start infrastructure
log_info "Starting infrastructure..."
$DC_LIGHTNING up -d bitcoin electrs relay-alice relay-bob relay-charlie relay-diana relay-ledgers wallet

wait_for_bitcoin
wait_for_electrs
wait_for_nostr

# Setup faucet
setup_faucet

# Run the full 4-operator + lightning setup
exec "$SCRIPT_DIR/setup-4op-lightning.sh" "$@"
