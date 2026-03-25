#!/bin/bash
# Reinitialize the full test network with Lightning node
#
# Tears down everything, optionally rebuilds binaries, then runs setup-4op-lightning.sh.
#
# Usage:
#   ./bin/reinit-lightning.sh           # Full teardown + rebuild + setup
#   ./bin/reinit-lightning.sh --quick   # Skip rebuild, just teardown + setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"
WORKSPACE_DIR="$(cd "$REPO_ROOT/.." && pwd)"

DC_LIGHTNING="docker compose -f $TOOLS_DIR/docker-compose.yml --profile lightning"

QUICK=false
REBUILD_LDK=false
PASSTHROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick|-q)
            QUICK=true
            shift
            ;;
        --rebuild-ldk)
            REBUILD_LDK=true
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
            echo "  --rebuild-ldk    Force rebuild of ldk-node Docker image"
            echo "  --nodes, -n N    Number of operator nodes (default: 4)"
            echo "  --help, -h       Show this help message"
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

log_info "=== Reinitializing + Lightning Test Network ==="

# Stop node processes
log_info "Stopping node processes..."
stop_all_nodes

# Stop any eve scale node processes
pkill -f "deposits-node run.*eve" 2>/dev/null || true

# Stop HTLC agent
pkill -f "htlc-agent" 2>/dev/null || true

# Stop native relays
log_info "Stopping native relays..."
stop_all_relays

# Stop per-node Electrs containers
log_info "Stopping per-node Electrs..."
stop_all_electrs

# Stop and remove all containers (including lightning node)
log_info "Stopping all containers..."
$DC_LIGHTNING down -v --remove-orphans 2>/dev/null || true

# Clean up lightning container/volumes not managed by compose
docker stop lightning 2>/dev/null || true
docker rm lightning 2>/dev/null || true
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

    if $REBUILD_LDK; then
        docker rmi ldk-node:latest 2>/dev/null || true
    fi
    if docker image inspect ldk-node:latest >/dev/null 2>&1; then
        log_info "ldk-node image already exists, skipping build (use --rebuild-ldk to force)"
    else
        log_info "Building ldk-node image..."
        docker build -f "$TOOLS_DIR/Dockerfile.ldk-node" -t ldk-node:latest "$WORKSPACE_DIR"
    fi
fi

# Start infrastructure (including lightning node, but NOT relay containers)
log_info "Starting infrastructure..."
$DC_LIGHTNING up -d bitcoin wallet

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

# Run the full 4-operator + lightning setup
exec "$SCRIPT_DIR/setup-4op-lightning.sh" "${PASSTHROUGH_ARGS[@]}"
