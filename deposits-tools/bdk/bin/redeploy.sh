#!/bin/bash
# Redeploy BDK nodes with new code, preserving all data
#
# Rebuilds the Rust binary and Docker image, then restarts only the BDK node
# containers. All volumes (blockchain, electrs, relay DB, node /data) are kept.
# Infrastructure services (bitcoind, electrs, strfry, prometheus, grafana) are
# left running untouched.
#
# Usage:
#   ./bin/redeploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log_info "=== Redeploying BDK Nodes (data preserved) ==="

# Build local wallet binary
log_info "Building local deposits-wallet binary..."
cargo build --release --manifest-path "$BDK_DIR/../../Cargo.toml" -p deposits-bdk --bin deposits-wallet 2>&1 | tail -3

# Rebuild Docker image
log_info "Building deposits-bdk image..."
$DC build --no-cache bdk-alice

# Stop and recreate only the BDK node containers (volumes stay)
log_info "Stopping BDK nodes..."
$DC stop bdk-alice bdk-bob bdk-charlie bdk-diana

log_info "Recreating BDK nodes with new image..."
$DC rm -f bdk-alice bdk-bob bdk-charlie bdk-diana
$DC up -d bdk-alice bdk-bob bdk-charlie bdk-diana

log_info "Waiting for nodes to initialize..."
sleep 5

echo ""
log_success "=== BDK Nodes Redeployed (data preserved) ==="
echo ""
show_status
