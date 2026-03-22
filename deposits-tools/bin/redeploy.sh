#!/bin/bash
# Redeploy nodes with new code, preserving all data
#
# Rebuilds the Rust binaries, then restarts the node processes.
# All data directories and infrastructure services are left untouched.
#
# Usage:
#   ./bin/redeploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log_info "=== Redeploying Nodes (data preserved) ==="

# Build binaries
log_info "Building deposits-node and deposits-wallet binaries..."
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin deposits-node --bin deposits-wallet 2>&1 | tail -3

# Stop and restart node processes (data dirs stay)
log_info "Stopping nodes..."
stop_all_nodes

log_info "Starting nodes with new binary..."
start_all_nodes

log_info "Waiting for nodes to initialize..."
sleep 5

echo ""
log_success "=== Nodes Redeployed (data preserved) ==="
echo ""
show_status
