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

AGENT_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --agent)
            AGENT_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --agent       Rebuild and restart only the HTLC agent"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

AGENT_DATA_DIR="$DATA_ROOT/htlc-agent"

if $AGENT_ONLY; then
    log_info "=== Redeploying HTLC Agent ==="

    log_info "Building htlc-agent..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin htlc-agent 2>&1 | tail -3

    "$SCRIPT_DIR/setup-htlc-agent.sh" --keep-data
else
    log_info "=== Redeploying Nodes (data preserved) ==="

    # Build binaries
    log_info "Building deposits-node, deposits-wallet, and htlc-agent..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin deposits-node --bin deposits-wallet --bin htlc-agent 2>&1 | tail -3

    # Stop and restart node processes (data dirs stay)
    log_info "Stopping nodes..."
    stop_all_nodes
    pkill -f "htlc-agent" 2>/dev/null || true

    log_info "Starting nodes with new binary..."
    start_all_nodes

    log_info "Waiting for nodes to initialize..."
    sleep 5

    # Restart HTLC agent if it was previously set up
    if [ -f "$AGENT_DATA_DIR/seed.hex" ]; then
        "$SCRIPT_DIR/setup-htlc-agent.sh" --keep-data
    fi

    echo ""
    log_success "=== Nodes Redeployed (data preserved) ==="
    echo ""
    show_status
fi
