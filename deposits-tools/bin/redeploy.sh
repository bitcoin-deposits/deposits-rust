#!/bin/bash
# Redeploy nodes with new code, preserving all data
#
# Rebuilds the Rust binaries, then restarts the node processes.
# All data directories and infrastructure services are left untouched.
#
# Auto-detects node count from the persisted topology (saved by setup-4op.sh).
# Falls back to counting data directories if no topology file exists.
#
# Usage:
#   ./bin/redeploy.sh              # Redeploy all nodes + agent
#   ./bin/redeploy.sh --agent      # Redeploy only the HTLC agent
#   ./bin/redeploy.sh --nodes 8    # Override node count

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-detect node count BEFORE sourcing _common.sh (which calls init_topology)
# Priority: --nodes arg > topology.json > data dir count > default 4
_detect_node_count() {
    local data_root="${SCRIPT_DIR}/../data"

    # Check persisted topology from setup-4op.sh
    if [ -f "$data_root/topology.json" ]; then
        local count=$(python3 -c "import json; print(len(json.load(open('$data_root/topology.json'))['nodes']))" 2>/dev/null || echo "")
        if [ -n "$count" ] && [ "$count" -gt 0 ] 2>/dev/null; then
            echo "$count"
            return
        fi
    fi

    # Fall back: count node data directories (exclude non-node dirs)
    local count=0
    for d in "$data_root"/*/; do
        local name=$(basename "$d")
        case "$name" in
            relays|htlc-agent|self-pay|state) continue ;;
            *) [ -f "$d/node.pid" ] || [ -f "$d/seed.hex" ] && count=$((count + 1)) ;;
        esac
    done
    if [ "$count" -gt 0 ]; then
        echo "$count"
        return
    fi

    echo "4"
}

# Parse args before sourcing _common.sh
AGENT_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --agent)
            AGENT_ONLY=true
            shift
            ;;
        --nodes|-n)
            NODE_COUNT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --agent            Rebuild and restart only the HTLC agent"
            echo "  --nodes, -n <N>    Override node count (default: auto-detect)"
            echo "  --help, -h         Show this help message"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Auto-detect if not specified via --nodes
if [ -z "${NODE_COUNT:-}" ]; then
    NODE_COUNT=$(_detect_node_count)
fi
export NODE_COUNT

source "$SCRIPT_DIR/_common.sh"

AGENT_DATA_DIR="$DATA_ROOT/htlc-agent"

log_info "Detected $NODE_COUNT nodes: ${NODES[*]}"

if $AGENT_ONLY; then
    log_info "=== Redeploying HTLC Agent ==="

    log_info "Building htlc-agent..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-node --bin htlc-agent 2>&1 | tail -3

    "$SCRIPT_DIR/setup-htlc-agent.sh" --keep-data
else
    log_info "=== Redeploying $NODE_COUNT Nodes (data preserved) ==="

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
    log_success "=== $NODE_COUNT Nodes Redeployed (data preserved) ==="
    echo ""
    show_status
fi
