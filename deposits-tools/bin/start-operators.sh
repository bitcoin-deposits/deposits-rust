#!/bin/bash
# Start operator watch processes for all nodes
#
# This starts background nostr watch processes so operators can respond
# to wallet requests (deposit offers, withdrawals, etc.)
#
# Usage:
#   ./bin/start-operators.sh        Start watches for all operators
#   ./bin/start-operators.sh alice  Start watch for Alice only
#   ./bin/start-operators.sh stop   Stop all watch processes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

start_operator_watch() {
    local container=$1
    local reserves_id=$2

    if [ -z "$reserves_id" ]; then
        # Try to get reserves from node info
        local info=$(run_node_cmd "$container" info 2>&1)
        reserves_id=$(echo "$info" | grep "Reserves address:" | awk '{print $3}')
    fi

    if [ -z "$reserves_id" ]; then
        log_warn "$container: No reserves found, skipping"
        return 1
    fi

    # Stop any existing watch first
    stop_nostr_watch "$container"

    # Start watch in background
    start_nostr_watch "$container" "$reserves_id"
    log_success "$container watching ${reserves_id:0:16}..."
}

stop_all_watches() {
    log_info "Stopping all operator watches..."
    for container in alice bob charlie diana; do
        if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            stop_nostr_watch "$container"
            log_info "  Stopped $container"
        fi
    done
    log_success "All watches stopped"
}

start_all_watches() {
    log_info "Starting operator watches..."
    echo ""

    for container in alice bob charlie diana; do
        if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            start_operator_watch "$container" || true
        else
            log_warn "$container not running"
        fi
    done

    echo ""
    log_success "Operators are now watching for requests"
    log_info "Test with: deposits-wallet discover --relay ws://localhost:<port>"
    log_info "Then:      deposits-wallet open <ledger_id> --alias test"
    log_info "           deposits-wallet offer test 50000"
}

case "${1:-all}" in
    stop)
        stop_all_watches
        ;;
    alice)
        start_operator_watch alice "$2"
        ;;
    bob)
        start_operator_watch bob "$2"
        ;;
    charlie)
        start_operator_watch charlie "$2"
        ;;
    diana)
        start_operator_watch diana "$2"
        ;;
    all|"")
        start_all_watches
        ;;
    *)
        echo "Usage: $0 [all|alice|bob|charlie|diana|stop] [reserves_id]"
        exit 1
        ;;
esac
