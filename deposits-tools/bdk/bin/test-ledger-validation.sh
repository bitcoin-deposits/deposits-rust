#!/bin/bash
# Ledger Export/Import/Validate Test Script
#
# This script tests the ledger validation flow:
# 1. Exports a ledger from the operator node
# 2. Discovers quorum members from the ledger
# 3. Imports the ledger on each quorum member's node
# 4. Validates the imported ledger on each quorum member
#
# Usage:
#   ./bin/test-ledger-validation.sh [reserves_id]
#
# If no reserves_id is provided, uses the primary ledger.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Use temp directory for exports and state (bash 3.x compatible)
STATE_DIR=$(mktemp -d)
EXPORT_DIR="$STATE_DIR/exports"
mkdir -p "$EXPORT_DIR"
trap "rm -rf $STATE_DIR" EXIT

TESTS_PASSED=0
TESTS_FAILED=0

test_pass() {
    log_success "PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

test_fail() {
    log_error "FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Store/retrieve functions (bash 3.2 compatible, same pattern as _common.sh)
store_value() {
    local key="$1"
    local value="$2"
    echo "$value" > "$STATE_DIR/$key"
}

get_value() {
    local key="$1"
    if [ -f "$STATE_DIR/$key" ]; then
        cat "$STATE_DIR/$key"
    fi
}

# All known nodes
ALL_NODES="bdk-alice bdk-bob bdk-charlie"

build_node_mapping() {
    log_info "Building node ID mapping..."

    for container in $ALL_NODES; do
        local info_output=$(run_bdk_cmd "$container" info 2>&1)
        local node_id=$(echo "$info_output" | grep "Node ID:" | awk '{print $3}')

        if [ -n "$node_id" ]; then
            # Store mapping: node_id -> container
            store_value "node_$node_id" "$container"
            # Store reverse mapping: container -> node_id
            store_value "id_$container" "$node_id"
            log_info "  $container -> ${node_id:0:16}..."
        fi
    done
}

# Get container name for a node_id
get_container_for_node_id() {
    local node_id=$1
    get_value "node_$node_id"
}

# ============================================================================
# Phase 1: Identify the operator and export ledger
# ============================================================================

export_ledger() {
    local operator_container=$1
    local reserves_id=$2

    log_info ""
    log_info "=== Phase 1: Export Ledger ==="
    echo ""

    log_info "Exporting ledger from $operator_container..."

    # Export writes to current working directory, so we cd to /tmp first
    local export_output
    if [ -n "$reserves_id" ]; then
        export_output=$(docker exec -e RUST_LOG=error "$operator_container" sh -c "cd /tmp && deposits-bdk ledger export '$reserves_id' --json --seed $(get_node_seed $operator_container) --network regtest --esplora http://electrs:3002 --data-dir /data" 2>&1)
    else
        export_output=$(docker exec -e RUST_LOG=error "$operator_container" sh -c "cd /tmp && deposits-bdk ledger export --json --seed $(get_node_seed $operator_container) --network regtest --esplora http://electrs:3002 --data-dir /data" 2>&1)
    fi

    # Parse the filename from output
    local export_file=$(echo "$export_output" | grep "Exported ledger to" | awk '{print $4}')

    if [ -z "$export_file" ]; then
        test_fail "Export failed: $export_output"
        return 1
    fi

    # Copy the file from the container's /tmp directory
    docker cp "${operator_container}:/tmp/${export_file}" "$EXPORT_DIR/ledger_export.json"
    EXPORTED_FILE="$EXPORT_DIR/ledger_export.json"

    # Get export stats
    local updates=$(echo "$export_output" | grep "Updates:" | awk '{print $2}')
    local size=$(echo "$export_output" | grep "Size:" | awk '{print $2}')

    test_pass "Exported ledger: $updates updates, $size bytes"
    log_info "  File: $EXPORTED_FILE"

    return 0
}

# ============================================================================
# Phase 2: Discover quorum members using partner list command
# ============================================================================

get_quorum_members() {
    local operator_container=$1

    log_info ""
    log_info "=== Phase 2: Discover Quorum Members ==="
    echo ""

    # Use partner list command to get quorum members
    local partner_output=$(run_bdk_cmd "$operator_container" partner list 2>&1)

    QUORUM_MEMBERS=""

    if echo "$partner_output" | grep -q "No quorum members"; then
        log_warn "No quorum members found"
        log_info "This is a single-operator ledger"
        return 0
    fi

    # Parse the output to extract pubkeys (format: "  <pubkey> - <role>")
    QUORUM_MEMBERS=$(echo "$partner_output" | grep -E '^\s+[0-9a-f]{66}' | awk '{print $1}' || true)

    # Count and display
    local count=$(echo $QUORUM_MEMBERS | wc -w | tr -d ' ')

    if [ "$count" -gt 0 ]; then
        test_pass "Found $count quorum members"
        for member in $QUORUM_MEMBERS; do
            local container=$(get_container_for_node_id "$member")
            if [ -n "$container" ]; then
                log_info "  ${member:0:16}... -> $container"
            else
                log_info "  ${member:0:16}... -> (unknown node)"
            fi
        done
    else
        log_warn "No quorum members found in ledger"
        log_info "This might be a single-operator ledger"
    fi

    return 0
}

# ============================================================================
# Phase 3: Import ledger on each quorum member
# ============================================================================

import_on_quorum_members() {
    log_info ""
    log_info "=== Phase 3: Import Ledger on Quorum Members ==="
    echo ""

    if [ -z "$QUORUM_MEMBERS" ]; then
        log_info "No quorum members to import to"
        return 0
    fi

    for member_id in $QUORUM_MEMBERS; do
        local container=$(get_container_for_node_id "$member_id")

        if [ -z "$container" ]; then
            log_warn "Unknown container for member ${member_id:0:16}..., skipping"
            continue
        fi

        log_info "Importing on $container..."

        # Copy export file to the container
        local remote_file="/tmp/ledger_import.json"
        docker cp "$EXPORTED_FILE" "${container}:${remote_file}"

        # Run import command
        local import_output=$(run_bdk_cmd "$container" ledger import "$remote_file" 2>&1)

        if echo "$import_output" | grep -q "Import successful"; then
            local sequence=$(echo "$import_output" | grep "Sequence:" | awk '{print $2}')
            local deposits=$(echo "$import_output" | grep "Deposit count:" | awk '{print $3}')
            test_pass "$container imported ledger (seq: $sequence, deposits: $deposits)"
        elif echo "$import_output" | grep -q "already exists"; then
            test_pass "$container already has this ledger"
        else
            test_fail "$container import failed"
            echo "    Output: $(echo "$import_output" | head -5)"
        fi
    done
}

# ============================================================================
# Phase 4: Validate on each quorum member
# ============================================================================

validate_on_quorum_members() {
    log_info ""
    log_info "=== Phase 4: Validate Ledger on Quorum Members ==="
    echo ""

    if [ -z "$QUORUM_MEMBERS" ]; then
        log_info "No quorum members to validate on"
        return 0
    fi

    # Get reserves_id from the export
    local reserves_id
    if command -v jq &> /dev/null; then
        reserves_id=$(jq -r '.reserves_id' "$EXPORTED_FILE" 2>/dev/null)
    else
        reserves_id=$(grep -o '"reserves_id":"[^"]*"' "$EXPORTED_FILE" | \
                      sed 's/"reserves_id":"//g' | sed 's/"//g' | head -1)
    fi

    for member_id in $QUORUM_MEMBERS; do
        local container=$(get_container_for_node_id "$member_id")

        if [ -z "$container" ]; then
            continue
        fi

        log_info "Validating on $container..."

        # Run validate command
        local validate_output=$(run_bdk_cmd "$container" ledger validate "$reserves_id" 2>&1)

        if echo "$validate_output" | grep -q "CONFORMING"; then
            local hash_chain=$(echo "$validate_output" | grep "Hash chain:" | head -1)
            test_pass "$container: Ledger is CONFORMING"
            log_info "    $hash_chain"
        elif echo "$validate_output" | grep -q "NOT CONFORMING"; then
            test_fail "$container: Ledger is NOT CONFORMING"
            echo "$validate_output" | grep -E "FAIL|Warning" | head -5
        else
            test_fail "$container: Validation failed"
            echo "    Output: $(echo "$validate_output" | head -5)"
        fi
    done
}

# ============================================================================
# Phase 5: Also validate on operator (for completeness)
# ============================================================================

validate_on_operator() {
    local operator_container=$1
    local reserves_id=$2

    log_info ""
    log_info "=== Phase 5: Validate on Operator ==="
    echo ""

    log_info "Validating on $operator_container (operator)..."

    local validate_output
    if [ -n "$reserves_id" ]; then
        validate_output=$(run_bdk_cmd "$operator_container" ledger validate "$reserves_id" 2>&1)
    else
        validate_output=$(run_bdk_cmd "$operator_container" ledger validate 2>&1)
    fi

    if echo "$validate_output" | grep -q "CONFORMING"; then
        test_pass "$operator_container (operator): Ledger is CONFORMING"

        # Show summary
        echo ""
        echo "$validate_output" | grep -E "Hash chain:|Signatures:|Business Rules:" | head -10
    else
        test_fail "$operator_container (operator): Validation failed"
        echo "$validate_output" | head -10
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    local reserves_id="${1:-}"
    local operator_container="${2:-bdk-alice}"  # Default to alice as operator

    log_info "=========================================="
    log_info "  Ledger Export/Import/Validate Test"
    log_info "=========================================="
    log_info "Operator: $operator_container"
    if [ -n "$reserves_id" ]; then
        log_info "Reserves ID: ${reserves_id:0:20}..."
    else
        log_info "Reserves ID: (primary ledger)"
    fi
    echo ""

    # Build mapping of node IDs to containers
    build_node_mapping

    # Phase 1: Export
    if ! export_ledger "$operator_container" "$reserves_id"; then
        log_error "Export failed, aborting"
        exit 1
    fi

    # Phase 2: Discover quorum members
    get_quorum_members "$operator_container"

    # Phase 3: Import on quorum members
    import_on_quorum_members

    # Phase 4: Validate on quorum members
    validate_on_quorum_members

    # Phase 5: Validate on operator
    validate_on_operator "$operator_container" "$reserves_id"

    # Summary
    echo ""
    log_info "=========================================="
    log_info "  Test Summary"
    log_info "=========================================="
    echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
    echo ""

    if [ $TESTS_FAILED -gt 0 ]; then
        log_error "Some tests failed"
        exit 1
    else
        log_success "All validation tests passed!"
        exit 0
    fi
}

# Parse command line arguments
RESERVES_ID=""
OPERATOR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --operator)
            OPERATOR="$2"
            shift 2
            ;;
        *)
            RESERVES_ID="$1"
            shift
            ;;
    esac
done

main "$RESERVES_ID" "$OPERATOR"
