#!/bin/bash
# Wrapper for running deposits-node commands inside Docker containers
#
# Usage:
#   ./bin/node.sh <operator> <command> [args...]
#
# Operators: alice, bob, charlie, diana
#
# Examples:
#   ./bin/node.sh alice info
#   ./bin/node.sh alice ledger open 500
#   ./bin/node.sh alice ledger list
#   ./bin/node.sh alice reserves 100000000
#   ./bin/node.sh alice reserves list
#   ./bin/node.sh bob ledger history <ledger_id>
#   ./bin/node.sh charlie partner add <reserves_id> <member_id> <member_ledger>
#
# Environment:
#   RUST_LOG  - Log level override (default: error)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <operator> <command> [args...]"
    echo ""
    echo "Operators: alice, bob, charlie, diana"
    echo ""
    echo "Examples:"
    echo "  $0 alice info"
    echo "  $0 alice ledger open 500"
    echo "  $0 alice ledger list"
    echo "  $0 alice reserves 100000000"
    echo "  $0 alice reserves list"
    echo "  $0 bob ledger history <ledger_id>"
    exit 1
fi

OP="$1"
shift

CONTAINER="$OP"

# Verify it's a known operator
SEED=$(get_node_seed "$CONTAINER" 2>/dev/null)
if [ -z "$SEED" ]; then
    echo "Unknown operator: $OP"
    echo "Valid operators: alice, bob, charlie, diana"
    exit 1
fi

LOG_LEVEL="${RUST_LOG:-error}"

run_node_cmd "$CONTAINER" "$@"
