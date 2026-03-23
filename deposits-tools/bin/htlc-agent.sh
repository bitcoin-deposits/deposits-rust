#!/bin/bash
# HTLC Agent CLI wrapper
#
# Usage:
#   ./bin/htlc-agent.sh status
#   ./bin/htlc-agent.sh deposits
#   ./bin/htlc-agent.sh routes
#   ./bin/htlc-agent.sh status --api-port 3201

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

HTLC_AGENT="${HTLC_AGENT:-$REPO_ROOT/target/release/htlc-agent}"

if [ ! -x "$HTLC_AGENT" ]; then
    echo "htlc-agent not found at $HTLC_AGENT — build with: cargo build --release -p deposits-node --bin htlc-agent" >&2
    exit 1
fi

exec "$HTLC_AGENT" "$@"
