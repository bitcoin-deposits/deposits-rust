#!/bin/bash
# Replay a ledger chain and pretty-print state
# Wrapper for the replay-ledger binary

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"

# Default --data-root to deposits-tools/data if not specified
if [[ ! " $* " =~ " --data-root " ]] && [[ ! " $* " =~ " -d " ]] && [[ ! " $* " =~ " --relay " ]] && [[ ! " $* " =~ " -r " ]]; then
    exec "$REPO_ROOT/target/release/replay-ledger" --data-root "$TOOLS_DIR/data" "$@"
else
    exec "$REPO_ROOT/target/release/replay-ledger" "$@"
fi
