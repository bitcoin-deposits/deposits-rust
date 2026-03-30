#!/bin/bash
# Replay a ledger chain and pretty-print state
# Wrapper for the replay-ledger binary
#
# With no arguments (or no matching prefix), lists available ledgers.
#
# Examples:
#   ./bin/replay-ledger.sh                            # List local ledgers
#   ./bin/replay-ledger.sh 183c                       # Replay by prefix
#   ./bin/replay-ledger.sh --relay ws://localhost:7779 # List ledgers on relay
#   ./bin/replay-ledger.sh 183c --relay ws://localhost:7779  # Prefix match on relay

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"

# Default --data-root to deposits-tools/data if not specified
if [[ ! " $* " =~ " --data-root " ]] && [[ ! " $* " =~ " -d " ]] && [[ ! " $* " =~ " --relay " ]] && [[ ! " $* " =~ " -r " ]]; then
    exec "$REPO_ROOT/target/release/replay-ledger" --data-root "$TOOLS_DIR/data" "$@"
else
    exec "$REPO_ROOT/target/release/replay-ledger" "$@"
fi
