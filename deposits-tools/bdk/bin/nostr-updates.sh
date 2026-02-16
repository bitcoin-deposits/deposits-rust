#!/bin/bash
# Show ledger updates from Nostr relay
#
# Usage:
#   ./bin/nostr-updates.sh              # List all ledgers
#   ./bin/nostr-updates.sh list         # List all ledgers
#   ./bin/nostr-updates.sh show <id>    # Show updates for specific ledger
#   ./bin/nostr-updates.sh validate <id> # Validate ledger hash chain

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WALLET_BIN="$REPO_ROOT/target/release/deposits-wallet"

# Default relay (can be overridden with --relay)
RELAY_URL="ws://localhost:7778"

# Parse arguments
COMMAND=""
LEDGER_ID=""
COLOR_FLAG=""

print_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "View ledger data from Nostr relay (read-only, no Docker required)."
    echo ""
    echo "Commands:"
    echo "  list              List all ledgers on the relay (default)"
    echo "  show <id>         Show all updates for a specific ledger"
    echo "  validate <id>     Validate ledger hash chain"
    echo ""
    echo "Options:"
    echo "  --relay <url>     Nostr relay URL (default: ws://localhost:7778)"
    echo "  --color-by-pk     Color output by operator pubkey"
    echo "  --color           Alias for --color-by-pk"
    echo ""
    echo "Examples:"
    echo "  $0                           # List all ledgers"
    echo "  $0 list                      # List all ledgers"
    echo "  $0 show 2bd07                # Show updates (supports partial ID)"
    echo "  $0 show 2bd07 --color        # Show with colors by operator"
    echo "  $0 validate 2bd07            # Validate hash chain"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            print_usage
            exit 0
            ;;
        --relay)
            RELAY_URL="$2"
            shift 2
            ;;
        --color-by-pk|--color)
            COLOR_FLAG="--color-by-pk"
            shift
            ;;
        list|ls)
            COMMAND="list"
            shift
            ;;
        show)
            COMMAND="show"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                LEDGER_ID="$1"
                shift
            fi
            ;;
        validate)
            COMMAND="validate"
            shift
            if [[ $# -gt 0 && ! "$1" =~ ^-- ]]; then
                LEDGER_ID="$1"
                shift
            fi
            ;;
        -*)
            echo "Unknown option: $1" >&2
            print_usage
            exit 1
            ;;
        *)
            # If no command yet, treat as ledger ID for show
            if [ -z "$COMMAND" ]; then
                COMMAND="show"
                LEDGER_ID="$1"
            fi
            shift
            ;;
    esac
done

# Default to list if no command
if [ -z "$COMMAND" ]; then
    COMMAND="list"
fi

# Check if wallet binary exists
if [ ! -x "$WALLET_BIN" ]; then
    echo "Error: deposits-wallet not found at $WALLET_BIN" >&2
    echo "Build it with: cargo build --release --bin deposits-wallet" >&2
    exit 1
fi

# Run the appropriate command
case $COMMAND in
    list)
        "$WALLET_BIN" ledger list --relay "$RELAY_URL"
        ;;
    show)
        if [ -z "$LEDGER_ID" ]; then
            echo "Error: show requires a ledger ID" >&2
            echo "Usage: $0 show <ledger_id>" >&2
            exit 1
        fi
        "$WALLET_BIN" ledger show "$LEDGER_ID" --relay "$RELAY_URL" $COLOR_FLAG
        ;;
    validate)
        if [ -z "$LEDGER_ID" ]; then
            echo "Error: validate requires a ledger ID" >&2
            echo "Usage: $0 validate <ledger_id>" >&2
            exit 1
        fi
        "$WALLET_BIN" ledger validate "$LEDGER_ID" --relay "$RELAY_URL"
        ;;
esac
