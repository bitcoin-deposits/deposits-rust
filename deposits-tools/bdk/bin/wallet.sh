#!/bin/bash
# Wrapper for deposits-wallet CLI
#
# Usage:
#   ./bin/wallet.sh discover                    Find available ledgers
#   ./bin/wallet.sh info <ledger_id>            Get ledger details
#   ./bin/wallet.sh open <ledger_id> <sats>     Open a new deposit
#   ./bin/wallet.sh offer <alias> <sats>        Add funds to existing deposit
#   ./bin/wallet.sh balance                     Show all balances
#   ./bin/wallet.sh withdraw <alias> <amt>      Withdraw from a deposit
#   ./bin/wallet.sh list                        List deposits with aliases
#
# Environment:
#   WALLET_SEED     - 32-byte hex seed (optional, generates if missing)
#   WALLET_RELAY    - Nostr relay URL (default: ws://localhost:7777)
#   WALLET_NETWORK  - Network: bitcoin, testnet, signet, regtest (default: regtest)
#   WALLET_DATA_DIR - Data directory (default: ~/.deposits-wallet)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BDK_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$BDK_DIR")")"

# Default configuration
RELAY="${WALLET_RELAY:-ws://localhost:7777}"
NETWORK="${WALLET_NETWORK:-regtest}"
DATA_DIR="${WALLET_DATA_DIR:-$HOME/.deposits-wallet}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_usage() {
    echo "Deposits Wallet - Nostr-based custody wallet"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  discover                    Find available ledgers on the network"
    echo "  info <ledger_id>            Get details about a specific ledger"
    echo "  open <ledger_id> <sats>     Open a new deposit on a ledger"
    echo "  offer <alias> <sats>        Add funds to an existing deposit"
    echo "  balance                     Show balances across all deposits"
    echo "  withdraw <alias> <amt>      Withdraw from a deposit"
    echo "  list                        List all your deposits with aliases"
    echo ""
    echo "Options:"
    echo "  --relay <url>       Nostr relay URL (default: $RELAY)"
    echo "  --network <net>     Network (default: $NETWORK)"
    echo "  --seed <hex>        Wallet seed (32 bytes hex)"
    echo "  --alias <name>      Local alias for deposit (for open command)"
    echo ""
    echo "Environment Variables:"
    echo "  WALLET_RELAY        Default relay URL"
    echo "  WALLET_NETWORK      Default network"
    echo "  WALLET_SEED         Wallet seed (hex)"
    echo "  WALLET_DATA_DIR     Data directory (default: ~/.deposits-wallet)"
    echo ""
    echo "Examples:"
    echo "  $0 discover"
    echo "  $0 open abc123... 100000 --alias savings"
    echo "  $0 offer savings 50000"
    echo "  $0 withdraw savings 25000 --to bc1q..."
    echo "  $0 balance"
}

# Check if deposits-wallet binary exists, build if needed
ensure_binary() {
    local binary="$REPO_ROOT/target/release/deposits-wallet"

    if [ ! -f "$binary" ]; then
        echo -e "${BLUE}Building deposits-wallet...${NC}"
        cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p deposits-bdk --bin deposits-wallet 2>&1 | tail -5
        echo ""
    fi

    echo "$binary"
}

# Main
if [ $# -eq 0 ]; then
    print_usage
    exit 0
fi

case "$1" in
    -h|--help|help)
        print_usage
        exit 0
        ;;
esac

# Build args array
ARGS=("$@")

# Add default relay and network if not specified in args
if ! printf '%s\n' "${ARGS[@]}" | grep -q -- '--relay'; then
    ARGS+=("--relay" "$RELAY")
fi

if ! printf '%s\n' "${ARGS[@]}" | grep -q -- '--network'; then
    ARGS+=("--network" "$NETWORK")
fi

if ! printf '%s\n' "${ARGS[@]}" | grep -q -- '--data-dir'; then
    ARGS+=("--data-dir" "$DATA_DIR")
fi

# Add seed if set in environment
if [ -n "$WALLET_SEED" ] && ! printf '%s\n' "${ARGS[@]}" | grep -q -- '--seed'; then
    ARGS+=("--seed" "$WALLET_SEED")
fi

BINARY=$(ensure_binary)
exec "$BINARY" "${ARGS[@]}"
