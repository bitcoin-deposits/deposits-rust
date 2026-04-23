#!/bin/bash
# Wrapper for deposits-wallet CLI
#
# Usage:
#   ./bin/wallet.sh discover                    Find available ledgers
#   ./bin/wallet.sh info <ledger_id>            Get ledger details
#   ./bin/wallet.sh open <ledger_id>            Create a deposit account (no funding yet)
#   ./bin/wallet.sh offer <alias> <sats>        Request a funding address for an existing deposit
#   ./bin/wallet.sh balance                     Show all balances
#   ./bin/wallet.sh withdraw <alias> <amt>      Withdraw from a deposit
#   ./bin/wallet.sh list                        List deposits with aliases
#
# Regtest helpers (only work against the local docker bitcoind):
#   ./bin/wallet.sh faucet <alias|addr> [sats]  Send from faucet to deposit
#
# Environment:
#   WALLET_SEED     - 32-byte hex seed (optional, generates if missing)
#   WALLET_RELAY    - Nostr relay URL (default: ws://localhost:7777)
#   WALLET_NETWORK  - Network: bitcoin, testnet, signet, regtest (default: regtest)
#   WALLET_DATA_DIR - Data directory (default: ~/.deposits-wallet)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Default configuration
RELAY="${WALLET_RELAY:-ws://localhost:7801}"
NETWORK="${WALLET_NETWORK:-regtest}"
DATA_DIR="${WALLET_DATA_DIR:-$HOME/.deposits-wallet}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    echo "  open <ledger_id>            Create a deposit account (no funding yet)"
    echo "  offer <alias> <sats>        Request a funding address for a deposit"
    echo "  balance                     Show balances across all deposits"
    echo "  sync                        Sync deposit statuses from daemon"
    echo "  withdraw <alias> <amt>      Withdraw from a deposit"
    echo "  list                        List all your deposits with aliases"
    echo ""
    echo "Regtest helpers:"
    echo "  faucet <alias|addr> [sats]  Send from faucet to deposit (local docker)"
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
    echo "  $0 open abc123... --alias savings"
    echo "  $0 offer savings 50000              # returns a funding address"
    echo "  $0 faucet savings                   # regtest: send faucet sats to it"
    echo "  $0 withdraw savings 25000 --to bc1q..."
    echo "  $0 balance"
}

# Send from the regtest faucet to an address or deposit alias
# Note: Bitcoin has a dust limit (~546 sats), so very small amounts will fail
faucet_send() {
    local target="$1"
    local sats="${2:-}"

    if [ -z "$target" ]; then
        echo -e "${RED}Usage: $0 faucet <alias|address> [sats]${NC}"
        exit 1
    fi

    local address="$target"
    local default_sats=10000

    local min_sats=546  # dust limit
    local max_sats=0

    # Check if target is an alias (not starting with bc/tb/bcrt)
    if [[ ! "$target" =~ ^(bc1|tb1|bcrt1) ]]; then
        # Try to look up alias in deposits.json
        local deposits_file="$DATA_DIR/deposits.json"
        if [ -f "$deposits_file" ]; then
            local found_addr=$(jq -r --arg alias "$target" '.[] | select(.alias == $alias) | .funding_address' "$deposits_file" 2>/dev/null)
            local found_min=$(jq -r --arg alias "$target" '.[] | select(.alias == $alias) | .min_sats' "$deposits_file" 2>/dev/null)
            local found_max=$(jq -r --arg alias "$target" '.[] | select(.alias == $alias) | .max_sats' "$deposits_file" 2>/dev/null)

            if [ -n "$found_addr" ] && [ "$found_addr" != "null" ] && [ "$found_addr" != "" ]; then
                address="$found_addr"
                # Get min/max from deposit
                if [ -n "$found_min" ] && [ "$found_min" != "null" ]; then
                    min_sats="$found_min"
                fi
                if [ -n "$found_max" ] && [ "$found_max" != "null" ]; then
                    max_sats="$found_max"
                    default_sats="$found_max"  # default to max if no arg
                fi
                echo -e "${BLUE}Found deposit '$target' (${min_sats}-${max_sats} sats)${NC}"
            else
                echo -e "${RED}No deposit found with alias '$target'${NC}"
                echo "Use './bin/wallet.sh list' to see your deposits"
                exit 1
            fi
        else
            echo -e "${RED}No deposits file found. Is '$target' an address?${NC}"
            exit 1
        fi
    fi

    sats="${sats:-$default_sats}"

    # Clamp sats to min/max range: max(min_sats, min(max_sats, sats))
    if [ "$max_sats" -gt 0 ]; then
        if [ "$sats" -gt "$max_sats" ]; then
            echo -e "${YELLOW}Clamping $sats to max $max_sats${NC}"
            sats="$max_sats"
        fi
        if [ "$sats" -lt "$min_sats" ]; then
            echo -e "${YELLOW}Clamping $sats to min $min_sats${NC}"
            sats="$min_sats"
        fi
    fi

    # Convert sats to BTC
    local btc=$(awk "BEGIN {printf \"%.8f\", $sats / 100000000}")

    echo -e "${BLUE}Funding address from faucet...${NC}"
    echo "  Address: $address"
    echo "  Amount: $sats sats ($btc BTC)"
    echo ""

    # Send from faucet (bitcoind still runs in Docker)
    local txid=$(docker exec bitcoind bitcoin-cli -regtest \
        -rpcuser=user -rpcpassword=pass \
        -rpcwallet=faucet sendtoaddress "$address" "$btc" 2>&1)

    if [[ "$txid" =~ ^[a-f0-9]{64}$ ]]; then
        echo -e "${GREEN}Sent!${NC} TXID: ${txid:0:16}..."

        # Mine a block to confirm
        echo -e "${BLUE}Mining block to confirm...${NC}"
        docker exec bitcoind bitcoin-cli -regtest \
            -rpcuser=user -rpcpassword=pass \
            -rpcwallet=faucet -generate 1 >/dev/null 2>&1

        echo -e "${GREEN}Done!${NC} Deposit should be credited automatically."
        echo ""
        echo "Check with: $0 balance"
    else
        echo -e "${RED}Failed to send:${NC} $txid"
        exit 1
    fi
}

# List all deposits from local storage
list_deposits() {
    local deposits_file="$DATA_DIR/deposits.json"

    if [ ! -f "$deposits_file" ]; then
        echo "No deposits found."
        echo ""
        echo "Create one with:"
        echo "  $0 open <ledger_id> [sats] --alias <name>"
        return
    fi

    local count=$(jq 'length' "$deposits_file" 2>/dev/null)
    if [ "$count" = "0" ] || [ -z "$count" ]; then
        echo "No deposits found."
        return
    fi

    echo "Your Deposits ($count)"
    echo "============="
    echo ""

    # Parse and display each deposit
    jq -r '.[] | "\(.alias)|\(.min_sats // .amount_sats)|\(.max_sats // .amount_sats)|\(.status)|\(.funding_address)|\(.ledger_id)"' "$deposits_file" 2>/dev/null | while IFS='|' read -r alias min_sats max_sats status addr ledger; do
        echo -e "${GREEN}$alias${NC}"
        if [ "$min_sats" = "$max_sats" ]; then
            echo "  Amount: $max_sats sats"
        else
            echo "  Amount: $min_sats-$max_sats sats"
        fi
        echo "  Status: $status"
        if [ -n "$addr" ] && [ "$addr" != "null" ]; then
            echo "  Address: ${addr:0:20}...${addr: -8}"
        fi
        echo "  Ledger: ${ledger:0:16}..."
        echo ""
    done

    echo "Commands:"
    echo "  faucet <alias>            Send from faucet to deposit"
    echo "  balance                   Check all balances"
}

# Check if deposits-wallet binary exists, build if needed
ensure_binary() {
    local binary="$REPO_ROOT/target/release/deposits-wallet"

    if [ ! -f "$binary" ]; then
        echo -e "${BLUE}Building deposits-wallet...${NC}"
        cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p.deposits-node --bin deposits-wallet 2>&1 | tail -5
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
    faucet)
        faucet_send "$2" "$3"
        exit 0
        ;;
    # list command now uses deposits-wallet binary
    # list|ls)
    #     list_deposits
    #     exit 0
    #     ;;
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
