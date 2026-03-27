#!/bin/bash
# Open a deposit on a ledger as a customer.
#
# Usage:
#   ./open-deposit.sh <ledger_id> <amount_sats> [--relay wss://...]
#
# This script:
#   1. Discovers the ledger from relay advertisements
#   2. Generates a deposit keypair
#   3. Opens the deposit via Nostr
#   4. Creates a lightning invoice to fund it
#   5. Prints the invoice for payment
#
# Environment:
#   DEPOSITS_SEED_DIR    - path to seed files (default: /mnt/bitcoind/deposits)
#   DEPOSITS_NETWORK     - bitcoin/testnet/regtest (default: bitcoin)
#   DEPOSITS_LEDGER_RELAY - relay URL (default: wss://relay.ynniv.com)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/node-cli.sh"

# Parse args
LEDGER_ID=""
AMOUNT_SATS=""
NODE_NAME="${DEPOSITS_OPEN_VIA:-alice}"  # which node to route through

for arg in "$@"; do
    case "$arg" in
        --via=*) NODE_NAME="${arg#--via=}" ;;
        --*) ;; # skip flags
        *)
            if [ -z "$LEDGER_ID" ]; then
                LEDGER_ID="$arg"
            elif [ -z "$AMOUNT_SATS" ]; then
                AMOUNT_SATS="$arg"
            fi
            ;;
    esac
done

if [ -z "$LEDGER_ID" ] || [ -z "$AMOUNT_SATS" ]; then
    echo "Usage: $0 <ledger_id> <amount_sats> [--via=<node>]"
    echo ""
    echo "Discover ledgers first:"
    echo "  $SCRIPT_DIR/discover.sh"
    exit 1
fi

echo "=== Opening deposit ==="
echo "  Ledger: ${LEDGER_ID:0:16}..."
echo "  Amount: $AMOUNT_SATS sats"
echo "  Via:    $NODE_NAME"
echo ""

# 1. Derive a deposit key (use next available index)
#    Find the highest used index from the wallet's deposits.json
WALLET_DIR="/mnt/bitcoind/deposits/$NODE_NAME/data/node/wallet"
NEXT_INDEX=0
if [ -f "$WALLET_DIR/deposits.json" ]; then
    NEXT_INDEX=$(python3 -c "
import json
try:
    deps = json.load(open('$WALLET_DIR/deposits.json'))
    indices = [d.get('key_index', 0) for d in deps]
    print(max(indices) + 1 if indices else 0)
except:
    print(0)
" 2>/dev/null || echo "0")
fi

echo "Deriving deposit key (index $NEXT_INDEX)..."
KEY_OUTPUT=$($CLI "$NODE_NAME" derive-deposit-key --index "$NEXT_INDEX" 2>&1)
PUBKEY=$(echo "$KEY_OUTPUT" | grep "^pubkey:" | awk '{print $2}')
SECRET=$(echo "$KEY_OUTPUT" | grep -v "^pubkey:" | grep -v INFO | head -1)

if [ -z "$PUBKEY" ]; then
    echo "ERROR: Failed to derive deposit key"
    echo "$KEY_OUTPUT"
    exit 1
fi
echo "  Pubkey: $PUBKEY"
echo ""

# 2. Open the deposit
echo "Opening deposit on ledger..."
OPEN_OUTPUT=$($CLI "$NODE_NAME" deposit open "$LEDGER_ID" "$PUBKEY" 2>&1 | grep -v INFO)
echo "$OPEN_OUTPUT"

if echo "$OPEN_OUTPUT" | grep -qi "error"; then
    exit 1
fi
echo ""

# 3. Create invoice to fund it
echo "Creating lightning invoice for $AMOUNT_SATS sats..."

# Find which node operates this ledger (check each node)
OPERATOR_NODE=""
for name in alice bob charlie diana; do
    LEDGERS=$($CLI "$name" ledger list 2>&1 | grep -v INFO || true)
    if echo "$LEDGERS" | grep -q "${LEDGER_ID:0:16}"; then
        OPERATOR_NODE="$name"
        break
    fi
done

if [ -z "$OPERATOR_NODE" ]; then
    echo "WARNING: Could not find which node operates this ledger."
    echo "Create invoice manually:"
    echo "  ./node-cli.sh <operator> deposit invoice $LEDGER_ID $PUBKEY $AMOUNT_SATS"
    exit 0
fi

echo "  Operator: $OPERATOR_NODE"
INVOICE=$($CLI "$OPERATOR_NODE" deposit invoice "$LEDGER_ID" "$PUBKEY" "$AMOUNT_SATS" 2>&1 | grep -v INFO | grep "^lnbc")

if [ -z "$INVOICE" ]; then
    echo "ERROR: Failed to create invoice"
    $CLI "$OPERATOR_NODE" deposit invoice "$LEDGER_ID" "$PUBKEY" "$AMOUNT_SATS" 2>&1
    exit 1
fi

echo ""
echo "=== Pay this invoice to fund the deposit ==="
echo ""
echo "$INVOICE"
echo ""
echo "After payment, check status with:"
echo "  $CLI $OPERATOR_NODE deposit ls $LEDGER_ID"
