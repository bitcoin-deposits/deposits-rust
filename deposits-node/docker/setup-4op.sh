#!/bin/bash
# Initialize a 4-operator deposits network in Docker.
#
# Prerequisites:
#   - All containers running (alice, bob, charlie, diana, electrs, bitcoind)
#   - Each node's wallet funded with BTC (for reserves)
#
# This script:
#   1. Creates reserves for each operator
#   2. Opens a ledger for each operator
#   3. Sets up quorum (each operator adds the others as members)
#   4. Establishes collateral between operators
#
# Usage:
#   ./setup-4op.sh                     # Full setup
#   ./setup-4op.sh --reserves-only     # Just create reserves
#   ./setup-4op.sh --skip-reserves     # Skip reserves (already created)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/node-cli.sh"

NODES=(alice bob charlie diana)
RESERVES_SATS="${RESERVES_SATS:-100000000}"  # 1 BTC default

# Parse args
RESERVES_ONLY=false
SKIP_RESERVES=false
for arg in "$@"; do
    case "$arg" in
        --reserves-only) RESERVES_ONLY=true ;;
        --skip-reserves) SKIP_RESERVES=true ;;
    esac
done

echo "=== Deposits 4-Operator Setup ==="
echo "  Nodes: ${NODES[*]}"
echo "  Reserves: $RESERVES_SATS sats each"
echo ""

# Step 1: Show funding addresses
echo "=== Step 1: Funding addresses ==="
echo ""
echo "Each node needs at least $RESERVES_SATS sats for reserves + fees."
echo ""
for name in "${NODES[@]}"; do
    echo "--- $name ---"
    $CLI "$name" address 2>/dev/null || echo "  (node not running?)"
    echo ""
done
echo "Fund these addresses, then re-run with --skip-fund to continue."
echo "To check balances: ./node-cli.sh <name> info"

# Only show addresses unless told to continue
if [ "$1" != "--skip-fund" ] && ! $SKIP_RESERVES; then
    exit 0
fi

if ! $SKIP_RESERVES; then
    echo ""
    echo "=== Step 2: Create reserves ==="
    for name in "${NODES[@]}"; do
        echo ""
        echo "--- $name: Creating reserves ($RESERVES_SATS sats) ---"
        $CLI "$name" reserves create "$RESERVES_SATS" || echo "  (may already exist)"
    done
fi

$RESERVES_ONLY && { echo "Done (reserves only)."; exit 0; }

echo ""
echo "=== Step 3: Open ledgers ==="
for name in "${NODES[@]}"; do
    echo ""
    echo "--- $name: Opening ledger ---"
    $CLI "$name" ledger open \
        --annual-fee-bps 50 \
        --min-fee-sats 100 \
        --fee-period-blocks 2016 \
        || echo "  (may already exist)"
done

echo ""
echo "=== Step 4: Node info ==="
for name in "${NODES[@]}"; do
    echo ""
    echo "--- $name ---"
    $CLI "$name" info 2>/dev/null || true
done

echo ""
echo "=== Next steps ==="
echo ""
echo "  ./node-cli.sh alice quorum begin"
echo "  ./node-cli.sh alice partner add <reserves_id> <member_pubkey> <member_ledger>"
echo "  (repeat for each pair)"
echo ""
echo "See deposits-tools/doc/DEPOSIT_ACCESS_CONTROL.md for access control."
