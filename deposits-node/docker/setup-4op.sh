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
echo "=== Step 1: Fund node wallets ==="
for name in "${NODES[@]}"; do
    echo ""
    echo "--- $name ---"
    $CLI "$name" address || true
done
echo ""
echo "Send at least $RESERVES_SATS sats to each address above."
echo "Press Enter when funded (or Ctrl+C to abort)..."
read -r

if ! $SKIP_RESERVES; then
    # Step 2: Create reserves
    echo ""
    echo "=== Step 2: Create reserves ==="
    for name in "${NODES[@]}"; do
        echo ""
        echo "--- $name: Creating reserves ($RESERVES_SATS sats) ---"
        $CLI "$name" reserves create "$RESERVES_SATS" || echo "  (may already exist)"
    done
fi

$RESERVES_ONLY && { echo "Done (reserves only)."; exit 0; }

# Step 3: Open ledgers
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

# Step 4: Show info for quorum setup
echo ""
echo "=== Step 4: Node info ==="
for name in "${NODES[@]}"; do
    echo ""
    echo "--- $name ---"
    $CLI "$name" info || true
done

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Note each node's reserves_id and operator pubkey from the info above"
echo "  2. Set up quorum: ./node-cli.sh alice quorum begin"
echo "  3. Add members:   ./node-cli.sh alice partner add <reserves_id> <member_pubkey> <member_ledger>"
echo "  4. Lock collateral between operators"
echo ""
echo "See deposits-tools/doc/DEPOSIT_ACCESS_CONTROL.md for access control setup."
