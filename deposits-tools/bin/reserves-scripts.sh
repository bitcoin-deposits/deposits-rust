#!/bin/bash
# Show reserves UTXO scripts
#
# Displays the full Taproot script details for all reserves outputs.
#
# Usage:
#   ./bin/reserves-scripts.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

ELECTRS_URL="http://localhost:3102"
OPERATORS="alice bob charlie"

echo ""
echo "=== Reserves UTXO Scripts ==="
echo ""

for op in $OPERATORS; do
    op_short="$op"

    echo "[$op_short]"

    # Get full reserves list output (includes script details)
    run_bdk_cmd "$op" reserves list 2>&1 | grep -v "^\[2m" | grep -v "^$"

    echo ""
    echo "---"
    echo ""
done
