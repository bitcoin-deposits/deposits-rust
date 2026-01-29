#!/bin/bash
# Show ledger updates, deposits, and deposit offers for BDK nodes
#
# Usage:
#   ./bin/updates.sh              # Show all info for all nodes
#   ./bin/updates.sh alice        # Show info for alice only
#   ./bin/updates.sh --ledgers    # Show only ledger info
#   ./bin/updates.sh --deposits   # Show only deposits
#   ./bin/updates.sh --offers     # Show only deposit offers
#   ./bin/updates.sh --withdrawals # Show only withdrawals

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Parse arguments
SHOW_LEDGERS=true
SHOW_DEPOSITS=true
SHOW_OFFERS=true
SHOW_WITHDRAWALS=true
SPECIFIC_NODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --ledgers|-l)
            SHOW_LEDGERS=true
            SHOW_DEPOSITS=false
            SHOW_OFFERS=false
            SHOW_WITHDRAWALS=false
            shift
            ;;
        --deposits|-d)
            SHOW_LEDGERS=false
            SHOW_DEPOSITS=true
            SHOW_OFFERS=false
            SHOW_WITHDRAWALS=false
            shift
            ;;
        --offers|-o)
            SHOW_LEDGERS=false
            SHOW_DEPOSITS=false
            SHOW_OFFERS=true
            SHOW_WITHDRAWALS=false
            shift
            ;;
        --withdrawals|-w)
            SHOW_LEDGERS=false
            SHOW_DEPOSITS=false
            SHOW_OFFERS=false
            SHOW_WITHDRAWALS=true
            shift
            ;;
        --all|-a)
            SHOW_LEDGERS=true
            SHOW_DEPOSITS=true
            SHOW_OFFERS=true
            SHOW_WITHDRAWALS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [NODE]"
            echo ""
            echo "Show ledger updates, deposits, and offers for BDK nodes."
            echo ""
            echo "NODE can be: alice, bob, charlie (or bdk-alice, bdk-bob, bdk-charlie)"
            echo ""
            echo "Options:"
            echo "  --ledgers, -l      Show only ledger info"
            echo "  --deposits, -d     Show only deposits in ledgers"
            echo "  --offers, -o       Show only deposit offers"
            echo "  --withdrawals, -w  Show only withdrawals"
            echo "  --all, -a          Show all info (default)"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                 # Show all info for all nodes"
            echo "  $0 alice           # Show all info for alice"
            echo "  $0 --ledgers       # Show ledgers for all nodes"
            echo "  $0 --deposits bob  # Show deposits for bob"
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            # Node name
            SPECIFIC_NODE=$1
            shift
            ;;
    esac
done

# Normalize node name
normalize_node() {
    local node=$1
    case "$node" in
        alice|bdk-alice)   echo "bdk-alice" ;;
        bob|bdk-bob)       echo "bdk-bob" ;;
        charlie|bdk-charlie) echo "bdk-charlie" ;;
        diana|bdk-diana)   echo "bdk-diana" ;;
        eve|bdk-eve)       echo "bdk-eve" ;;
        *)                 echo "$node" ;;
    esac
}

# Get nodes to process
if [ -n "$SPECIFIC_NODE" ]; then
    NODES_TO_PROCESS=($(normalize_node "$SPECIFIC_NODE"))
else
    NODES_TO_PROCESS=("bdk-alice" "bdk-bob" "bdk-charlie")
fi

# Show node info header
show_node_header() {
    local node=$1
    local display_name=${node#bdk-}  # Remove bdk- prefix
    display_name=$(echo "$display_name" | sed 's/\b\(.\)/\u\1/')  # Capitalize first letter

    echo ""
    echo "========================================"
    echo "  $display_name"
    echo "========================================"

    # Get node ID
    local info=$(run_bdk_cmd "$node" info 2>&1)
    local node_id=$(echo "$info" | grep "Node ID:" | awk '{print $3}')
    local wallet_balance=$(echo "$info" | grep "Wallet balance:" | awk '{print $3}')
    local reserves_balance=$(echo "$info" | grep "Reserves balance:" | awk '{print $3}')

    if [ -n "$node_id" ]; then
        echo "  Node ID: ${node_id:0:20}..."
        echo "  Wallet:  ${wallet_balance:-0} sats"
        echo "  Reserves: ${reserves_balance:-0} sats"
    else
        echo "  (node not available)"
    fi
    echo ""
}

# Show ledgers for a node
show_ledgers() {
    local node=$1
    echo "--- Ledgers ---"

    local output=$(run_bdk_cmd "$node" ledger list 2>&1)

    if echo "$output" | grep -q "No ledgers found"; then
        echo "  No ledgers"
    elif echo "$output" | grep -q "Ledgers"; then
        # Show ledger details
        echo "$output" | grep -E "Ledger|Operator:|Reserves:|Sequence:|Deposits:|Reserves:|Enforcement" | sed 's/^/  /'

        # For each reserves, show history
        local reservess=$(echo "$output" | grep "Reserves:" | awk '{print $2}')
        for reserves in $reservess; do
            echo ""
            echo "  History for ledger $reserves:"
            local history=$(run_bdk_cmd "$node" ledger history "$reserves" 2>&1)
            if echo "$history" | grep -q "Updates for ledger"; then
                echo "$history" | grep -v "^Updates for ledger" | sed 's/^/    /'
            else
                echo "    (no history)"
            fi
        done
    else
        echo "  (error querying ledgers)"
    fi
    echo ""
}

# Show deposits for a node
show_deposits() {
    local node=$1
    echo "--- Deposits ---"

    # Get list of ledgers first
    local ledger_output=$(run_bdk_cmd "$node" ledger list 2>&1)

    # Extract reserves ids from ledgers where we are operator
    local has_deposits=false

    # Get node's own ID
    local info=$(run_bdk_cmd "$node" info 2>&1)
    local our_id=$(echo "$info" | grep "Node ID:" | awk '{print $3}')

    # For each ledger, try to list deposits
    # This is a simplification - in practice we'd parse the ledger list properly
    for reserves_node in "${NODES[@]}"; do
        if [ "$reserves_node" = "$node" ]; then
            continue
        fi

        local reserves_info=$(run_bdk_cmd "$reserves_node" info 2>&1)
        local reserves_id=$(echo "$reserves_info" | grep "Node ID:" | awk '{print $3}')

        if [ -n "$reserves_id" ]; then
            local deposits_output=$(run_bdk_cmd "$node" deposit ls "$reserves_id" 2>&1)

            if echo "$deposits_output" | grep -q "Deposit:"; then
                local reserves_name=${reserves_node#bdk-}
                echo "  Ledger with $reserves_name:"
                echo "$deposits_output" | grep -E "Deposit:|Balance:|Locked:|Fees:" | sed 's/^/    /'
                has_deposits=true
            fi
        fi
    done

    if [ "$has_deposits" = false ]; then
        echo "  No deposits found"
    fi
    echo ""
}

# Show deposit offers for a node
show_offers() {
    local node=$1
    echo "--- Deposit Offers ---"

    local output=$(run_bdk_cmd "$node" deposit list 2>&1)

    if echo "$output" | grep -q "No deposit offers"; then
        echo "  No deposit offers"
    elif echo "$output" | grep -q "Offer:"; then
        echo "$output" | grep -E "Offer:|Status:|Address:|Amount:|Deadline:|Reserves:|Deposit:" | sed 's/^/  /'
    else
        echo "  (none)"
    fi
    echo ""
}

# Show withdrawals for a node
show_withdrawals() {
    local node=$1
    echo "--- Withdrawals ---"

    local output=$(run_bdk_cmd "$node" withdraw list 2>&1)

    if echo "$output" | grep -q "No withdrawals"; then
        echo "  No withdrawals"
    elif echo "$output" | grep -q "Withdrawal:"; then
        echo "$output" | grep -E "Withdrawal:|Status:|Amount:|Destination:|Fee:" | sed 's/^/  /'
    else
        echo "  (none)"
    fi
    echo ""
}

# Main
echo "BDK Network Status"
echo "=================="
echo "Block height: $(get_block_height 2>/dev/null || echo 'N/A')"

for node in "${NODES_TO_PROCESS[@]}"; do
    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
        echo ""
        echo "========================================"
        echo "  ${node#bdk-} (not running)"
        echo "========================================"
        continue
    fi

    show_node_header "$node"

    if $SHOW_LEDGERS; then
        show_ledgers "$node"
    fi

    if $SHOW_DEPOSITS; then
        show_deposits "$node"
    fi

    if $SHOW_OFFERS; then
        show_offers "$node"
    fi

    if $SHOW_WITHDRAWALS; then
        show_withdrawals "$node"
    fi
done

echo ""
echo "Done."
