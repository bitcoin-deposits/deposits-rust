#!/bin/bash
# Show transactions
#
# Usage:
#   ./bin/txns.sh              # Show all non-coinbase txns
#   ./bin/txns.sh <BLOCK>      # Show txns for specific block
#   ./bin/txns.sh --all        # Include coinbase txns

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELECTRS_URL="http://localhost:3102"

SHOW_COINBASE=false
SPECIFIC_BLOCK=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --all|-a)
            SHOW_COINBASE=true
            shift
            ;;
        *)
            SPECIFIC_BLOCK=$1
            shift
            ;;
    esac
done

# Get all input addresses for a transaction
get_input_addresses() {
    local tx_json=$1
    # For each input, fetch the previous transaction and get the address
    echo "$tx_json" | jq -r '.vin[] | select(.prevout) | .prevout.scriptpubkey_address' 2>/dev/null | sort -u
}

# Format a transaction for display
format_tx() {
    local txid=$1
    local block_height=$2
    local TX=$(curl -s "$ELECTRS_URL/tx/$txid")

    # Check if coinbase
    IS_COINBASE=$(echo "$TX" | jq -r '.vin[0].is_coinbase')

    if [ "$IS_COINBASE" = "true" ]; then
        if [ "$SHOW_COINBASE" = "true" ]; then
            VALUE=$(echo "$TX" | jq -r '.vout[0].value')
            echo "  $block_height  [coinbase]    ${txid:0:12}...  +${VALUE} sats"
        fi
        return
    fi

    FEE=$(echo "$TX" | jq -r '.fee')

    # Get input addresses to identify change vs payment
    INPUT_ADDRS=$(get_input_addresses "$TX")

    # Check for OP_RETURN (withdrawal transaction)
    OP_RETURN=$(echo "$TX" | jq -r '.vout[] | select(.scriptpubkey_type == "op_return") | .scriptpubkey_asm' | head -1)

    if [ -n "$OP_RETURN" ]; then
        # Extract WDRL data
        if echo "$OP_RETURN" | grep -q "5744524c"; then
            WDRL_ID=$(echo "$OP_RETURN" | sed 's/.*5744524c3a//' | cut -c1-8)

            # For withdrawals with HD wallets, the change goes to a fresh address (not in inputs).
            # So both payment and change appear as "not in input addresses".
            # Heuristic: the SMALLER non-input output is the withdrawal (users typically withdraw less than their balance).
            # Get all p2wpkh/p2tr outputs with addresses not in inputs, sorted by value
            OUTPUTS=$(echo "$TX" | jq -r '.vout[] | select(.scriptpubkey_type == "v0_p2wpkh" or .scriptpubkey_type == "v1_p2tr") | "\(.value) \(.scriptpubkey_address)"' | sort -n)

            # Find payment output (smallest non-input address - likely the withdrawal, not change)
            DEST=""
            AMT=""
            while read -r val addr; do
                if [ -n "$addr" ] && ! echo "$INPUT_ADDRS" | grep -q "$addr"; then
                    DEST="$addr"
                    AMT="$val"
                    break  # Take smallest (first after sort)
                fi
            done <<< "$OUTPUTS"

            # Fallback if we couldn't identify
            if [ -z "$DEST" ]; then
                DEST=$(echo "$TX" | jq -r '.vout[] | select(.scriptpubkey_type == "v0_p2wpkh") | .scriptpubkey_address' | head -1)
                AMT=$(echo "$TX" | jq -r '.vout[] | select(.scriptpubkey_type == "v0_p2wpkh") | .value' | head -1)
            fi

            echo "  $block_height  [withdrawal]  ${txid:0:12}...  wdrl:$WDRL_ID  ${AMT} sats → ${DEST:0:10}..${DEST: -6}"
        else
            echo "  $block_height  [op_return]   ${txid:0:12}...  fee:$FEE"
        fi
    else
        # Regular transaction - find payment output (not change)
        # For HD wallets, change goes to a fresh address (not in inputs), so both payment and change
        # appear as "not in input addresses". Use heuristic: smaller output is likely the payment.
        OUTPUTS=$(echo "$TX" | jq -r '.vout[] | select(.scriptpubkey_address) | "\(.value) \(.scriptpubkey_address)"' | sort -n)

        # Find payment output (smallest non-input address - likely the payment, not change)
        DEST=""
        AMT=""
        while read -r val addr; do
            if [ -n "$addr" ] && ! echo "$INPUT_ADDRS" | grep -q "$addr"; then
                DEST="$addr"
                AMT="$val"
                break  # Take smallest (first after sort)
            fi
        done <<< "$OUTPUTS"

        # If all outputs go back to input addresses, it's a consolidation
        if [ -z "$DEST" ]; then
            TOTAL_OUT=$(echo "$TX" | jq '[.vout[].value] | add')
            echo "  $block_height  [consolidate] ${txid:0:12}...  ${TOTAL_OUT} sats (self-transfer)"
        else
            echo "  $block_height  [transfer]    ${txid:0:12}...  ${AMT} sats → ${DEST:0:10}..${DEST: -6}"
        fi
    fi
}

export -f format_tx get_input_addresses
export ELECTRS_URL SHOW_COINBASE

# Collect txids for a single block
collect_block_txids() {
    local HEIGHT=$1
    HASH=$(curl -s "$ELECTRS_URL/block-height/$HEIGHT" 2>/dev/null)
    if [ -n "$HASH" ] && [ "$HASH" != "Block not found" ]; then
        curl -s "$ELECTRS_URL/block/$HASH/txids" 2>/dev/null | jq -r ".[]" 2>/dev/null | while read txid; do
            echo "$HEIGHT $txid"
        done
    fi
}
export -f collect_block_txids

if [ -n "$SPECIFIC_BLOCK" ]; then
    # Show single block
    HEIGHT=$SPECIFIC_BLOCK
    HASH=$(curl -s "$ELECTRS_URL/block-height/$HEIGHT")
    echo "=== Block $HEIGHT ==="
    echo ""

    curl -s "$ELECTRS_URL/block/$HASH/txids" | jq -r '.[]' | while read txid; do
        echo "$HEIGHT $txid"
    done | xargs -P 8 -L 1 bash -c 'format_tx "$2" "$1"' _ | sort -n
else
    # Show all non-coinbase transactions across all blocks (after initial mining)
    TIP=$(curl -s "$ELECTRS_URL/blocks/tip/height")
    START=101  # Start after initial mining blocks

    echo "=== Transactions (blocks $START-$TIP) ==="
    echo ""

    # Collect txids in parallel, then process in parallel
    seq $START $TIP | xargs -P 16 -I {} bash -c 'collect_block_txids {}' | xargs -P 16 -L 1 bash -c 'format_tx "$2" "$1"' _ | sort -n
fi
