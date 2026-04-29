#!/bin/bash
# Adversarial test harness — brings up a configurable Docker environment.
#
# Reads a JSON spec from stdin (or --spec file) and creates the network.
# Outputs a JSON manifest of running nodes with their API endpoints.
#
# Usage:
#   echo '{"operators":["alice","bob"],...}' | ./harness.sh start
#   ./harness.sh --spec spec.json start
#   ./harness.sh stop
#   ./harness.sh status
#
# The harness delegates to deposits-tools infrastructure but with
# configurable parameters instead of hardcoded 4-operator defaults.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TOOLS_DIR="$REPO_ROOT/deposits-tools"
source "$TOOLS_DIR/bin/_common.sh"

# Parse arguments
SPEC_FILE=""
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --spec) SPEC_FILE="$2"; shift 2 ;;
        start|stop|status|fund|balance) COMMAND="$1"; shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# Read spec from file or stdin
read_spec() {
    if [ -n "$SPEC_FILE" ]; then
        cat "$SPEC_FILE"
    else
        cat
    fi
}

case "$COMMAND" in
    start)
        SPEC=$(read_spec)
        OPERATORS=$(echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print(' '.join(o['name'] for o in s['operators']))")
        NUM_OPS=$(echo "$OPERATORS" | wc -w)

        echo "Starting adversarial environment: $NUM_OPS operators ($OPERATORS)"

        # Export node count for _common.sh
        export NODE_COUNT=$NUM_OPS
        init_topology

        # Start infrastructure if not running
        if ! docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass getblockcount >/dev/null 2>&1; then
            echo "Starting infrastructure..."
            $DC up -d bitcoin
            wait_for_bitcoin
            start_all_electrs
            wait_for_all_electrs
            start_all_relays
            wait_for_nostr
            setup_faucet
            $DC up -d miner
        fi

        # Create data dirs and seeds
        for op in $OPERATORS; do
            mkdir -p "$DATA_ROOT/$op"
            if [ ! -f "$DATA_ROOT/$op/seed" ]; then
                openssl rand -hex 32 > "$DATA_ROOT/$op/seed"
            fi
        done

        # Fund operators
        RESERVES=$(echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print(s.get('default_reserves_sats', 100000000))")
        for op in $OPERATORS; do
            SEED=$(cat "$DATA_ROOT/$op/seed")
            ADDR=$(run_node_cmd_raw "$op" address 2>/dev/null | grep -oE 'bcrt1[a-z0-9]+' | head -1)
            if [ -n "$ADDR" ]; then
                FUND_BTC=$(echo "scale=8; ($RESERVES * 3) / 100000000" | bc)
                docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass \
                    sendtoaddress "$ADDR" "$FUND_BTC" 2>/dev/null || true
            fi
        done

        # Mine to confirm
        mine_blocks 6
        sleep 3

        # Start node daemons
        for op in $OPERATORS; do
            start_node "$op"
        done
        sleep 5

        # Create reserves
        for op in $OPERATORS; do
            OP_RESERVES=$(echo "$SPEC" | python3 -c "
import sys,json; s=json.load(sys.stdin)
for o in s['operators']:
    if o['name'] == '$op':
        print(o.get('reserves_sats', s.get('default_reserves_sats', 100000000)))
        break
")
            run_node_cmd "$op" reserves create "$OP_RESERVES" 2>/dev/null || true
        done
        mine_blocks 6
        sleep 3

        # Open ledgers
        for op in $OPERATORS; do
            run_node_cmd "$op" ledger open \
                --annual-fee-bps 50 --annual-fee-fixed-msats 2600000 --fee-period-blocks 2016 \
                2>/dev/null || true
        done
        sleep 2

        # Output manifest
        echo ""
        echo "=== Environment Ready ==="
        echo "{"
        echo "  \"operators\": ["
        FIRST=true
        for op in $OPERATORS; do
            SEED=$(cat "$DATA_ROOT/$op/seed")
            PID=$(cat "$DATA_ROOT/$op/pid" 2>/dev/null || echo "?")
            $FIRST || echo ","
            FIRST=false
            echo -n "    {\"name\":\"$op\",\"pid\":$PID,\"seed\":\"$SEED\"}"
        done
        echo ""
        echo "  ]"
        echo "}"
        ;;

    stop)
        stop_all_nodes 2>/dev/null || true
        ;;

    status)
        init_topology
        for op in $(get_all_node_names 2>/dev/null || echo "alice bob charlie diana"); do
            echo "=== $op ==="
            run_node_cmd "$op" info 2>/dev/null | grep -v '^\[2m' || echo "  (not running)"
        done
        ;;

    fund)
        # Fund a specific operator with additional BTC
        SPEC=$(read_spec)
        OP=$(echo "$SPEC" | python3 -c "import sys,json; print(json.load(sys.stdin)['operator'])")
        AMOUNT=$(echo "$SPEC" | python3 -c "import sys,json; print(json.load(sys.stdin)['amount_btc'])")
        ADDR=$(run_node_cmd "$OP" address 2>/dev/null | grep -oE 'bcrt1[a-z0-9]+' | head -1)
        docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass \
            sendtoaddress "$ADDR" "$AMOUNT" 2>/dev/null
        mine_blocks 6
        ;;

    balance)
        # Output balance sheet for all operators
        init_topology
        echo "{"
        FIRST=true
        for op in $(get_all_node_names 2>/dev/null || echo "alice bob charlie diana"); do
            INFO=$(run_node_cmd "$op" info 2>/dev/null | grep -v '^\[2m') || true
            RESERVES=$(echo "$INFO" | grep -i "reserves" | grep -oE '[0-9]+' | head -1)
            DEPOSITS=$(echo "$INFO" | grep -i "total.*balance\|deposit.*balance" | grep -oE '[0-9]+' | head -1)
            $FIRST || echo ","
            FIRST=false
            echo -n "  \"$op\":{\"reserves_sats\":${RESERVES:-0},\"deposit_balance_sats\":${DEPOSITS:-0}}"
        done
        echo ""
        echo "}"
        ;;

    *)
        echo "Usage: $0 [--spec file.json] <start|stop|status|fund|balance>"
        exit 1
        ;;
esac
