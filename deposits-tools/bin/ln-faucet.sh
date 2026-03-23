#!/bin/bash
# Lightning faucet — pays a BOLT11 invoice via the shared LDK node
#
# Uses the self-pay wrapper, so invoices created on the same node settle
# internally without needing to route through Lightning.
#
# Usage:
#   ./bin/ln-faucet.sh <bolt11_invoice>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

INVOICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --from)
            shift 2  # ignored — all operators share one node now
            ;;
        --help|-h)
            echo "Usage: $0 <bolt11_invoice>"
            echo "  Pays the invoice via the shared LDK node + self-pay wrapper."
            exit 0
            ;;
        *)
            INVOICE="$1"
            shift
            ;;
    esac
done

if [ -z "$INVOICE" ]; then
    echo "Usage: $0 <bolt11_invoice>"
    exit 1
fi

# Set up wrapper env
LDK_REAL_CLI="${LDK_SERVER_CLI:-$HOME/ldk-server/target/release/ldk-server-cli}"
NETWORK=$(docker exec lightning printenv NETWORK 2>/dev/null || echo "regtest")
API_KEY=$(docker exec lightning sh -c "cat /ldk/${NETWORK}/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null)

export LDK_REAL_CLI
export LDK_HOST="localhost"
export LDK_PORT="3111"
export LDK_API_KEY="$API_KEY"
export LDK_TLS_CERT="$TOOLS_DIR/certs/lightning.crt"
export LDK_SELF_PAY_DIR="${DATA_ROOT}/self-pay"

echo "Paying invoice..."
result=$("$SCRIPT_DIR/ldk-cli-wrapper.sh" bolt11-send --invoice "$INVOICE" 2>&1)

payment_id=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('payment_id',''))" 2>/dev/null || echo "")
if [ -n "$payment_id" ]; then
    echo "Paid! ID: ${payment_id:0:32}..."
else
    echo "$result"
    exit 1
fi
