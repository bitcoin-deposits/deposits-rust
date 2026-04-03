#!/bin/bash
# Start the LNURL-pay gateway for deposits.
#
# Connects to all operator relays and serves LNURL-pay endpoints that
# create invoices for any deposit on any ledger.
#
# Usage:
#   ./bin/setup-lnurl.sh
#   ./bin/setup-lnurl.sh --port 3000 --domain deposits.example.com
#
# The service uses its own Nostr key (not an operator key).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

LNURL_BIN="${LNURL_BIN:-$REPO_ROOT/target/release/deposits-lnurl}"
LNURL_SEED="4c4e55524c7061790000000000000000000000000000000000000000000000ff"
LNURL_PORT="${LNURL_PORT:-3000}"
LNURL_DOMAIN="${LNURL_DOMAIN:-localhost:$LNURL_PORT}"
LNURL_DATA_DIR="$DATA_ROOT/lnurl"

while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            LNURL_PORT="$2"
            LNURL_DOMAIN="${LNURL_DOMAIN:-localhost:$LNURL_PORT}"
            shift 2
            ;;
        --domain)
            LNURL_DOMAIN="$2"
            shift 2
            ;;
        --seed)
            LNURL_SEED="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

mkdir -p "$LNURL_DATA_DIR"

# Build relay list from all operator relays + ledger relay
RELAY_LIST=""
for r in "${ALL_RELAYS[@]}"; do
    [ -n "$RELAY_LIST" ] && RELAY_LIST="$RELAY_LIST,"
    RELAY_LIST="$RELAY_LIST$r"
done
[ -n "$RELAY_LEDGERS" ] && RELAY_LIST="$RELAY_LIST,$RELAY_LEDGERS"

# Stop existing
if [ -f "$LNURL_DATA_DIR/lnurl.pid" ]; then
    old_pid=$(cat "$LNURL_DATA_DIR/lnurl.pid")
    kill "$old_pid" 2>/dev/null || true
    sleep 1
fi

log_info "Starting deposits-lnurl gateway..."
log_info "  Domain: $LNURL_DOMAIN"
log_info "  Listen: 0.0.0.0:$LNURL_PORT"
log_info "  Relays: $RELAY_LIST"

LNURL_NSEC="$LNURL_SEED" \
LNURL_RELAYS="$RELAY_LIST" \
LNURL_DOMAIN="$LNURL_DOMAIN" \
LNURL_LISTEN="0.0.0.0:$LNURL_PORT" \
RUST_LOG=info \
"$LNURL_BIN" > "$LNURL_DATA_DIR/lnurl.log" 2>&1 &

pid=$!
echo "$pid" > "$LNURL_DATA_DIR/lnurl.pid"
log_success "deposits-lnurl started (pid $pid)"
log_info "  Lightning address format: <ledger_id>-<deposit_pubkey>@$LNURL_DOMAIN"
log_info "  Log: $LNURL_DATA_DIR/lnurl.log"
