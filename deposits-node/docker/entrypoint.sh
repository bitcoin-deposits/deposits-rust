#!/bin/sh
set -e

# --- deposits-node standalone container ---
#
# Runs deposits-node + a bundled strfry relay in a single container.
#
# Required env:
#   NODE_SEED or NODE_SEED_FILE      - BIP39 seed phrase for the operator
#   NETWORK                          - bitcoin, testnet, signet, regtest
#   ELECTRUM_URL                     - esplora/electrs URL
#   LEDGER_RELAY                     - durable relay for advertisements + ledger updates
#
# Optional env:
#   EPHEMERAL_RELAYS                 - comma-separated additional relay URLs
#   ATTESTATION_VERIFIER_PUBKEY      - hex pubkey of lightning-verify service
#   DEPOSIT_ACCESS_CONTROL           - true to enable allowlisting
#   MAX_DEPOSIT_BALANCE_MSATS        - per-deposit balance cap
#   RELAY_PORT                       - local relay port (default: 7777)
#   METRICS_PORT                     - prometheus metrics port (default: 9100)
#   NODE_NAME                        - operator name for advertisements
#
# Volumes:
#   /data                            - persistent node data + relay DB
#   /config/deposit_allowlist.txt    - optional npub allowlist
#   /config/deposit_denylist.txt     - optional npub denylist
#   /config/deposit_domain_allowlist.txt - optional domain allowlist

DATA_DIR="/data/node"
RELAY_DIR="/data/relay"
RELAY_PORT="${RELAY_PORT:-7777}"
METRICS_PORT="${METRICS_PORT:-9100}"

mkdir -p "$DATA_DIR" "$RELAY_DIR"

# Copy access control files into node data dir if provided
for f in deposit_allowlist.txt deposit_denylist.txt deposit_domain_allowlist.txt; do
    if [ -f "/config/$f" ]; then
        cp "/config/$f" "$DATA_DIR/$f"
    fi
done

# Read seed from file if specified
if [ -n "$NODE_SEED_FILE" ] && [ -f "$NODE_SEED_FILE" ]; then
    NODE_SEED=$(cat "$NODE_SEED_FILE" | tr -d '\n')
fi

if [ -z "$NODE_SEED" ]; then
    echo "ERROR: NODE_SEED or NODE_SEED_FILE required"
    exit 1
fi

if [ -z "$NETWORK" ]; then
    echo "ERROR: NETWORK required (bitcoin, testnet, signet, regtest)"
    exit 1
fi

if [ -z "$ELECTRUM_URL" ]; then
    echo "ERROR: ELECTRUM_URL required"
    exit 1
fi

if [ -z "$LEDGER_RELAY" ]; then
    echo "ERROR: LEDGER_RELAY required (durable relay for advertisements + ledger updates)"
    exit 1
fi

# --- Start strfry relay ---
sed "s|__RELAY_DIR__|${RELAY_DIR}|g; s|__RELAY_PORT__|${RELAY_PORT}|g" \
    /etc/strfry.conf.tmpl > /tmp/strfry.conf

echo "Starting relay on port $RELAY_PORT..."
strfry --config=/tmp/strfry.conf relay &
sleep 1

LOCAL_RELAY="ws://127.0.0.1:${RELAY_PORT}"

# --- Build relay list ---
# First relay = primary (publish target), rest = read
RELAYS="--relay $LOCAL_RELAY"

# Add ephemeral relays
if [ -n "$EPHEMERAL_RELAYS" ]; then
    for r in $(echo "$EPHEMERAL_RELAYS" | tr ',' ' '); do
        RELAYS="$RELAYS --relay $r"
    done
fi

# Ledger relay(s) are the slow/durable relays (comma-separated)
for r in $(echo "$LEDGER_RELAY" | tr ',' ' '); do
    RELAYS="$RELAYS --slow-relay $r"
done

# --- Start deposits-node ---
echo "Starting deposits-node..."
echo "  Network:      $NETWORK"
echo "  Electrum:     $ELECTRUM_URL"
echo "  Local relay:  $LOCAL_RELAY (port $RELAY_PORT)"
echo "  Ledger relay: $LEDGER_RELAY"
[ -n "$EPHEMERAL_RELAYS" ] && echo "  Extra relays: $EPHEMERAL_RELAYS"
[ -n "$ATTESTATION_VERIFIER_PUBKEY" ] && echo "  Verifier:     ${ATTESTATION_VERIFIER_PUBKEY}"
[ -n "$NODE_NAME" ] && echo "  Name:         $NODE_NAME"

# --- LDK Lightning setup (optional) ---
# If LDK data is mounted, auto-configure the API key.
# Write the hex key to a well-known file so docker exec commands can find it too.
if [ -d "/ldk-data" ] && [ -z "$LDK_API_KEY" ]; then
    API_KEY_FILE="/ldk-data/${NETWORK}/api_key"
    if [ -f "$API_KEY_FILE" ]; then
        export LDK_API_KEY=$(cat "$API_KEY_FILE" | od -A n -t x1 | tr -d ' \n')
        echo "$LDK_API_KEY" > /data/ldk_api_key_hex
        echo "  LDK API key: loaded from $API_KEY_FILE"
    fi
fi
if [ -f "/ldk-data/tls.crt" ] && [ -z "$LDK_TLS_CERT" ]; then
    export LDK_TLS_CERT="/ldk-data/tls.crt"
fi

exec deposits-node run \
    --seed "$NODE_SEED" \
    --network "$NETWORK" \
    --electrum "$ELECTRUM_URL" \
    $RELAYS \
    --data-dir "$DATA_DIR" \
    --metrics-port "$METRICS_PORT"
