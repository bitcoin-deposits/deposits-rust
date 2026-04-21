#!/bin/sh
set -e

# --- deposits-node standalone container ---
#
# Runs deposits-node + a bundled strfry relay in a single container.
# On first boot generates its own operator key, DMs the admin npub the
# BIP39 mnemonic + funding address (NIP-17 gift-wrapped), waits for the
# first on-chain payment to become reserves, then discovers peer operators
# and forms a Q=5 quorum with the fastest ones.
#
# Required:
#   <admin_npub>                     - passed as first positional arg, OR env ADMIN_NPUB.
#                                      Must have a published Kind 0 profile.
#   NETWORK                          - bitcoin, testnet, signet, regtest
#   ELECTRUM_URL                     - esplora/electrs URL
#   LEDGER_RELAY                     - durable relay (used for ads, DM, discovery)
#
# Optional:
#   EPHEMERAL_RELAYS                 - comma-separated additional relay URLs
#   RELAY_PORT                       - local relay port (default: 7777)
#   METRICS_PORT                     - prometheus metrics port (default: 9100)
#   NODE_NAME                        - operator name for advertisements
#   QUORUM_SIZE                      - default 5
#
# State (in /data/node):
#   seed.hex                         - generated operator seed (idempotent: reused on restart)
#   funding_address                  - address shown in the DM (stable across restarts)
#   reserves_ready.marker            - set after phase 2 completes
#   quorum_active.marker             - set after phase 3 completes
#
# Volumes:
#   /data                            - persistent node data + relay DB

DATA_DIR="/data/node"
RELAY_DIR="/data/relay"
RELAY_PORT="${RELAY_PORT:-7777}"
METRICS_PORT="${METRICS_PORT:-9100}"
QUORUM_SIZE="${QUORUM_SIZE:-5}"

mkdir -p "$DATA_DIR" "$RELAY_DIR"

# --- Resolve admin npub ---
ADMIN_NPUB="${1:-$ADMIN_NPUB}"
if [ -z "$ADMIN_NPUB" ]; then
    echo "ERROR: admin npub required — pass as first arg or set ADMIN_NPUB env"
    echo "usage: docker run ... <admin_npub>"
    exit 1
fi

# --- Validate required env ---
if [ -z "$NETWORK" ]; then
    echo "ERROR: NETWORK required (bitcoin, testnet, signet, regtest)"
    exit 1
fi
if [ -z "$ELECTRUM_URL" ]; then
    echo "ERROR: ELECTRUM_URL required"
    exit 1
fi
if [ -z "$LEDGER_RELAY" ]; then
    echo "ERROR: LEDGER_RELAY required"
    exit 1
fi

# --- Start strfry relay ---
sed "s|__RELAY_DIR__|${RELAY_DIR}|g; s|__RELAY_PORT__|${RELAY_PORT}|g" \
    /etc/strfry.conf.tmpl > /tmp/strfry.conf
echo "Starting local relay on port $RELAY_PORT..."
strfry --config=/tmp/strfry.conf relay &
sleep 1

LOCAL_RELAY="ws://127.0.0.1:${RELAY_PORT}"

# --- Build relay flag list ---
# Primary = local, others = upstream relays for publishing + discovery.
RELAYS="--relay $LOCAL_RELAY"
if [ -n "$EPHEMERAL_RELAYS" ]; then
    for r in $(echo "$EPHEMERAL_RELAYS" | tr ',' ' '); do
        RELAYS="$RELAYS --relay $r"
    done
fi
for r in $(echo "$LEDGER_RELAY" | tr ',' ' '); do
    RELAYS="$RELAYS --slow-relay $r"
done

# Bootstrap-phase relay (single value, used by init/reserves/quorum commands).
BOOT_RELAY=$(echo "$LEDGER_RELAY" | cut -d',' -f1)

# --- Phase 1: seed + DM admin (pre-daemon, creates seed.hex + admin.npub) ---
if [ ! -f "$DATA_DIR/seed.hex" ]; then
    echo ""
    echo "Phase 1: generating operator key + DMing admin..."
    deposits-node bootstrap init "$ADMIN_NPUB" \
        --data-dir "$DATA_DIR" \
        --network "$NETWORK" \
        --esplora "$ELECTRUM_URL" \
        --relay "$BOOT_RELAY"
fi
NODE_SEED=$(cat "$DATA_DIR/seed.hex")

# --- Start deposits-node daemon (runs through phases 2 + 3 via admin DMs) ---
echo ""
echo "Starting deposits-node daemon..."
echo "  Network:      $NETWORK"
echo "  Electrum:     $ELECTRUM_URL"
echo "  Local relay:  $LOCAL_RELAY"
echo "  Ledger relay: $LEDGER_RELAY"
[ -n "$NODE_NAME" ] && echo "  Name:         $NODE_NAME"

NAME_FLAG=""
[ -n "$NODE_NAME" ] && NAME_FLAG="--name $NODE_NAME"

deposits-node run \
    --seed "$NODE_SEED" \
    --network "$NETWORK" \
    --electrum "$ELECTRUM_URL" \
    $RELAYS \
    --data-dir "$DATA_DIR" \
    --metrics-port "$METRICS_PORT" \
    $NAME_FLAG &
DAEMON_PID=$!

# Give the daemon time to open its relay subscriptions before we start
# sending admin requests through it.
sleep 5

# --- Phase 2: wait for funding + create reserves + open ledger (via daemon) ---
if [ ! -f "$DATA_DIR/reserves_ready.marker" ]; then
    echo ""
    echo "Phase 2: waiting for funding + opening ledger..."
    deposits-node bootstrap reserves \
        --seed "$NODE_SEED" \
        --data-dir "$DATA_DIR" \
        --network "$NETWORK" \
        --esplora "$ELECTRUM_URL" \
        --relay "$BOOT_RELAY"
    touch "$DATA_DIR/reserves_ready.marker"
fi

# --- Phase 3: discover peers + form Q=5 quorum (via daemon) ---
if [ ! -f "$DATA_DIR/quorum_active.marker" ]; then
    echo ""
    echo "Phase 3: discovering peers + forming quorum (Q=$QUORUM_SIZE)..."
    if deposits-node bootstrap quorum \
        --seed "$NODE_SEED" \
        --data-dir "$DATA_DIR" \
        --network "$NETWORK" \
        --esplora "$ELECTRUM_URL" \
        --relay "$BOOT_RELAY" \
        --quorum-size "$QUORUM_SIZE"; then
        echo "Bootstrap complete — operator is live."
    else
        echo "WARN: quorum formation failed; operator still running with solo ledger."
        echo "      Rerun 'deposits-node bootstrap quorum' when more peers are available."
    fi
fi

# --- Keep daemon in foreground ---
wait $DAEMON_PID
