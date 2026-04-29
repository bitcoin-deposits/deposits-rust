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
#   NETWORK                          - bitcoin, testnet, signet, regtest
#   ELECTRUM_URL                     - esplora/electrs URL
#   LEDGER_RELAY                     - durable relay (used for ads, discovery)
#
# Required only on the bootstrap-init path (no NODE_SEED_FILE):
#   <admin_npub>                     - first positional arg, OR env ADMIN_NPUB.
#                                      Must have a published Kind 0 profile.
#                                      Accepts npub1... bech32 or 64-char hex.
#                                      Used to DM the generated mnemonic.
#                                      Optional when NODE_SEED_FILE is set —
#                                      a self-administered node (operator
#                                      drives admin via their own seed) does
#                                      not need a separate admin identity.
#
# Seed handling:
#   NODE_SEED_FILE                   - path to a pre-mounted operator seed.
#                                      Default /secrets/seed. When this file
#                                      exists, the entrypoint copies it to
#                                      $DATA_DIR/seed.hex on first boot and
#                                      skips the bootstrap-init "generate
#                                      seed + DM admin mnemonic" flow. Used
#                                      in production where the operator
#                                      already has a seed (HSM-backed,
#                                      restored from backup, etc.). When
#                                      NODE_SEED_FILE doesn't exist, the
#                                      entrypoint falls back to
#                                      `bootstrap init` which generates a
#                                      fresh seed and DMs the admin the
#                                      mnemonic over Nostr.
#
# Optional:
#   EPHEMERAL_RELAYS                 - comma-separated additional relay URLs
#   RELAY_PORT                       - local relay port (default: 7777)
#   METRICS_PORT                     - prometheus metrics port (default: 9100)
#   NODE_NAME                        - operator name for advertisements
#   QUORUM_SIZE                      - default 5
#   COURIER_RESERVES_SATS            - open a buffer deposit of this many
#                                      sats on the operator's own ledger
#                                      after quorum, publish a Swap
#                                      advertisement for it, and run
#                                      swap-listen in the background so
#                                      the node serves as its own courier.
#                                      Omit to skip courier mode.
#   SKIP_QUORUM                      - when set to any non-empty value
#                                      other than "0"/"false", skip Phase
#                                      3 entirely. The daemon comes up
#                                      with a solo ledger and no quorum.
#                                      Use this to bring up the first few
#                                      nodes in a brand-new network, when
#                                      there are no peers to discover
#                                      yet. Run
#                                        deposits-node bootstrap quorum
#                                      manually via docker exec once
#                                      enough peers are online.
#                                      Incompatible with COURIER_RESERVES_SATS
#                                      (courier mode requires an active
#                                      quorum).
#
# Access control (passed through to the daemon via env):
#   DEPOSIT_ACCESS_CONTROL           - "true" to gate deposit_open on the
#                                      npub allowlist / verify attestation.
#                                      When unset or "false", only the
#                                      denylist is consulted.
#   ATTESTATION_VERIFIER_PUBKEY      - hex pubkey of the lightning-verify
#                                      service whose attestations the node
#                                      trusts. Echoed back in rejection
#                                      responses so wallets know who to
#                                      DM.
#   MAX_DEPOSIT_BALANCE_MSATS        - cap per deposit; 0 = unlimited.
#
# Access-control files (mount into /config to apply them):
#   /config/deposit_allowlist.txt         - one xonly npub per line; these
#                                           sender pubkeys skip the
#                                           attestation check.
#   /config/deposit_denylist.txt          - one npub per line; these are
#                                           rejected regardless of
#                                           DEPOSIT_ACCESS_CONTROL.
#   /config/deposit_domain_allowlist.txt  - lightning-address domains whose
#                                           verifier attestations are
#                                           accepted (e.g. "example.com").
#
# State (in /data/node):
#   seed.hex                         - generated operator seed (idempotent: reused on restart)
#   funding_address                  - address shown in the DM (stable across restarts)
#   reserves_ready.marker            - set after phase 2 completes
#   quorum_active.marker             - set after phase 3 completes
#
# Volumes:
#   /data                            - persistent node data + relay DB
#   /config                          - optional access-control lists (see above)

DATA_DIR="/data/node"
RELAY_DIR="/data/relay"
RELAY_PORT="${RELAY_PORT:-7777}"
METRICS_PORT="${METRICS_PORT:-9100}"
QUORUM_SIZE="${QUORUM_SIZE:-5}"

mkdir -p "$DATA_DIR" "$RELAY_DIR"

# --- Copy access-control lists from /config into the data dir ---
# The daemon reads these from {data_dir} (see Node::load_list in
# deposits-node/src/node/init.rs). We copy rather than symlink so a
# container stop/start doesn't leave stale pointers.
for f in deposit_allowlist.txt deposit_denylist.txt deposit_domain_allowlist.txt; do
    if [ -f "/config/$f" ]; then
        cp "/config/$f" "$DATA_DIR/$f"
    fi
done

# --- Resolve admin npub (optional) ---
# `admin.npub` authorises a *separate* identity to drive admin-class
# gift-wrapped requests. Self-authored admin requests (signer ==
# operator) are always authorised regardless, so a node administered
# by its own operator key (e.g. via node-cli.sh against the same
# seed) doesn't need this set.
#
# `bootstrap init` does need it though — to DM the admin the
# generated mnemonic. So we only hard-fail on missing ADMIN_NPUB
# below if we end up taking the generate-seed path.
ADMIN_NPUB="${1:-${ADMIN_NPUB:-}}"

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

# --- Start local strfry relay (if installed) ---
# Optional: when strfry is bundled in the image, we run a local relay and
# wire it as the primary publish target. Otherwise we rely entirely on
# LEDGER_RELAY. Most real deployments use an external relay.
LOCAL_RELAY=""
if command -v strfry >/dev/null 2>&1 && [ -f /etc/strfry.conf.tmpl ]; then
    sed "s|__RELAY_DIR__|${RELAY_DIR}|g; s|__RELAY_PORT__|${RELAY_PORT}|g" \
        /etc/strfry.conf.tmpl > /tmp/strfry.conf
    echo "Starting local relay on port $RELAY_PORT..."
    strfry --config=/tmp/strfry.conf relay &
    sleep 1
    LOCAL_RELAY="ws://127.0.0.1:${RELAY_PORT}"
fi

# --- Build relay flag list ---
# Primary is the local relay if present, otherwise the first upstream.
RELAYS=""
if [ -n "$LOCAL_RELAY" ]; then
    RELAYS="--relay $LOCAL_RELAY"
fi
if [ -n "$EPHEMERAL_RELAYS" ]; then
    for r in $(echo "$EPHEMERAL_RELAYS" | tr ',' ' '); do
        RELAYS="$RELAYS --relay $r"
    done
fi
for r in $(echo "$LEDGER_RELAY" | tr ',' ' '); do
    # When there's no local relay, the first upstream becomes primary.
    if [ -z "$LOCAL_RELAY" ] && [ -z "$RELAYS" ]; then
        RELAYS="--relay $r"
    else
        RELAYS="$RELAYS --slow-relay $r"
    fi
done

if [ -z "$RELAYS" ]; then
    echo "ERROR: no relays resolved. Set LEDGER_RELAY (and optionally" >&2
    echo "       EPHEMERAL_RELAYS) — without at least one relay the daemon" >&2
    echo "       can't subscribe to incoming events and admin requests" >&2
    echo "       silently time out." >&2
    exit 1
fi

# Bootstrap-phase relay (single value, used by init/reserves/quorum commands).
BOOT_RELAY=$(echo "$LEDGER_RELAY" | cut -d',' -f1)

# --- Phase 1: seed + DM admin (pre-daemon, creates seed.hex + admin.npub) ---
NODE_SEED_FILE="${NODE_SEED_FILE:-/secrets/seed}"
if [ -f "$NODE_SEED_FILE" ] && [ ! -f "$DATA_DIR/seed.hex" ]; then
    # Pre-mounted seed path. Skip the DM-mnemonic flow entirely — the
    # operator already has the seed out of band (HSM, backup, etc.).
    echo ""
    echo "Phase 1: importing pre-mounted seed from $NODE_SEED_FILE"
    cp "$NODE_SEED_FILE" "$DATA_DIR/seed.hex"
    chmod 600 "$DATA_DIR/seed.hex"
    # Only write admin.npub when an external admin identity was
    # explicitly provided. The daemon's auth check unconditionally
    # accepts requests signed by the operator's own key, so leaving
    # admin.npub absent is the correct shape for a self-administered
    # node (which is the common case).
    if [ -n "$ADMIN_NPUB" ]; then
        printf '%s\n' "$ADMIN_NPUB" > "$DATA_DIR/admin.npub"
    fi
elif [ ! -f "$DATA_DIR/seed.hex" ]; then
    # First-boot fresh-seed path. `bootstrap init` generates a seed,
    # writes seed.hex + admin.npub, and DMs the admin the mnemonic
    # over Nostr. Requires both a relay and an admin npub so the DM
    # can land somewhere meaningful.
    if [ -z "$ADMIN_NPUB" ]; then
        echo "ERROR: bootstrap init needs ADMIN_NPUB (or first positional arg)" >&2
        echo "       to DM the generated mnemonic. Either provide one, or" >&2
        echo "       mount a pre-existing seed at \$NODE_SEED_FILE" >&2
        echo "       (default /secrets/seed) to skip bootstrap init." >&2
        exit 1
    fi
    echo ""
    echo "Phase 1: generating operator key + DMing admin..."
    deposits-node bootstrap init "$ADMIN_NPUB" \
        --data-dir "$DATA_DIR" \
        --network "$NETWORK" \
        --esplora "$ELECTRUM_URL" \
        --relay "$BOOT_RELAY"
fi
NODE_SEED=$(cat "$DATA_DIR/seed.hex" 2>/dev/null || true)
if [ -z "$NODE_SEED" ]; then
    echo "ERROR: $DATA_DIR/seed.hex is empty or missing after Phase 1." >&2
    echo "       NODE_SEED_FILE=$NODE_SEED_FILE (exists: $([ -f "$NODE_SEED_FILE" ] && echo yes || echo no))." >&2
    echo "       If using a pre-mounted seed, mount it at \$NODE_SEED_FILE." >&2
    echo "       If using bootstrap init, ensure ADMIN_NPUB and LEDGER_RELAY are reachable." >&2
    exit 1
fi

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

# --- Phase 3: discover peers + form quorum (via daemon) ---
#
# Skipped entirely when SKIP_QUORUM is set (anything but unset/0/false) —
# used to bring up the first nodes in a fresh network. Otherwise bootstrap
# quorum retries every ~5 min indefinitely until enough peers are online
# and all join steps succeed; the container is effectively blocked in
# Phase 3 until then.
case "${SKIP_QUORUM:-}" in
    ""|"0"|"false"|"False"|"FALSE")
        skip_quorum=0
        ;;
    *)
        skip_quorum=1
        ;;
esac

if [ "$skip_quorum" = "1" ]; then
    echo ""
    echo "Phase 3: SKIP_QUORUM set — running solo, no quorum formation"
    echo "         form a quorum later with:"
    echo "         docker exec <container> deposits-node bootstrap quorum \\"
    echo "             --seed <seed> --data-dir $DATA_DIR --network $NETWORK \\"
    echo "             --esplora $ELECTRUM_URL --relay $BOOT_RELAY --quorum-size $QUORUM_SIZE"
elif [ ! -f "$DATA_DIR/quorum_active.marker" ]; then
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
        # bootstrap quorum retries internally, so reaching this branch
        # means a fast-fail condition (bad config, missing ledger, etc.)
        # rather than "peers not online yet".
        echo "WARN: quorum formation failed with a non-retriable error."
        echo "      Check the log above; rerun the command or set SKIP_QUORUM=1"
        echo "      to run solo until the issue is resolved."
    fi
fi

# --- Phase 4 (optional): courier mode ---
# If the admin set COURIER_RESERVES_SATS, open a buffer deposit funded at
# that amount, bridge it into a wallet state file, publish a swap ad, and
# run swap-listen as a background service. The node's own buffer becomes
# the liquidity source for swaps into its ledger — the operator is a
# natural courier for their own freshly-opened ledger (no external
# courier has reason to park capacity there yet).
if [ -n "$COURIER_RESERVES_SATS" ] && [ "$skip_quorum" = "1" ]; then
    echo ""
    echo "Phase 4: COURIER_RESERVES_SATS set but SKIP_QUORUM=1 — skipping."
    echo "         courier mode requires an active quorum to cosign the"
    echo "         buffer's InvoiceCredit. Form a quorum first, then"
    echo "         restart without SKIP_QUORUM to enable courier."
elif [ -n "$COURIER_RESERVES_SATS" ]; then
    echo ""
    echo "Phase 4: opening courier buffer ($COURIER_RESERVES_SATS sats)..."

    # Admin open + fill in one step. Output is human-readable; parse
    # the index / pubkey / ledger_id out with grep — small and stable
    # enough that a dedicated --json flag isn't worth the churn.
    BUFFER_OUT=$(deposits-node admin buffer open \
        --amount-sats "$COURIER_RESERVES_SATS" \
        --seed "$NODE_SEED" \
        --data-dir "$DATA_DIR" \
        --network "$NETWORK" \
        --esplora "$ELECTRUM_URL" \
        --relay "$BOOT_RELAY" 2>&1)

    BUF_INDEX=$(echo "$BUFFER_OUT" | awk '/^  index:/ {print $2}')
    BUF_PUBKEY=$(echo "$BUFFER_OUT" | awk '/^  pubkey:/ {print $2}')
    BUF_LEDGER=$(echo "$BUFFER_OUT" | awk '/^  ledger:/ {print $2}')

    if [ -z "$BUF_INDEX" ] || [ -z "$BUF_PUBKEY" ] || [ -z "$BUF_LEDGER" ]; then
        echo "$BUFFER_OUT" | tail -10
        echo "WARN: buffer open parse failed — skipping courier setup"
    else
        echo "  buffer index: $BUF_INDEX"
        echo "  pubkey:       ${BUF_PUBKEY:0:16}..."
        echo "  ledger:       $BUF_LEDGER"

        # Build a wallet data-dir so swap-advertise and swap-listen can
        # reason about the buffer as a named deposit.
        WALLET_DIR="$DATA_DIR/courier-wallet"
        mkdir -p "$WALLET_DIR"
        echo "$NODE_SEED" > "$WALLET_DIR/seed.hex"
        cat > "$WALLET_DIR/deposits.json" <<EOF
[
  {
    "alias": "courier",
    "ledger_id": "$BUF_LEDGER",
    "key_index": $BUF_INDEX,
    "deposit_pubkey": "$BUF_PUBKEY",
    "status": "funded"
  }
]
EOF

        # Publish a SwapAdvertisement from the courier deposit.
        echo "  publishing swap advertisement..."
        deposits-wallet swap-advertise courier "$COURIER_RESERVES_SATS" \
            --data-dir "$WALLET_DIR" \
            --network "$NETWORK" \
            --relay "$BOOT_RELAY" \
            --expires-hours 168 \
            > /dev/null 2>&1 || \
            echo "  WARN: swap-advertise failed"

        # Run swap-listen in the background so the courier actually
        # responds to swap_request events.
        echo "  launching swap-listen..."
        deposits-wallet swap-listen \
            --data-dir "$WALLET_DIR" \
            --network "$NETWORK" \
            --relay "$BOOT_RELAY" \
            > "$DATA_DIR/swap-listen.log" 2>&1 &
        SWAP_PID=$!
        echo "  swap-listen pid: $SWAP_PID"
        echo "Courier live."
    fi
fi

# --- Keep daemon in foreground ---
wait $DAEMON_PID
