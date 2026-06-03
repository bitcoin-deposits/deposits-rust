#!/bin/bash
# Wrapper around `deposits-node run` that constructs the right --relay
# flags from env vars. The daemon takes one or more --relay <url> flags
# on the command line; this wrapper materialises them from
# $RELAY_LEDGERS (required) and $RELAY_MESSAGING (optional), so the
# systemd EnvironmentFile shape stays declarative.
#
# Installed at /usr/local/bin/deposits-node-wrapped by init.sh. The
# unit file invokes this rather than deposits-node directly so the env
# file is the single source of config.

set -e

: "${NETWORK:?NETWORK must be set}"
: "${OPERATOR_NAME:?OPERATOR_NAME must be set}"
: "${RELAY_LEDGERS:?RELAY_LEDGERS must be set (wss:// or ws://)}"
: "${SIGNER_PUBKEY:?SIGNER_PUBKEY must be set (run init.sh)}"

ESPLORA_URL="${ESPLORA_URL:-https://blockstream.info/api}"
ADMIN_BIND="${ADMIN_BIND:-127.0.0.1:8765}"
DATA_DIR="${DEPOSITS_DATA_DIR:-/var/lib/deposits}"
SIGNER_SOCKET="${DEPOSITS_SIGNER_SOCKET:-/run/dsigner/socket}"

args=(
    "run"
    "--network"        "$NETWORK"
    "--name"           "$OPERATOR_NAME"
    "--data-dir"       "$DATA_DIR"
    "--esplora"        "$ESPLORA_URL"
    "--signer-socket"  "$SIGNER_SOCKET"
    "--signer-pubkey"  "$SIGNER_PUBKEY"
    "--metrics-port"   "9100"
    "--admin-bind"     "$ADMIN_BIND"
    "--relay"          "$RELAY_LEDGERS"
)

# Optional secondary messaging relay. The daemon accepts multiple
# --relay flags; the first is treated as the durable ledger relay.
if [ -n "${RELAY_MESSAGING:-}" ]; then
    args+=("--relay" "$RELAY_MESSAGING")
fi

exec /usr/local/bin/deposits-node "${args[@]}"
