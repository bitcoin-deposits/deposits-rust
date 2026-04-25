#!/bin/sh
# Entrypoint for the lnaddr-attest container.
#
# Two processes share the image:
#   1. lnurl-server.py — test fixture. Serves .well-known/nostr.json (NIP-05)
#      and .well-known/lnurlp/<user> (LUD-06/LUD-16) on 443/HTTPS so the
#      attest service has a fake lightning-address provider to probe in
#      test topologies.
#   2. deposits-attest — the Rust challenge-response service (Nostr kind
#      25500/25501) that produces npub ↔ ln-address attestations. Runs in
#      the foreground; its exit terminates the container.
#
# Both talk to the same LDK node via the mounted ldk-cli wrapper.

set -e

export LDK_API_KEY=$(cat /ldk-data/regtest/api_key | od -A n -t x1 | tr -d ' \n')
export LDK_REAL_CLI=/ldk-cli/ldk-server-cli
mkdir -p /self-pay

# Background: fake NIP-05 / LNURL-pay server (test fixture).
python3 -u /app/lnurl-server.py &
LNURL_PID=$!

# Forward container signals so the Python child exits with the Rust parent.
trap 'kill $LNURL_PID 2>/dev/null; exit' TERM INT

# Foreground: the Rust attest service.
exec deposits-attest
