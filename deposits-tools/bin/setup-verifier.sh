#!/bin/bash
# Set up the lightning-verify service and NIP-05 test server.
#
# Generates certs and keys if needed, starts the containers, and
# registers test users from the running operator nodes.
#
# Usage:
#   ./bin/setup-verifier.sh              # Full setup
#   ./bin/setup-verifier.sh --register   # Just re-register users from running nodes

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$TOOLS_DIR"

source "$SCRIPT_DIR/_common.sh" 2>/dev/null || true

REGISTER_ONLY=false
if [ "${1:-}" = "--register" ]; then
    REGISTER_ONLY=true
fi

if ! $REGISTER_ONLY; then
    # 1. Generate certs
    echo "=== Setting up TLS certs ==="
    "$SCRIPT_DIR/setup-nip05-certs.sh"

    # 2. Generate verifier nsec if missing
    mkdir -p secrets
    if [ ! -f secrets/verify_nsec ]; then
        openssl rand -hex 32 > secrets/verify_nsec
        echo "Generated verifier nsec"
    else
        echo "Verifier nsec already exists"
    fi

    # 3. Copy LDK API key to secrets (from the running lightning container)
    if [ ! -f secrets/ldk_api_key ]; then
        echo "test_api_key" > secrets/ldk_api_key
        echo "Set default LDK API key"
    fi

    # 4. Build and start containers
    echo ""
    echo "=== Starting verifier and NIP-05 server ==="
    docker compose --profile lightning up -d --build lightning-verify nip05 2>&1

    # Wait for nip05 to be ready
    echo -n "Waiting for NIP-05 server..."
    for i in $(seq 1 20); do
        if curl -sk https://172.21.0.50/ >/dev/null 2>&1; then
            echo " ready"
            break
        fi
        sleep 0.5
        echo -n "."
    done
fi

# 5. Register test users from running nodes
echo ""
echo "=== Registering test users ==="

# Get the wallet pubkey for each running node by reading its nostr key
# The node's nostr pubkey is derived from its seed — we can get it from the node logs or by asking
DATA_ROOT="${DATA_ROOT:-$TOOLS_DIR/data}"

register_user() {
    local name="$1"
    local pubkey="$2"
    if [ -z "$pubkey" ]; then
        echo "  Skipping $name — no pubkey"
        return
    fi
    "$SCRIPT_DIR/nip05-register.sh" "$name" "$pubkey"
}

# Try to get pubkeys from running nodes' advertisements
# Parse from the most recent kind 39100 events on the relays
echo "Looking for operator pubkeys from advertisements..."

for port in 7801 7802 7803 7804; do
    # Query the relay for advertisements
    ADS=$(echo '["REQ","q",{"kinds":[39100],"limit":1}]' | timeout 2 websocat -n1 ws://localhost:$port 2>/dev/null || true)
    if [ -n "$ADS" ]; then
        # Extract operator_name and the event pubkey
        PUBKEY=$(echo "$ADS" | grep -o '"pubkey":"[^"]*"' | head -1 | cut -d'"' -f4)
        NAME=$(echo "$ADS" | grep -o '"operator_name":"[^"]*"' | head -1 | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')
        if [ -n "$PUBKEY" ] && [ -n "$NAME" ]; then
            register_user "$NAME" "$PUBKEY"
        fi
    fi
done

# Also register any wallet seeds if available
# The wallet uses key index 0, so its pubkey = getPublicKeyHex(deriveSecretKey(seed, 0))
# This is harder to extract without running code, so we skip it for now
# and let the wallet's NIP-05 check handle it at verification time.

echo ""
echo "=== Verifier setup complete ==="

# Show the verifier's npub
NSEC=$(cat secrets/verify_nsec)
# Derive pubkey from secret key (using openssl + secp256k1 is complex, so just log it)
echo "Verifier nsec: ${NSEC:0:16}..."
echo "Start the verifier with: docker compose --profile lightning up -d lightning-verify"
echo "NIP-05 test: curl -sk https://172.21.0.50/.well-known/nostr.json"
echo ""
echo "To register additional users:"
echo "  ./bin/nip05-register.sh <username> <hex-pubkey>"
