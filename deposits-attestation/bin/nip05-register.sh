#!/bin/bash
# Register a user in the fake NIP-05 service.
#
# Usage:
#   ./bin/nip05-register.sh <username> <hex-pubkey>
#
# Writes to the nip05_data docker volume, which the verifier container
# (running lnurl-server.py as a test fixture) serves on :443.
# Multiple calls accumulate users in the same nostr.json.

set -e

USERNAME="$1"
PUBKEY="$2"

if [ -z "$USERNAME" ] || [ -z "$PUBKEY" ]; then
    echo "Usage: $0 <username> <hex-pubkey>"
    exit 1
fi

# Get the mount point of the nip05_data volume
VOLUME_PATH=$(docker volume inspect deposits-tools_nip05_data -f '{{.Mountpoint}}' 2>/dev/null || \
              docker volume inspect deposits-tools-nip05_data -f '{{.Mountpoint}}' 2>/dev/null || true)

if [ -z "$VOLUME_PATH" ]; then
    echo "nip05_data volume not found. Start the lnaddr-attest container first:"
    echo "  docker compose --profile lightning up -d lnaddr-attest"
    exit 1
fi

NOSTR_JSON="$VOLUME_PATH/nostr.json"

# Read existing names or start fresh
if [ -f "$NOSTR_JSON" ]; then
    NAMES=$(python3 -c "
import json, sys
with open('$NOSTR_JSON') as f:
    data = json.load(f)
names = data.get('names', {})
names['$USERNAME'] = '$PUBKEY'
print(json.dumps({'names': names}, indent=2))
" 2>/dev/null || echo '{"names":{"'$USERNAME'":"'$PUBKEY'"}}')
else
    NAMES='{"names":{"'$USERNAME'":"'$PUBKEY'"}}'
fi

# Write atomically
echo "$NAMES" | sudo tee "$NOSTR_JSON" > /dev/null
echo "Registered $USERNAME -> ${PUBKEY:0:16}... in NIP-05"
echo "  Verify: curl http://localhost:8805/.well-known/nostr.json?name=$USERNAME"
