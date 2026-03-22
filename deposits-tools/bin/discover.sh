#!/bin/bash
# Discover operators and quorum topology from Nostr relays
# Wrapper for the discover binary

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
exec "$REPO_ROOT/target/release/discover" "$@"
