#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$REPO_ROOT/target/release/transfer-simulator"

if [ ! -x "$BIN" ]; then
    echo "Building transfer-simulator (release)..."
    cargo build --release --bin transfer-simulator --manifest-path "$REPO_ROOT/Cargo.toml"
fi

"$BIN" \
    --relay ws://localhost:7801 \
    --node sim:~/.deposits-wallet \
    --bootstrap --auto-topoff \
    --deposit-count 72 \
    --target-tps 500 --workers 50
