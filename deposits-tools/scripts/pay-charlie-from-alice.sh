#!/bin/bash

cd "$(dirname "$0")"

SCRIPT_DIR="$(pwd)"
PROJECT_DIR="$(cd ".." && pwd)"
WORKSPACE_DIR="$(cd "../.." && pwd)"

2> /dev/null "$WORKSPACE_DIR/target/release/nwc-client" -w "$PROJECT_DIR/wallet/alice.json" pay-invoice  $("$WORKSPACE_DIR/target/release/nwc-client" -w "$PROJECT_DIR/wallet/charlie.json" make-invoice 10000 | jq -r .result.invoice)
sleep 3
"$SCRIPT_DIR/updates.sh" --verbose
