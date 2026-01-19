#!/bin/bash
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
PROJECT_DIR="$(cd ".." && pwd)"
WORKSPACE_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
NWC="$WORKSPACE_DIR/target/release/nwc-client"

2> /dev/null "$NWC" -w "$PROJECT_DIR/wallet/charlie.json" pay-invoice  $("$NWC" -w "$PROJECT_DIR/wallet/amber.json" make-invoice 10000 | jq -r .result.invoice)
sleep 3
"$SCRIPT_DIR/updates.sh" --verbose
