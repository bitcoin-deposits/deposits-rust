#!/bin/bash
cd "$(dirname "$0")/.."

NWC="../target/release/nwc-client"

2> /dev/null "$NWC" -w wallet/amber.json pay-invoice  $("$NWC" -w wallet/blue.json make-invoice 1000 | jq -r .result.invoice)
sleep 3
./bin/updates.sh --verbose
