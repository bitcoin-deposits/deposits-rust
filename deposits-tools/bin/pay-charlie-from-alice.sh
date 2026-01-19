#!/bin/bash
cd "$(dirname "$0")/.."

NWC="../target/release/nwc-client"

2> /dev/null "$NWC" -w wallet/alice.json pay-invoice  $("$NWC" -w wallet/charlie.json make-invoice 10000 | jq -r .result.invoice)
sleep 3
./bin/updates.sh --verbose
