2> /dev/null target/release/nwc-client -w wallet/alice.json pay-invoice  $(target/release/nwc-client -w wallet/charlie.json make-invoice 10000 | jq -r .result.invoice)
sleep 3
./updates.sh --verbose
