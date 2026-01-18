2> /dev/null target/release/nwc-client -w wallet/amber.json pay-invoice  $(target/release/nwc-client -w wallet/blue.json make-invoice 1000 | jq -r .result.invoice)
sleep 3
./updates.sh --verbose
