#!/bin/sh
set -e
apk add --no-cache curl >/dev/null 2>&1
RPC="http://user:pass@bitcoin:18443/wallet/faucet"

echo "Waiting for faucet wallet..."
until curl -sf -d '{"method":"getbalance"}' $RPC >/dev/null 2>&1; do
  sleep 2
done

ADDR=$(curl -sf -d '{"method":"getnewaddress"}' $RPC | sed 's/.*"result":"\([^"]*\)".*/\1/')
echo "Mining to $ADDR (1 block/sec)"

while true; do
  curl -sf -d "{\"method\":\"generatetoaddress\",\"params\":[1,\"$ADDR\"]}" $RPC >/dev/null
  sleep 1
done
