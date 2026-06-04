#!/bin/sh
set -e
apk add --no-cache curl >/dev/null 2>&1
RPC="http://user:pass@bitcoin:18443/wallet/faucet"

# Interval between mining iterations. Each iteration mines
# $MINER_BATCH_SIZE blocks (default 1). To mine faster, lower the
# interval — e.g. MINER_INTERVAL=0.05 mines ~20 blocks/sec. To burst
# many blocks at once with low rate, set MINER_BATCH_SIZE=10 and
# MINER_INTERVAL=2. Set MINER_INTERVAL=0 to disable the sleep (tight
# loop; bitcoind will be the bottleneck).
INTERVAL="${MINER_INTERVAL:-1}"
BATCH_SIZE="${MINER_BATCH_SIZE:-1}"

echo "Waiting for faucet wallet..."
until curl -sf -d '{"method":"getbalance"}' $RPC >/dev/null 2>&1; do
  sleep 2
done

ADDR=$(curl -sf -d '{"method":"getnewaddress"}' $RPC | sed 's/.*"result":"\([^"]*\)".*/\1/')
echo "Mining to $ADDR ($BATCH_SIZE block(s) every ${INTERVAL}s)"

while true; do
  curl -sf -d "{\"method\":\"generatetoaddress\",\"params\":[$BATCH_SIZE,\"$ADDR\"]}" $RPC >/dev/null
  sleep "$INTERVAL"
done
