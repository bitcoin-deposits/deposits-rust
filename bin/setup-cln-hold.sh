#!/usr/bin/env bash
# Spin up a two-node CLN regtest pair for the hold-invoice integration test:
#
#   cln-hold-test   the "bridge" node — runs the BoltzExchange `hold` plugin
#                   (https://github.com/BoltzExchange/hold), exposing
#                   holdinvoice / listholdinvoices / settleholdinvoice /
#                   cancelholdinvoice over the usual lightning-rpc socket.
#   cln-payer-test  a plain CLN node with a channel INTO the hold node, used
#                   to pay the hold invoice (its `pay` blocks while HTLCs are
#                   parked — exactly the property under test).
#
# Joins the existing deposits regtest network (`deposits-tools_regtest`) and
# uses its bitcoind (alias `bitcoind`, rpcuser=user, rpcpassword=pass).
# Sockets are bind-mounted to the host so the deposits-node ClnBackend can
# connect directly:
#
#   /tmp/cln-hold-test/regtest/lightning-rpc    (the bridge node)
#   /tmp/cln-payer-test/regtest/lightning-rpc   (the payer)
#
# Usage:
#   ./bin/setup-cln-hold.sh         # bring up + fund + open channel
#   ./bin/setup-cln-hold.sh down    # tear down containers + state
#
# Then:
#   CLN_SOCKET_PATH=/tmp/cln-hold-test/regtest/lightning-rpc \
#     cargo test -p deposits-node --test cln_hold_invoice -- --ignored
set -euo pipefail

NETWORK=deposits-tools_regtest
IMG=elementsproject/lightningd:v25.05
HOLD_BIN="$(cd "$(dirname "$0")/.." && pwd)/deploy/cln-hold/build/hold-linux-amd64"
HOLD_DIR=/tmp/cln-hold-test
PAYER_DIR=/tmp/cln-payer-test
BCLI="docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass"

cli_hold()  { docker exec cln-hold-test  lightning-cli --network=regtest "$@"; }
cli_payer() { docker exec cln-payer-test lightning-cli --network=regtest "$@"; }

if [[ "${1:-}" == "down" ]]; then
    docker rm -f cln-hold-test cln-payer-test 2>/dev/null || true
    sudo rm -rf "$HOLD_DIR" "$PAYER_DIR" 2>/dev/null || rm -rf "$HOLD_DIR" "$PAYER_DIR" || true
    echo "cln-hold test stack removed"
    exit 0
fi

if [[ ! -f "$HOLD_BIN" ]]; then
    echo "hold plugin binary missing at $HOLD_BIN"
    echo "fetch with:"
    echo "  curl -sL -o /tmp/hold.tar.gz https://github.com/BoltzExchange/hold/releases/download/v0.3.3/hold-linux-amd64.tar.gz"
    echo "  tar xzf /tmp/hold.tar.gz -C deploy/cln-hold/"
    exit 1
fi

mkdir -p "$HOLD_DIR" "$PAYER_DIR"
chmod 777 "$HOLD_DIR" "$PAYER_DIR"

docker rm -f cln-hold-test cln-payer-test 2>/dev/null || true

echo "[1/6] starting CLN nodes..."
docker run -d --name cln-hold-test --network "$NETWORK" \
    -v "$HOLD_DIR":/root/.lightning \
    -v "$HOLD_BIN":/plugins/hold:ro \
    "$IMG" \
    --network=regtest \
    --bitcoin-rpcconnect=bitcoind --bitcoin-rpcport=18443 \
    --bitcoin-rpcuser=user --bitcoin-rpcpassword=pass \
    --alias=cln-hold-test \
    --important-plugin=/plugins/hold \
    --hold-database=sqlite:///root/.lightning/hold.db \
    --bind-addr=0.0.0.0:9735 \
    --developer --dev-bitcoind-poll=2 --dev-fast-gossip >/dev/null

docker run -d --name cln-payer-test --network "$NETWORK" \
    -v "$PAYER_DIR":/root/.lightning \
    "$IMG" \
    --network=regtest \
    --bitcoin-rpcconnect=bitcoind --bitcoin-rpcport=18443 \
    --bitcoin-rpcuser=user --bitcoin-rpcpassword=pass \
    --alias=cln-payer-test \
    --bind-addr=0.0.0.0:9735 \
    --developer --dev-bitcoind-poll=2 --dev-fast-gossip >/dev/null

echo "[2/6] waiting for RPC sockets..."
for i in $(seq 1 60); do
    if cli_hold getinfo >/dev/null 2>&1 && cli_payer getinfo >/dev/null 2>&1; then
        break
    fi
    [[ $i == 60 ]] && { echo "CLN nodes failed to start"; docker logs cln-hold-test | tail -20; exit 1; }
    sleep 1
done

# Sockets are created root-owned inside the containers; open them up so the
# host-side test process can connect through the bind mount.
docker exec cln-hold-test  chmod -R a+rwX /root/.lightning
docker exec cln-payer-test chmod -R a+rwX /root/.lightning

echo "[3/6] funding payer..."
PAYER_ADDR=$(cli_payer newaddr | grep -o '"bech32": *"[^"]*"' | cut -d'"' -f4)
$BCLI -rpcwallet=default sendtoaddress "$PAYER_ADDR" 1.0 >/dev/null \
    || $BCLI sendtoaddress "$PAYER_ADDR" 1.0 >/dev/null
MINER_ADDR=$($BCLI -rpcwallet=default getnewaddress 2>/dev/null || $BCLI getnewaddress)
$BCLI generatetoaddress 3 "$MINER_ADDR" >/dev/null

for i in $(seq 1 30); do
    FUNDS=$(cli_payer listfunds | grep -c '"confirmed"' || true)
    [[ "$FUNDS" -gt 0 ]] && break
    sleep 1
done

echo "[4/6] opening channel payer -> hold..."
HOLD_ID=$(cli_hold getinfo | grep -o '"id": *"[^"]*"' | head -1 | cut -d'"' -f4)
cli_payer connect "$HOLD_ID@cln-hold-test:9735" >/dev/null
cli_payer fundchannel "$HOLD_ID" 10000000 >/dev/null   # 0.1 BTC channel
$BCLI generatetoaddress 6 "$MINER_ADDR" >/dev/null

echo "[5/6] waiting for channel active..."
for i in $(seq 1 60); do
    STATE=$(cli_payer listpeerchannels | grep -o '"state": *"[^"]*"' | head -1 | cut -d'"' -f4 || true)
    [[ "$STATE" == "CHANNELD_NORMAL" ]] && break
    [[ $i == 60 ]] && { echo "channel failed to confirm (state=$STATE)"; exit 1; }
    sleep 1
done

echo "[6/6] verifying hold plugin..."
cli_hold help holdinvoice >/dev/null || { echo "hold plugin not loaded!"; docker logs cln-hold-test | tail -20; exit 1; }

echo
echo "ready:"
echo "  holder socket: $HOLD_DIR/regtest/lightning-rpc"
echo "  payer socket:  $PAYER_DIR/regtest/lightning-rpc"
echo "  channel:       payer -> holder, 0.1 BTC"
echo
echo "run the test:"
echo "  CLN_SOCKET_PATH=$HOLD_DIR/regtest/lightning-rpc \\"
echo "  CLN_PAYER_SOCKET_PATH=$PAYER_DIR/regtest/lightning-rpc \\"
echo "    cargo test -p deposits-node --test cln_hold_invoice -- --ignored --nocapture"
