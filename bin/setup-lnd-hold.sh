#!/usr/bin/env bash
# Spin up an LND holder for the hold-invoice integration test:
#
#   lnd-hold-test   the "bridge" node — LND with native invoicesrpc hold
#                   invoices (/v2/invoices/hodl, settle, cancel), REST API
#                   exposed to the host.
#
# The payer is the CLN node from ./bin/setup-cln-hold.sh (cln-payer-test),
# which opens a second channel into the LND holder. Run that script first.
#
# Joins the existing deposits regtest network (`deposits-tools_regtest`) and
# uses its bitcoind (alias `bitcoind`, user/pass, ZMQ on 28332/28333).
#
# Host-facing artifacts:
#   REST API:   https://localhost:8180
#   macaroon:   /tmp/lnd-hold-test/data/chain/bitcoin/regtest/admin.macaroon
#   TLS:        self-signed; the test uses LND_TLS_INSECURE=1
#
# Usage:
#   ./bin/setup-lnd-hold.sh         # bring up + channel from cln payer
#   ./bin/setup-lnd-hold.sh down    # tear down
#
# Then:
#   LND_REST_URL=https://localhost:8180 \
#   LND_MACAROON_FILE=/tmp/lnd-hold-test/data/chain/bitcoin/regtest/admin.macaroon \
#   LND_TLS_INSECURE=1 \
#   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
#     cargo test -p deposits-node --test lnd_hold_invoice -- --ignored --nocapture
set -euo pipefail

NETWORK=deposits-tools_regtest
IMG=lightninglabs/lnd:v0.19.0-beta
LND_DIR=/tmp/lnd-hold-test
BCLI="docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass"

lncli_hold() { docker exec lnd-hold-test lncli --network=regtest "$@"; }
cli_payer()  { docker exec cln-payer-test lightning-cli --network=regtest "$@"; }

if [[ "${1:-}" == "down" ]]; then
    docker rm -f lnd-hold-test 2>/dev/null || true
    sudo rm -rf "$LND_DIR" 2>/dev/null || rm -rf "$LND_DIR" || true
    echo "lnd-hold test stack removed"
    exit 0
fi

if ! docker ps --format '{{.Names}}' | grep -q '^cln-payer-test$'; then
    echo "cln-payer-test not running — run ./bin/setup-cln-hold.sh first"
    exit 1
fi

mkdir -p "$LND_DIR"
chmod 777 "$LND_DIR"

docker rm -f lnd-hold-test 2>/dev/null || true

echo "[1/6] starting LND..."
docker run -d --name lnd-hold-test --network "$NETWORK" \
    -p 8180:8080 \
    -v "$LND_DIR":/root/.lnd \
    "$IMG" \
    --bitcoin.regtest \
    --bitcoin.node=bitcoind \
    --bitcoind.rpchost=bitcoind:18443 \
    --bitcoind.rpcuser=user \
    --bitcoind.rpcpass=pass \
    --bitcoind.zmqpubrawblock=tcp://bitcoind:28332 \
    --bitcoind.zmqpubrawtx=tcp://bitcoind:28333 \
    --restlisten=0.0.0.0:8080 \
    --rpclisten=0.0.0.0:10009 \
    --listen=0.0.0.0:9735 \
    --tlsextradomain=lnd-hold-test \
    --tlsextraip=0.0.0.0 \
    --noseedbackup \
    --alias=lnd-hold-test >/dev/null

echo "[2/6] waiting for LND RPC..."
for i in $(seq 1 90); do
    if lncli_hold getinfo >/dev/null 2>&1; then break; fi
    [[ $i == 90 ]] && { echo "LND failed to start"; docker logs lnd-hold-test | tail -20; exit 1; }
    sleep 1
done
docker exec lnd-hold-test chmod -R a+rX /root/.lnd

echo "[3/6] funding LND on-chain (for channel anchors)..."
LND_ADDR=$(lncli_hold newaddress p2wkh | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)
$BCLI -rpcwallet=default sendtoaddress "$LND_ADDR" 0.1 >/dev/null \
    || $BCLI sendtoaddress "$LND_ADDR" 0.1 >/dev/null
MINER_ADDR=$($BCLI -rpcwallet=default getnewaddress 2>/dev/null || $BCLI getnewaddress)
$BCLI generatetoaddress 3 "$MINER_ADDR" >/dev/null

echo "[4/6] opening channel cln-payer -> lnd-hold..."
LND_ID=$(lncli_hold getinfo | grep -o '"identity_pubkey": *"[^"]*"' | cut -d'"' -f4)
cli_payer connect "$LND_ID@lnd-hold-test:9735" >/dev/null
cli_payer fundchannel "$LND_ID" 5000000 >/dev/null   # 0.05 BTC channel
$BCLI generatetoaddress 6 "$MINER_ADDR" >/dev/null

echo "[5/6] waiting for channel active..."
for i in $(seq 1 90); do
    ACTIVE=$(lncli_hold listchannels | grep -c '"active": *true' || true)
    [[ "$ACTIVE" -gt 0 ]] && break
    [[ $i == 90 ]] && { echo "channel failed to activate"; exit 1; }
    sleep 1
done

echo "[6/6] verifying invoicesrpc hold endpoint..."
# AddHoldInvoice with a throwaway hash — proves the subserver is compiled in.
PROBE_HASH=$(head -c 32 /dev/urandom | xxd -p -c64)
lncli_hold addholdinvoice "$PROBE_HASH" --amt 1000 >/dev/null \
    || { echo "invoicesrpc hold endpoint missing!"; exit 1; }
lncli_hold cancelinvoice "$PROBE_HASH" >/dev/null

echo
echo "ready:"
echo "  REST:     https://localhost:8180"
echo "  macaroon: $LND_DIR/data/chain/bitcoin/regtest/admin.macaroon"
echo "  channel:  cln-payer -> lnd-hold, 0.05 BTC"
echo
echo "run the test:"
echo "  LND_REST_URL=https://localhost:8180 \\"
echo "  LND_MACAROON_FILE=$LND_DIR/data/chain/bitcoin/regtest/admin.macaroon \\"
echo "  LND_TLS_INSECURE=1 \\"
echo "  CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \\"
echo "    cargo test -p deposits-node --test lnd_hold_invoice -- --ignored --nocapture"
