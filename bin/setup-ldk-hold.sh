#!/usr/bin/env bash
# Spin up the FORK ldk-server as a hold-invoice holder for the integration
# test, running on the HOST (not docker) against the existing regtest stack:
#
#   - chain source: the deposits regtest electrs (esplora REST on
#     host port 3102, from docker-compose.lightning.yml / deposits-tools)
#   - p2p: 0.0.0.0:9737 — reachable from containers at the docker network
#     gateway (172.21.0.x → host)
#   - REST API: 127.0.0.1:3201 (TLS, self-signed by ldk-server)
#
# The payer is the CLN node from ./bin/setup-cln-hold.sh, which opens a
# channel into this node. Run that script first.
#
# This exercises BOTH halves of our fork work end-to-end:
#   - the for-hash command set (bolt11-receive-for-hash / claim / fail)
#   - the GetClaimableDetails endpoint + PaymentClaimable event tracking
#     (the claim_deadline plumbing added on the deposits-hold-invoices branch)
#
# Usage:
#   ./bin/setup-ldk-hold.sh         # build (if needed) + start + channel
#   ./bin/setup-ldk-hold.sh down    # stop + remove state
set -euo pipefail

LDK_REPO=/home/claude/ldk-server
LDK_DIR=/tmp/ldk-hold-test
P2P_PORT=9737
REST_PORT=3201
BCLI="docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass"
cli_payer() { docker exec cln-payer-test lightning-cli --network=regtest "$@"; }

if [[ "${1:-}" == "down" ]]; then
    pkill -f "ldk-server.*$LDK_DIR" 2>/dev/null || true
    rm -rf "$LDK_DIR"
    echo "ldk-hold test stack removed"
    exit 0
fi

if ! docker ps --format '{{.Names}}' | grep -q '^cln-payer-test$'; then
    echo "cln-payer-test not running — run ./bin/setup-cln-hold.sh first"
    exit 1
fi

echo "[1/6] building fork ldk-server (debug)..."
(cd "$LDK_REPO" && cargo build --offline -p ldk-server -p ldk-server-cli 2>&1 | tail -1)

pkill -f "ldk-server.*$LDK_DIR" 2>/dev/null || true
rm -rf "$LDK_DIR"
mkdir -p "$LDK_DIR"

cat > "$LDK_DIR/config.toml" <<EOF
[node]
network = "regtest"
listening_addresses = ["0.0.0.0:$P2P_PORT"]
rest_service_address = "127.0.0.1:$REST_PORT"
alias = "ldk-hold-test"

[storage.disk]
dir_path = "$LDK_DIR/data"

[log]
level = "Debug"
file = "$LDK_DIR/ldk-server.log"

[tls]
hosts = ["localhost"]

[esplora]
server_url = "http://localhost:3102"
EOF

echo "[2/6] starting ldk-server..."
nohup "$LDK_REPO/target/debug/ldk-server" "$LDK_DIR/config.toml" \
    > "$LDK_DIR/stdout.log" 2>&1 &
echo $! > "$LDK_DIR/ldk-server.pid"

echo "[3/6] waiting for REST + api key..."
CLI="$LDK_REPO/target/debug/ldk-server-cli"
API_KEY_FILE="$LDK_DIR/data/regtest/api_key"
TLS_CERT="$LDK_DIR/data/tls.crt"
for i in $(seq 1 60); do
    if [[ -f "$API_KEY_FILE" ]] && "$CLI" -b "localhost:$REST_PORT" -a "$(xxd -p -c64 $API_KEY_FILE)" -t "$TLS_CERT" get-node-info >/dev/null 2>&1; then
        break
    fi
    [[ $i == 60 ]] && { echo "ldk-server failed to start"; tail -20 "$LDK_DIR/ldk-server.log" 2>/dev/null || tail -20 "$LDK_DIR/stdout.log"; exit 1; }
    sleep 1
done
API_KEY=$(xxd -p -c64 "$API_KEY_FILE")
LDK_ID=$("$CLI" -b "localhost:$REST_PORT" -a "$API_KEY" -t "$TLS_CERT" get-node-info | grep -o '"node_id": *"[^"]*"' | cut -d'"' -f4)
echo "  node_id: $LDK_ID"

echo "[4/6] funding ldk on-chain + opening channel cln-payer -> ldk-hold..."
# ldk-node rejects inbound ANCHOR channels (which CLN v25 opens by default)
# unless it holds on-chain funds for the per-channel anchor reserve —
# "Channel request rejected" otherwise. Fund it first.
LDK_ADDR=$("$CLI" -b "localhost:$REST_PORT" -a "$API_KEY" -t "$TLS_CERT" onchain-receive | grep -o '"address": *"[^"]*"' | cut -d'"' -f4)
$BCLI -rpcwallet=faucet sendtoaddress "$LDK_ADDR" 0.05 >/dev/null \
    || $BCLI sendtoaddress "$LDK_ADDR" 0.05 >/dev/null
MINER_ADDR=$($BCLI -rpcwallet=faucet getnewaddress 2>/dev/null || $BCLI getnewaddress)
$BCLI generatetoaddress 3 "$MINER_ADDR" >/dev/null
for i in $(seq 1 30); do
    FUNDED=$("$CLI" -b "localhost:$REST_PORT" -a "$API_KEY" -t "$TLS_CERT" get-balances 2>/dev/null | grep -cE '"total_onchain_balance_sats": *[1-9]' || true)
    [[ "$FUNDED" -gt 0 ]] && break
    sleep 2
done

# Containers reach the host via the docker network gateway.
GATEWAY=$(docker network inspect deposits-tools_regtest --format '{{(index .IPAM.Config 0).Gateway}}')
cli_payer connect "$LDK_ID@$GATEWAY:$P2P_PORT" >/dev/null
cli_payer fundchannel "$LDK_ID" 5000000 >/dev/null
$BCLI generatetoaddress 6 "$MINER_ADDR" >/dev/null

echo "[5/6] waiting for channel usable..."
for i in $(seq 1 90); do
    USABLE=$("$CLI" -b "localhost:$REST_PORT" -a "$API_KEY" -t "$TLS_CERT" list-channels 2>/dev/null | grep -c '"is_usable": *true' || true)
    [[ "$USABLE" -gt 0 ]] && break
    [[ $i == 90 ]] && { echo "channel failed to become usable"; exit 1; }
    sleep 2
done

echo "[6/6] verifying for-hash command set..."
"$CLI" bolt11-receive-for-hash --help >/dev/null || { echo "fork CLI missing for-hash commands!"; exit 1; }

echo
echo "ready:"
echo "  REST:      https://localhost:$REST_PORT"
echo "  api key:   $API_KEY_FILE"
echo "  tls cert:  $TLS_CERT"
echo "  channel:   cln-payer -> ldk-hold, 0.05 BTC"
echo
echo "run the test:"
echo "  LDK_CLI=$CLI \\"
echo "  LDK_HOST=localhost LDK_PORT=$REST_PORT \\"
echo "  LDK_API_KEY=$API_KEY \\"
echo "  LDK_TLS_CERT=$TLS_CERT \\"
echo "  LDK_SERVER_BIN=$LDK_REPO/target/debug/ldk-server \\"
echo "  LDK_SERVER_CONFIG=$LDK_DIR/config.toml \\"
echo "  LDK_SERVER_PID_FILE=$LDK_DIR/ldk-server.pid \\"
echo "  CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \\"
echo "    cargo test -p deposits-node --test ldk_hold_invoice -- --ignored --nocapture"
