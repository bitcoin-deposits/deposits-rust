#!/usr/bin/env bash
# Set up the deposits-bridge daemon for the bridge-receive drill:
# one funded deposit on op2's ledger, LN side = the LND holder from
# ./bin/setup-lnd-hold.sh (so cln-payer-test can pay its invoices over
# the existing channel).
#
# Prereqs: deposits cluster running (deposits-tools/bin/setup.sh),
#          ./bin/setup-cln-hold.sh && ./bin/setup-lnd-hold.sh stacks up.
#
# Usage:
#   ./bin/setup-bridge.sh           # fresh: open+fund deposit, start daemon
#   ./bin/setup-bridge.sh down      # stop daemon, remove data
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR=/tmp/deposits-bridge-test
SEED="b21d6e000000000000000000000000000000000000000000000000000000000b"
RELAY="${RELAY_LEDGERS:-ws://localhost:17779}"
WALLET="${DEPOSITS_WALLET:-$REPO_ROOT/target/debug/deposits-wallet}"
NODE="${DEPOSITS_NODE:-$REPO_ROOT/target/debug/deposits-node}"
BRIDGE="$REPO_ROOT/target/debug/deposits-bridge"
DEPOSIT_SATS=200000     # bridge liquidity: covers several test receives
OP2_DATA="$REPO_ROOT/deposits-tools/data/op2"
OP2_SEED="6f70320000000000000000000000000000000000000000000000000000000000"

if [[ "${1:-}" == "down" ]]; then
    [[ -f "$DATA_DIR/bridge.pid" ]] && kill "$(cat $DATA_DIR/bridge.pid)" 2>/dev/null || true
    pkill -f "deposits-bridge --" 2>/dev/null || true
    rm -rf "$DATA_DIR"
    echo "bridge test stack removed"
    exit 0
fi

[[ -x "$WALLET" ]] || { echo "deposits-wallet missing — cargo build -p deposits-wallet"; exit 1; }
[[ -x "$NODE" ]] || { echo "deposits-node missing — cargo build -p deposits-node"; exit 1; }
[[ -x "$BRIDGE" ]] || { echo "deposits-bridge missing — cargo build -p deposits-node --bin deposits-bridge"; exit 1; }

LEDGER=$(cat "$REPO_ROOT/deposits-tools/data/state/ledger_2_1" 2>/dev/null | tr -d '[:space:]')
[[ -n "$LEDGER" ]] || { echo "ledger_2_1 state missing — run deposits-tools/bin/setup.sh"; exit 1; }

pkill -f "deposits-bridge --" 2>/dev/null || true
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
echo "$SEED" > "$DATA_DIR/seed.hex"

echo "[1/4] opening bridge deposit on ledger ${LEDGER:0:16}…"
"$WALLET" open "$LEDGER" --alias bridge --seed "$SEED" \
    --data-dir "$DATA_DIR" --network regtest --relay "$RELAY" \
    | tail -2

DEPOSIT_PK=$(python3 -c "
import json
d=json.load(open('$DATA_DIR/deposits.json'))
e=[x for x in d if x.get('alias')=='bridge'][0]
print(e.get('deposit_pubkey') or e['descriptor'][3:-1])")
echo "  deposit pubkey: ${DEPOSIT_PK:0:16}…"

echo "[2/4] crediting bridge deposit ($DEPOSIT_SATS sats) via op2…"
sleep 6   # let the DepositOpen propagate to op2's cosigners
DEPOSIT_ID=$(python3 -c "
import json
d=json.load(open('$DATA_DIR/deposits.json'))
e=[x for x in d if x.get('alias')=='bridge'][0]
print(e['deposit_id'])")
"$NODE" deposit credit "$LEDGER" "$DEPOSIT_ID" \
    "$((DEPOSIT_SATS * 1000))" "bridge-fund-$(date +%s)" \
    --seed "$OP2_SEED" --name op2 --network regtest \
    --data-dir "$OP2_DATA" --esplora http://localhost:3102 \
    --relay "$RELAY" 2>&1 | tail -2

echo "[2b/4] ensuring bridge LND has outbound liquidity (pay direction)…"
# LND can't SEND until its local balance clears the channel reserve
# (1% of capacity = 50k sats on the 0.05 BTC channel). Push 150k from
# cln-payer via a plain invoice if we're below 80k.
LND_MAC=$(xxd -p -c2000 /tmp/lnd-hold-test/data/chain/bitcoin/regtest/admin.macaroon)
LND_LOCAL=$(curl -sk -H "Grpc-Metadata-macaroon: $LND_MAC" \
    https://localhost:8180/v1/balance/channels \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('local_balance',{}).get('sat','0'))" 2>/dev/null || echo 0)
if [[ "${LND_LOCAL:-0}" -lt 80000 ]]; then
    PAYREQ=$(curl -sk -X POST -H "Grpc-Metadata-macaroon: $LND_MAC" \
        https://localhost:8180/v1/invoices \
        -d '{"value": "150000", "memo": "bridge outbound liquidity"}' \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['payment_request'])")
    python3 - "$PAYREQ" <<'PYEOF'
import socket, json, sys
s = socket.socket(socket.AF_UNIX); s.connect("/tmp/cln-payer-test/regtest/lightning-rpc"); s.settimeout(60)
s.sendall((json.dumps({"jsonrpc":"2.0","id":1,"method":"pay","params":{"bolt11":sys.argv[1]}})+"\n").encode())
buf = b""
while not buf.endswith(b"\n"): buf += s.recv(65536)
r = json.loads(buf)
status = r.get("result",{}).get("status") or r.get("error")
print(f"  liquidity push: {status}")
PYEOF
else
    echo "  LND local balance ${LND_LOCAL} sats — sufficient"
fi

echo "[3/4] starting deposits-bridge (LN backend: lnd-hold-test)…"
LIGHTNING_BACKEND=lnd \
LND_REST_URL=https://localhost:8180 \
LND_MACAROON_FILE=/tmp/lnd-hold-test/data/chain/bitcoin/regtest/admin.macaroon \
LND_TLS_INSECURE=1 \
BRIDGE_HOLD_WINDOW_BLOCKS=140 \
nohup "$BRIDGE" \
    --relay "$RELAY" --ledgers-relay "$RELAY" \
    --network regtest \
    --node "bridge:$DATA_DIR" \
    > "$DATA_DIR/bridge.log" 2>&1 &
echo $! > "$DATA_DIR/bridge.pid"

echo "[4/4] waiting for daemon ready (npub in log)…"
for i in $(seq 1 30); do
    NPUB=$(grep -oE "bridge pubkey: [0-9a-f]{64}" "$DATA_DIR/bridge.log" 2>/dev/null | head -1 | awk '{print $3}' || true)
    [[ -n "$NPUB" ]] && break
    sleep 1
done
if [[ -z "${NPUB:-}" ]]; then
    # Fallback: derive via the same m/44'/1237' path the daemon uses.
    NPUB=$(grep -oE "[0-9a-f]{64}" "$DATA_DIR/bridge.log" | head -1 || true)
fi
[[ -n "$NPUB" ]] || { echo "daemon did not report its pubkey"; tail -20 "$DATA_DIR/bridge.log"; exit 1; }
echo "$NPUB" > "$DATA_DIR/bridge.npub"

echo
echo "ready:"
echo "  bridge npub:  $NPUB"
echo "  ledger:       $LEDGER"
echo "  log:          $DATA_DIR/bridge.log"
echo "  status:       http://localhost:9740/status"
echo
echo "drill:"
echo "  BRIDGE_NPUB=\$(cat $DATA_DIR/bridge.npub) BRIDGE_LEDGER=$LEDGER \\"
echo "  CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \\"
echo "    cargo test -p deposits-test --test bridge_receive -- --ignored --nocapture"
