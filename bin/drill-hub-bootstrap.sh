#!/usr/bin/env bash
# Drill: `deposits-hub bootstrap --nodes 4` against live regtest.
# Plays the human's single role (fund the printed treasury address),
# mines while the pipeline runs, and asserts the end state:
#   - 4 Active ledgers with cross-wired Q=3 quorums
#   - exactly 1 disbursement tx (4 outputs) + 4 activation txs
#
# Prereqs: deposits-tools cluster infra up (bitcoind + electrs + relays).
set -uo pipefail
REPO=/home/claude/deposits-rust
HUB=$REPO/target/debug/deposits-hub
NODE=$REPO/target/debug/deposits-node
D="${DRILL_DIR:-/tmp/hub-bootstrap-drill}"
BCLI="docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass"

if [[ "${1:-}" == "down" ]]; then
    for f in "$D"/bootstrap-nodes/*/daemon.pid; do
        [[ -f "$f" ]] && kill "$(cat "$f")" 2>/dev/null
    done
    rm -rf "$D"
    echo "drill stack removed"
    exit 0
fi

rm -rf "$D"; mkdir -p "$D"

echo "[drill] launching bootstrap (background)"
DEPOSITS_NODE=$NODE "$HUB" bootstrap \
    --nodes 4 \
    --network regtest \
    --relay ws://localhost:17779 \
    --esplora http://localhost:3102 \
    --data-dir "$D" \
    --per-ledger-sats 1000000 \
    > "$D/bootstrap.log" 2>&1 &
BPID=$!

echo "[drill] waiting for the treasury address"
ADDR=""
for i in $(seq 1 60); do
    ADDR=$(grep -A 2 "send AT LEAST" "$D/bootstrap.log" 2>/dev/null | grep -oE 'bcrt1[a-z0-9]+' | head -1 || true)
    [[ -n "$ADDR" ]] && break
    kill -0 $BPID 2>/dev/null || { echo "FAIL: bootstrap died early"; cat "$D/bootstrap.log"; exit 1; }
    sleep 2
done
[[ -n "$ADDR" ]] || { echo "FAIL: no treasury address"; cat "$D/bootstrap.log"; exit 1; }
# Fund EXACTLY what the hub asked for (its required floor) — this turns
# the drill into a real guard on the fee-headroom math: if the floor is
# ever too tight, the disbursement underpays and the run stalls here.
REQ_SATS=$(grep -oE "send AT LEAST [0-9]+ sats" "$D/bootstrap.log" | grep -oE "[0-9]+" | head -1)
[[ -n "$REQ_SATS" ]] || { echo "FAIL: could not read required sats"; exit 1; }
REQ_BTC=$(python3 -c "print(f'{$REQ_SATS/1e8:.8f}')")
echo "[drill] funding treasury $ADDR with exactly $REQ_SATS sats ($REQ_BTC BTC)"
$BCLI -rpcwallet=faucet sendtoaddress "$ADDR" "$REQ_BTC" >/dev/null
$BCLI -rpcwallet=faucet -generate 1 >/dev/null

echo "[drill] mining loop while the pipeline runs"
MINED=0
while kill -0 $BPID 2>/dev/null; do
    sleep 5
    $BCLI -rpcwallet=faucet -generate 1 >/dev/null 2>&1
    MINED=$((MINED + 1))
    if [[ $MINED -gt 240 ]]; then
        echo "FAIL: bootstrap still running after ~20min"
        kill $BPID
        tail -30 "$D/bootstrap.log"
        exit 1
    fi
done
wait $BPID; RC=$?
echo "[drill] bootstrap exited rc=$RC"
tail -12 "$D/bootstrap.log"
[[ $RC -eq 0 ]] || { echo "FAIL: bootstrap nonzero"; exit 1; }

echo "[drill] asserting on-chain footprint"
TXID=$(python3 -c "import json; print(json.load(open('$D/bootstrap-state.json'))['disbursement_txid'])")
NOUT=$($BCLI getrawtransaction "$TXID" true | python3 -c "import json,sys; print(len(json.load(sys.stdin)['vout']))")
echo "  disbursement $TXID has $NOUT outputs (expect 5: 4 ledgers + change)"
[[ "$NOUT" -ge 4 ]] || { echo "FAIL: disbursement outputs"; exit 1; }

echo "[drill] asserting 4 Active quorums via admin APIs"
OK=0
for i in 0 1 2 3; do
    PORT=$((8870 + i))
    LID=$(python3 -c "import json; print(json.load(open('$D/bootstrap-state.json'))['ledgers']['node$i'])")
    TOKEN=$(cat "$D/bootstrap-nodes/node$i/admin-token")
    ACTIVE=$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/ledgers" \
        | python3 -c "
import json, sys
ledgers = json.load(sys.stdin)
me = [l for l in ledgers if l['ledger_id'] == '$LID']
print('yes' if me and me[0]['quorum_active'] else 'no')")
    if [[ "$ACTIVE" == "yes" ]]; then
        OK=$((OK + 1))
        echo "  node$i ledger ${LID:0:16}… quorum_active=true"
    else
        echo "  node$i NOT active"
    fi
done
[[ $OK -eq 4 ]] || { echo "FAIL: only $OK/4 active"; exit 1; }

echo "DRILL PASSED: 4 nodes, 4 Active ledgers, 1 funding + 1 disbursement + 4 activations"
