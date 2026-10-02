#!/usr/bin/env bash
# ci-regtest.sh — hermetic four-operator regtest, end to end, against the current CLI.
#
#   1  quorum      alice opens ledger A; bob, charlie, diana consent; funded QuorumBegin
#   2  transfers   two wallet deposits on A, operator credit, an intra-ledger send
#   3  dispute     alice equivocates (two cosigned updates at one sequence); the members
#                  detect it, prove it, confiscate the vault to the lottery output, and one
#                  claims custody
#   4  skip        bob signs an update that skips sequences; the members prove it (a
#                  NonConformingUpdate) and confiscate B's vault
#   5  recovery    charlie's ledger C with a short quorum expiry: diana's single-member
#                  vault spend is non-final before quorum_expiry + 720 (DEP-03), then confirms
#
# Everything runs natively under $WORK: bitcoind (regtest), an Esplora shim over it
# (the node's BDK wallet syncs through Esplora), a relay, four deposits-node daemons.
#
#   RELAY_IMPL=strfry   build-time strfry at $STRFRY_BIN (CI)
#   RELAY_URL=ws://...  use a relay that is already running (local runs)
#   BITCOIND, BITCOIN_CLI, DEPOSITS_NODE, DEPOSITS_WALLET  binaries
#   KEEP=1              leave $WORK and the processes up after the run
#   PHASES="1 2 3 4"    subset to run (later phases need the earlier ones)
#
# The node must be built with --features dangerous-testing (phase 3's invalid update).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
NODE="${DEPOSITS_NODE:-$REPO/target/release/deposits-node}"
WALLET="${DEPOSITS_WALLET:-$REPO/target/release/deposits-wallet}"
BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
STRFRY_BIN="${STRFRY_BIN:-$HERE/strfry}"
WORK="${WORK:-$(mktemp -d /tmp/deposits-ci.XXXXXX)}"
PHASES="${PHASES:-1 2 3 4 5}"
BASE="${PORT_BASE:-29400}"
RPC_PORT=$((BASE + 1)); P2P_PORT=$((BASE + 2)); ESPLORA_PORT=$((BASE + 3)); RELAY_PORT=$((BASE + 4))
OPS=(alice bob charlie diana)
ESPLORA_URL="http://127.0.0.1:$ESPLORA_PORT"
BCLI=("$BITCOIN_CLI" -regtest "-datadir=$WORK/btc" "-rpcport=$RPC_PORT")
COOKIE="$WORK/btc/regtest/.cookie"
PIDS=()

step() { echo; echo "=== $* ==="; }
ok()   { echo "  ok: $*"; }
fail() { echo "FAIL: $*" >&2; dump_logs; exit 1; }
dump_logs() {
  for op in "${OPS[@]}"; do
    [ -f "$WORK/$op/node.log" ] || continue
    echo "----- $op (last 40 lines) -----" >&2; tail -40 "$WORK/$op/node.log" | sed 's/\x1b\[[0-9;]*m//g' >&2
  done
}
cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: $WORK left running"; return; }
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  "${BCLI[@]}" stop >/dev/null 2>&1 || true
  sleep 2; rm -rf "$WORK"
}
trap cleanup EXIT
trap 'echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR

bcli()  { "${BCLI[@]}" "$@"; }
mine()  { bcli -rpcwallet=miner -generate "${1:-1}" >/dev/null; }
height(){ bcli getblockcount; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
node_env() { echo "LIGHTNING_BACKEND=none CHAIN_BACKEND=bitcoind BITCOIND_RPC_URL=http://127.0.0.1:$RPC_PORT BITCOIND_COOKIE_FILE=$COOKIE"; }
# cli OP ARGS... — the node CLI against OP's data dir (it reaches the daemon over the relay)
cli() { local op=$1; shift; env $(node_env) RUST_LOG=error timeout "${CLI_TIMEOUT:-180}" "$NODE" "$@" --network regtest --esplora "$ESPLORA_URL" --relay "$RELAY_URL" --data-dir "$WORK/$op" 2>&1 | strip; }
wallet() { env WALLET_DATA_DIR="$WORK/wallet" RUST_LOG=error timeout 180 "$WALLET" "$@" --relay "$RELAY_URL" --network regtest --esplora "$ESPLORA_URL" 2>&1 | strip | grep -vE '^\S*(INFO|WARN|ERROR) '; }
# wait_log OP REGEX SECS [MINE_EVERY] — wait for REGEX in OP's log, optionally mining a block every MINE_EVERY seconds
wait_log() {
  local op=$1 re=$2 secs=$3 every=${4:-0} i
  for i in $(seq 1 "$secs"); do
    grep -qE "$re" "$WORK/$op/node.log" 2>/dev/null && return 0
    [ "$every" -gt 0 ] && [ $((i % every)) -eq 0 ] && mine 1
    sleep 1
  done
  return 1
}
WATCH=(bob charlie diana)
wait_any_log() {   # wait_any_log REGEX SECS MINE_EVERY — first of WATCH whose log matches; prints it
  local re=$1 secs=$2 every=$3 i op
  for i in $(seq 1 "$secs"); do
    for op in "${WATCH[@]}"; do grep -qE "$re" "$WORK/$op/node.log" 2>/dev/null && { echo "$op"; return 0; }; done
    [ $((i % every)) -eq 0 ] && mine 1
    sleep 1
  done
  return 1
}

start_infra() {
  step "infrastructure in $WORK"
  mkdir -p "$WORK/btc"
  "$BITCOIND" -regtest "-datadir=$WORK/btc" "-rpcport=$RPC_PORT" "-port=$P2P_PORT" -listen=0 -txindex=1 \
    -fallbackfee=0.0001 -daemonwait >"$WORK/bitcoind.log" 2>&1 || { cat "$WORK/bitcoind.log"; fail "bitcoind did not start"; }
  bcli createwallet miner >/dev/null; mine 110; ok "bitcoind regtest at $(height)"

  ESPLORA_BITCOIN_CLI="${BCLI[*]}" ESPLORA_PORT=$ESPLORA_PORT python3 "$HERE/esplora-shim.py" >"$WORK/esplora.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 30); do curl -sf "$ESPLORA_URL/blocks/tip/height" >/dev/null && break; sleep 1; done
  curl -sf "$ESPLORA_URL/blocks/tip/height" >/dev/null || fail "esplora shim did not start"
  ok "esplora shim at $ESPLORA_URL"

  if [ -n "${RELAY_URL:-}" ]; then
    ok "relay (external) $RELAY_URL"
  else
    [ -x "$STRFRY_BIN" ] || fail "no relay: set RELAY_URL or build strfry at $STRFRY_BIN"
    mkdir -p "$WORK/strfry-db"
    # The repo's relay template; ephemeral events are kept 300 s, which the
    # confiscation_sign polling relies on. nofiles 0: runners cap open files at 65536.
    sed -e "s|^db = .*|db = \"$WORK/strfry-db/\"|" -e "s|port = 7777|port = $RELAY_PORT|" \
        -e "s|^\( *\)nofiles = .*|\1nofiles = 0|" "$HERE/../config/strfry.conf" >"$WORK/strfry.conf"
    "$STRFRY_BIN" --config="$WORK/strfry.conf" relay >"$WORK/strfry.log" 2>&1 &
    PIDS+=($!)
    RELAY_URL="ws://127.0.0.1:$RELAY_PORT"
    for i in $(seq 1 30); do (exec 3<>/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null && break; sleep 1; done
    (exec 3<>/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null || { cat "$WORK/strfry.log"; fail "strfry did not start"; }
    ok "strfry at $RELAY_URL"
  fi
}

start_node() {
  local op=$1 port=$2 dir="$WORK/$1"
  mkdir -p "$dir"; [ -f "$dir/seed.hex" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$dir/seed.hex"
  ( cd "$dir" && exec env $(node_env) "$NODE" run --network regtest --relay "$RELAY_URL" --esplora "$ESPLORA_URL" \
      --data-dir "$dir" --seed-file "$dir/seed.hex" --name "$op" --admin-bind "127.0.0.1:$port" >>"$dir/node.log" 2>&1 ) &
  PIDS+=($!); echo $! >"$dir/pid"
}
stop_node() { local p; p=$(cat "$WORK/$1/pid" 2>/dev/null) && kill "$p" 2>/dev/null || true; }

start_nodes() {
  step "four operators"
  local i=0 op
  for op in "${OPS[@]}"; do start_node "$op" $((BASE + 10 + i)); i=$((i + 1)); done
  for op in "${OPS[@]}"; do wait_log "$op" 'Wallet synced' 120 || fail "$op did not come up"; done
  for op in "${OPS[@]}"; do
    PK[$op]=$(cli "$op" quorum show-identity | sed -nE 's/.*[Pp]ubkey: *([0-9a-f]{66}).*/\1/p' | head -1)
    [ -n "${PK[$op]}" ] || fail "$op identity"
    COLL[$op]=$(env $(node_env) RUST_LOG=error "$NODE" pubkey-to-p2wpkh --network regtest --seed-file "$WORK/$op/seed.hex" --data-dir "$WORK/$op" 2>&1 | grep -oE 'bcrt1[0-9a-z]+' | head -1)
    [ -n "${COLL[$op]}" ] || fail "$op collateral address"
    ok "$op ${PK[$op]:0:16}  collateral at ${COLL[$op]}"
  done
  fund_collateral
}
fund_collateral() {   # replacement collateral for arming a dispute; each dispute consumes it
  local op
  for op in "${OPS[@]}"; do bcli -rpcwallet=miner sendtoaddress "${COLL[$op]}" 0.02 >/dev/null; done
  mine 1
}

open_ledger() {   # open_ledger OP -> ledger id
  cli "$1" ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p' | head -1
}
members_of() {    # members_of OP LEDGER — member lines of LEDGER in OP's `quorum list`
  cli "$1" quorum list | awk -v l="${2:0:16}" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'
}
add_member() {    # add_member OP LEDGER MEMBER — retried: the CLI can time out waiting on the daemon
  local op=$1 l=$2 m=$3 i
  for i in 1 2 3 4; do
    cli "$op" quorum add "$l" "${PK[$m]}" "${OWN[$m]}" >/dev/null || true
    members_of "$op" "$l" | grep -q "${PK[$m]:0:16}" && return 0
    sleep 5
  done
  return 1
}
begin_quorum() {  # begin_quorum OP LEDGER [extra args] — fund the vault address, then QuorumBegin
  local op=$1 l=$2; shift 2
  local addr out i
  addr=$(cli "$op" ledger address "$l" | grep -oE 'bcrt1[0-9a-z]+' | head -1); [ -n "$addr" ] || fail "$op ledger address"
  bcli -rpcwallet=miner sendtoaddress "$addr" 0.5 >/dev/null; mine 3; sleep 20
  for i in 1 2 3 4 5 6; do
    out=$(cli "$op" quorum begin "$l" --collateral-ratio 0.5 "$@") || true
    echo "$out" | grep -qiE 'No response|timed out' || { echo "$out" | tail -2 | sed 's/^/    /'; return 0; }
    mine 1; sleep 10
  done
  return 1
}
vault_outpoint() {  # the vault the ledger's latest QuorumBegin created, as txid:vout (from `reserves list`)
  cli "$1" reserves list | grep -A3 "${2:0:16}" | grep -oE '[0-9a-f]{64}:[0-9]+' | head -1
}

declare -A PK OWN COLL

phase1() {
  step "1  quorum formation"
  local op
  for op in "${OPS[@]}"; do OWN[$op]=$(open_ledger "$op"); [ -n "${OWN[$op]}" ] || fail "$op ledger open"; done
  A=${OWN[alice]}; ok "A (alice) $A"
  for op in bob charlie diana; do add_member alice "$A" "$op" || fail "add $op to A"; done
  [ "$(members_of alice "$A" | wc -l)" -eq 3 ] || fail "A has $(members_of alice "$A" | wc -l) members"
  ok "bob, charlie, diana consented"
  begin_quorum alice "$A" || fail "quorum begin on A"
  sleep 8
  for op in bob charlie diana; do
    grep -q "cosign_update, ledger=${A:0:16}" "$WORK/$op/node.log" || grep -qE "${A:0:16}.*(QuorumBegin|cosign)" "$WORK/$op/node.log" \
      || fail "$op did not cosign A's QuorumBegin"
  done
  VAULT_A=$(vault_outpoint alice "$A"); ok "QuorumBegin cosigned by every member; vault ${VAULT_A:-?}"
  local rs; rs=$(cli alice reserves list | sed -nE 's/.*active_ruleset: *([a-z0-9-]+).*/\1/p' | head -1)
  [ "$rs" = balance-commit-v4 ] || fail "A's first QuorumBegin is on ruleset '${rs:-?}', not balance-commit-v4"
  ok "ruleset $rs"
  cli alice ledger advertise "$A" | grep -q "Advertisement published" || fail "advertise A"   # wallets find ledgers by their ad
  ok "A advertised"
}

phase2() {
  step "2  deposits and transfers on A"
  mkdir -p "$WORK/wallet"
  wallet open "$A" --alias w1 | grep -q created || fail "wallet open w1"
  wallet open "$A" --alias w2 | grep -q created || fail "wallet open w2"
  local d1 d2
  d1=$(python3 -c "import json; print([d['deposit_id'] for d in json.load(open('$WORK/wallet/deposits.json')) if d['alias']=='w1'][0])")
  d2=$(python3 -c "import json; print([d['deposit_id'] for d in json.load(open('$WORK/wallet/deposits.json')) if d['alias']=='w2'][0])")
  cli alice deposit credit "$A" "$d1" 5000000 "ci-$RANDOM" | grep -q "New balance" || fail "credit w1"
  ok "operator credited w1 5000 sats"
  wallet send w1 1000 --to "$d2" | grep -q "Sent 1000 sats" || fail "send w1 -> w2"
  local bal; bal=$(wallet balance)
  echo "$bal" | grep -E ' w2 ' | grep -q '1000 sats' || fail "w2 balance: $bal"
  ok "w1 -> w2 1000 sats; balances: $(echo "$bal" | grep -E ' w[12] ' | tr -s ' ' | tr '\n' ';')"
}

phase3() {
  step "3  dispute: alice equivocates on A; confiscation, lottery"
  # Two operator-signed, cosigned updates at one sequence: the cosigners ingest the first,
  # then see the second, build the Equivocation proof themselves, and arm.
  local who seeds=() op
  for op in bob charlie diana; do seeds+=(--cosigner-seed "$(cat "$WORK/$op/seed.hex")"); done
  cli alice danger fork-update "$A" --seed "$(cat "$WORK/alice/seed.hex")" --name alice "${seeds[@]}" | grep -E '^U_[AB]' | cut -c1-40 | sed 's/^/    /'
  who=$(wait_any_log "[Ee]quivocat" 180 10) || fail "no member detected the equivocation"
  ok "$who detected the equivocation"
  who=$(wait_any_log "Confiscation transaction in chain" 900 5) || fail "no confiscation of A's vault"
  ok "confiscation confirmed ($who)"
  who=$(wait_any_log "We won the lottery|DisputeAcquire published" 900 5) || fail "no lottery winner took custody"
  ok "lottery won and custody acquired ($who)"
  if [ -n "${VAULT_A:-}" ]; then
    [ -z "$(bcli gettxout "${VAULT_A%:*}" "${VAULT_A#*:}")" ] && ok "A's vault $VAULT_A is spent" || fail "A's vault still unspent"
  fi
}

phase4() {
  step "4  skip: bob signs an update that skips sequences on B; members prove it, confiscate"
  local B=${OWN[bob]} op who vault
  fund_collateral
  for op in alice charlie diana; do add_member bob "$B" "$op" || fail "add $op to B"; done
  begin_quorum bob "$B" || fail "quorum begin on B"
  vault=$(vault_outpoint bob "$B"); [ -n "$vault" ] || fail "B's vault"
  sleep 8
  cli bob danger publish-invalid "$B" skip-sequence | grep -E 'Sequence|Violation' | sed 's/^/    /'
  WATCH=(alice charlie diana)
  who=$(wait_any_log "INVALID UPDATE DETECTED on ledger ${B:0:16}.*sequence_skip" 180 10) || fail "no member reported the skip"
  ok "$who reported the skip as a NonConformingUpdate"
  for i in $(seq 1 180); do
    [ -z "$(bcli gettxout "${vault%:*}" "${vault#*:}")" ] && break
    [ $((i % 5)) -eq 0 ] && mine 1; sleep 1
  done
  [ -z "$(bcli gettxout "${vault%:*}" "${vault#*:}")" ] || fail "B's vault $vault was not confiscated"
  ok "B's vault $vault confiscated"
  WATCH=(bob charlie diana)
}

phase5() {
  step "5  recovery tiers: a single member spends an expired vault after its CLTV"
  local C=${OWN[charlie]} op
  # alice and bob were accused in phases 3-4, so C's one member is diana: with two
  # voters the post-expiry tiers collapse to "single member after expiry + 720".
  add_member charlie "$C" diana || fail "add diana to C"
  begin_quorum charlie "$C" --quorum-expiry-blocks 20 || fail "quorum begin on C"
  sleep 5
  local list; list=$(cli charlie reserves list); echo "$list" | sed 's/^/    /' | head -20
  # Members stop, so nobody auto-disputes the expiry: the tier path is what is under test.
  for op in "${OPS[@]}"; do stop_node "$op"; done
  local qexp t1 dest out
  qexp=$(echo "$list" | sed -nE 's/.*First Expiry: block ([0-9]+).*/\1/p' | head -1)
  t1=$(echo "$list" | sed -nE 's/.*Tier 1: .*timelock=([0-9]+)\).*/\1/p' | head -1)
  [ -n "$qexp" ] && [ -n "$t1" ] || fail "could not read quorum expiry / tier-1 timelock from reserves list"
  [ "$t1" -eq $((qexp + 720)) ] || fail "tier-1 CLTV $t1 is not quorum_expiry + 720 ($((qexp + 720))) as DEP-03 requires"
  ok "quorum expiry $qexp, tier-1 CLTV $t1 = expiry + 720"
  dest=$(bcli -rpcwallet=miner getnewaddress)
  # The spend reads C's history from charlie's replica and signs with diana's seed only.
  mkdir -p "$WORK/seeds/diana"; cp "$WORK/diana/seed.hex" "$WORK/seeds/diana/seed.hex"
  out=$(cli charlie reserves spend "$dest" --ledger "$C" --seed-dir "$WORK/seeds" --tier 1) || true
  echo "$out" | grep -qiE 'non-final|non-BIP68-final|locktime' || fail "tier-1 spend before CLTV was not refused as non-final: $(echo "$out" | tail -3)"
  ok "tier-1 spend at $(height) refused: non-final"
  mine $(( t1 - $(height) + 1 ))
  out=$(cli charlie reserves spend "$dest" --ledger "$C" --seed-dir "$WORK/seeds" --tier 1) || true
  local txid; txid=$(echo "$out" | grep -oE '[0-9a-f]{64}' | tail -1)
  [ -n "$txid" ] && mine 1 && [ "$(bcli getrawtransaction "$txid" true | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations",0))')" -ge 1 ] \
    || fail "tier-1 spend after CLTV: $(echo "$out" | tail -3)"
  ok "tier-1 spend $txid confirmed at $(height)"
}

start_infra
start_nodes
for p in $PHASES; do "phase$p"; done
echo; echo "PASS: phases $PHASES"
