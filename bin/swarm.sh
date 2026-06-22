#!/usr/bin/env bash
#
# swarm.sh — pour sand in the top.
#
# Launches one INDEPENDENT `deposit-bot` process per deposit found in a
# wallet's deposits.json. Each bot autonomously forwards funds to a random
# peer on its ledger whenever its balance rises above a floor; funds bleed to
# fees (which return to you as the operator). Top deposits back up out of band
# and the bots resume.
#
# There is no central controller — this script just spawns the fleet and, on
# Ctrl-C, kills it. Mix behaviors by launching bots by hand with different
# --behavior flags; this launcher uses the default (forward) for all.
#
# Usage:
#   bin/swarm.sh --data-dir /data/alice --seed <64-hex> [--relay ws://localhost:7801] \
#                [--network regtest] [--floor-sats 1000] [--reserve-sats 200] \
#                [--interval-ms 1500] [--limit N]
#
# Requires: a built `deposit-bot` (cargo build -p deposits-node --bin deposit-bot)
# and python3 (to read aliases out of deposits.json).

set -euo pipefail

DATA_DIR=""
SEED=""
RELAY="ws://localhost:7801"
NETWORK="regtest"
LIMIT=0
PASSTHRU=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --seed)     SEED="$2"; shift 2 ;;
    --relay)    RELAY="$2"; shift 2 ;;
    --network)  NETWORK="$2"; shift 2 ;;
    --limit)    LIMIT="$2"; shift 2 ;;
    # Everything else is forwarded verbatim to each deposit-bot
    # (e.g. --floor-sats, --reserve-sats, --interval-ms, --fee-rate-bps).
    *)          PASSTHRU+=("$1"); shift ;;
  esac
done

[[ -n "$DATA_DIR" ]] || { echo "error: --data-dir required" >&2; exit 2; }
# --seed is optional: by default each bot reads the master key from
# <data-dir>/seed.hex (the wallet's own location), so it stays off the
# command line. Pass --seed only for throwaway/regtest keys.

DEPOSITS_JSON="$DATA_DIR/deposits.json"
[[ -f "$DEPOSITS_JSON" ]] || { echo "error: no deposits.json at $DEPOSITS_JSON" >&2; exit 2; }

# Locate the binary (prefer release, fall back to debug, then PATH).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOT=""
for cand in "$ROOT/target/release/deposit-bot" "$ROOT/target/debug/deposit-bot" "$(command -v deposit-bot || true)"; do
  if [[ -n "$cand" && -x "$cand" ]]; then BOT="$cand"; break; fi
done
[[ -n "$BOT" ]] || { echo "error: deposit-bot binary not found — run: cargo build -p deposits-node --bin deposit-bot" >&2; exit 2; }

# Pull deposit aliases out of deposits.json (one per line).
mapfile -t ALIASES < <(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    entries = json.load(f)
for e in entries:
    a = e.get("alias")
    if a:
        print(a)
' "$DEPOSITS_JSON")

[[ ${#ALIASES[@]} -gt 0 ]] || { echo "error: no deposits with an alias in $DEPOSITS_JSON" >&2; exit 2; }

if [[ "$LIMIT" -gt 0 && "$LIMIT" -lt ${#ALIASES[@]} ]]; then
  ALIASES=("${ALIASES[@]:0:$LIMIT}")
fi

echo "swarm: launching ${#ALIASES[@]} bot(s) against $RELAY"
echo "       binary: $BOT"
echo

PIDS=()
cleanup() {
  echo
  echo "swarm: stopping ${#PIDS[@]} bot(s)…"
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

SEED_ARGS=()
[[ -n "$SEED" ]] && SEED_ARGS=(--seed "$SEED")

for alias in "${ALIASES[@]}"; do
  "$BOT" \
    --data-dir "$DATA_DIR" \
    "${SEED_ARGS[@]}" \
    --alias "$alias" \
    --relay "$RELAY" \
    --network "$NETWORK" \
    "${PASSTHRU[@]}" 2>&1 | sed "s/^/[$alias] /" &
  PIDS+=($!)
  echo "  + $alias (pid $!)"
  sleep 0.2
done

echo
echo "swarm: ${#PIDS[@]} bot(s) running. Ctrl-C to stop the fleet."
wait
