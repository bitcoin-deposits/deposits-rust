#!/usr/bin/env bash
# Adopt stranded taproot vaults across all hub-bootstrap nodes.
#
# Use when `quorum begin` broadcast the activation tx (the funding UTXO is
# spent into the Q=N vault on-chain) but the daemon lost the local taproot
# record — e.g. a timeout during the post-broadcast confirmation wait, before
# the persist-after-broadcast fix. The funds are safe in the vault; this
# re-derives the local record so a subsequent `quorum begin` resumes.
#
# Reads node->ledger and node->deposit-address from bootstrap-state.json and
# runs `recovery adopt-vault` per node, always via --seed-file (never the seed
# on the command line, where it would land in `ps`/shell history). Idempotent:
# re-running on an already-adopted node just re-writes the same record.
#
# Daemons MUST be stopped first (this instantiates a wallet per node).
#
# Env overrides: HUB_DIR, NODE (binary), ESPLORA, NETWORK.
set -euo pipefail

HUB_DIR="${HUB_DIR:-$HOME/.deposits-hub}"
NODE="${NODE:-$HOME/deposits-rust/target/release/deposits-node}"
ESPLORA="${ESPLORA:-http://localhost:3100}"
NETWORK="${NETWORK:-bitcoin}"
STATE="$HUB_DIR/bootstrap-state.json"

[[ -x "$NODE" ]]   || { echo "deposits-node not found/executable at $NODE (set NODE=...)"; exit 1; }
[[ -f "$STATE" ]]  || { echo "no bootstrap-state.json at $STATE (set HUB_DIR=...)"; exit 1; }

if pgrep -f 'deposits-node run' >/dev/null 2>&1; then
    echo "Daemons are still running. Stop them first:"
    echo "  kill \$(cat $HUB_DIR/bootstrap-nodes/node*/daemon.pid)"
    exit 1
fi

mapfile -t ROWS < <(python3 - "$STATE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for name, lid in d["ledgers"].items():
    addr = d["ledger_addresses"].get(name)
    if addr:
        print(f"{name}\t{lid}\t{addr}")
PY
)

[[ ${#ROWS[@]} -gt 0 ]] || { echo "no ledgers found in $STATE"; exit 1; }

for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r name lid addr <<<"$row"
    dir="$HUB_DIR/bootstrap-nodes/$name"
    seed="$dir/seed.hex"
    [[ -f "$seed" ]] || { echo "!! $name: no seed file at $seed — skipping"; continue; }
    echo "=== $name  ledger ${lid:0:16}…  funding $addr ==="
    "$NODE" recovery adopt-vault "$lid" \
        --funding-address "$addr" \
        --data-dir "$dir" \
        --esplora "$ESPLORA" \
        --network "$NETWORK" \
        --seed-file "$seed"
    echo
done

echo "All vaults adopted. Next:"
echo "  1. restart the daemons (or just re-run the hub bootstrap, which respawns them)"
echo "  2. re-run: deposits-hub bootstrap --nodes ${#ROWS[@]} --relay <relay> --esplora $ESPLORA \\"
echo "             --per-ledger-sats 40000 --network $NETWORK"
echo "     each quorum begin resumes via the adopted vault (no new tx) and goes Active."
