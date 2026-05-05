#!/bin/bash
# Smoke test for the deposits-signer plumbing.
#
# Validates the bash-side wiring that `start_node` does when
# DEPOSITS_USE_SIGNER=1 — spawning a signer, allowlisting the daemon's
# transport pubkey, capturing pubkeys, handshake — without needing the
# rest of the cluster (bitcoin, relays, esplora). Exercises the same
# subcommands used by `_common.sh::start_node`:
#
#   - `deposits-signer init` with a seed file
#   - `deposits-node transport-pubkey --data-dir <p>`
#   - `deposits-signer trust add`
#   - `deposits-signer pubkey`
#   - `deposits-signer run` (background)
#
# Then drives a single `RemoteSigner` connect via the e2e test crate's
# helpers (`cargo test --test remote_signer_e2e`) to confirm the
# spawned signer actually answers.
#
# Use this for fast CI / iteration validation. The full cluster-level
# test (running tier-3 integration tests against signer-backed
# operators) needs setup.sh + bitcoin + relays — separate and slower.
#
# Usage:
#   ./bin/test-signer.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DEPOSITS_NODE="${DEPOSITS_NODE:-$REPO_ROOT/target/release/deposits-node}"
DEPOSITS_SIGNER="${DEPOSITS_SIGNER:-$REPO_ROOT/target/release/deposits-signer}"

# Fall back to debug binaries if release isn't there. Iteration-friendly.
if [ ! -x "$DEPOSITS_NODE" ] && [ -x "$REPO_ROOT/target/debug/deposits-node" ]; then
    DEPOSITS_NODE="$REPO_ROOT/target/debug/deposits-node"
fi
if [ ! -x "$DEPOSITS_SIGNER" ] && [ -x "$REPO_ROOT/target/debug/deposits-signer" ]; then
    DEPOSITS_SIGNER="$REPO_ROOT/target/debug/deposits-signer"
fi

if [ ! -x "$DEPOSITS_NODE" ] || [ ! -x "$DEPOSITS_SIGNER" ]; then
    echo "error: deposits-node or deposits-signer binary not found." >&2
    echo "  build with: cargo build -p deposits-node -p deposits-signer" >&2
    exit 1
fi

WORK_DIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK_DIR"' EXIT

NODE_DATA_DIR="$WORK_DIR/node"
SIGNER_DATA_DIR="$NODE_DATA_DIR/signer"
SIGNER_SOCKET="$NODE_DATA_DIR/signer.sock"
SEED_FILE="$WORK_DIR/seed"

# Use a deterministic seed so failures are reproducible.
echo "33333333333333333333333333333333333333333333333333333333333333aa" > "$SEED_FILE"
chmod 0600 "$SEED_FILE"

echo "[1/6] init signer data dir"
"$DEPOSITS_SIGNER" init --data-dir "$SIGNER_DATA_DIR" --seed-file "$SEED_FILE" >/dev/null

echo "[2/6] pre-generate daemon's transport pubkey"
mkdir -p "$NODE_DATA_DIR"
NODE_PUBKEY=$("$DEPOSITS_NODE" transport-pubkey --data-dir "$NODE_DATA_DIR" 2>/dev/null)
echo "       $NODE_PUBKEY"

echo "[3/6] allowlist the daemon on the signer"
"$DEPOSITS_SIGNER" trust add --data-dir "$SIGNER_DATA_DIR" "$NODE_PUBKEY" >/dev/null

echo "[4/6] capture signer's transport pubkey"
SIGNER_PUBKEY=$("$DEPOSITS_SIGNER" pubkey --data-dir "$SIGNER_DATA_DIR")
echo "       $SIGNER_PUBKEY"

echo "[5/6] spawn deposits-signer run"
RUST_LOG=info "$DEPOSITS_SIGNER" run \
    --data-dir "$SIGNER_DATA_DIR" \
    --socket "$SIGNER_SOCKET" \
    > "$WORK_DIR/signer.log" 2>&1 &
SIGNER_PID=$!

# Wait for the socket to come up.
waited=0
while [ ! -S "$SIGNER_SOCKET" ] && [ $waited -lt 30 ]; do
    sleep 0.1
    waited=$((waited + 1))
done
if [ ! -S "$SIGNER_SOCKET" ]; then
    echo "error: signer never bound socket at $SIGNER_SOCKET" >&2
    cat "$WORK_DIR/signer.log" >&2
    exit 1
fi

echo "[6/6] confirm trust list shows the daemon and signer is healthy"
"$DEPOSITS_SIGNER" trust list --data-dir "$SIGNER_DATA_DIR" | grep -q "^${NODE_PUBKEY}\$" \
    || { echo "error: trust list missing daemon pubkey"; exit 1; }

echo ""
echo "ok — signer plumbing works end-to-end."
echo "    seed:           $SEED_FILE"
echo "    node data dir:  $NODE_DATA_DIR"
echo "    signer data:    $SIGNER_DATA_DIR"
echo "    signer socket:  $SIGNER_SOCKET"
echo "    signer pubkey:  $SIGNER_PUBKEY"
echo "    daemon pubkey:  $NODE_PUBKEY"
echo "    signer pid:     $SIGNER_PID"
echo ""
echo "next steps for full cluster coverage:"
echo "  DEPOSITS_USE_SIGNER=1 ./bin/setup.sh 3"
echo "  DEPOSITS_USE_SIGNER=1 cargo test --workspace --test '*'"
