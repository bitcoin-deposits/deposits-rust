#!/bin/bash
# Integration test for npub-based access control.
#
# Toggles DEPOSIT_ACCESS_CONTROL on op0 with an allowlist containing one
# xonly npub, then exercises three paths with the CLI wallet:
#
#   1. wallet signs as the allowlisted npub     → deposit_open ACCEPTED
#   2. wallet signs as a different (unknown) npub → deposit_open REJECTED
#      with code=not_authorized, no attestation_required (because we
#      don't configure a domain allowlist for this test)
#   3. remove the allowlisted npub, retry case 1 → now REJECTED
#
# This covers the access-control code path without requiring a
# lightning-verify service — we identify users purely by their Nostr
# pubkey. It's the simplest possible integration for operators who want
# a fixed allowlist of known customers.
#
# Usage:
#   ./bin/test-access-control.sh
#
# Requires the cluster from ./bin/setup.sh to be running.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DEPOSITS_NODE="$REPO_ROOT/target/release/deposits-node"
DEPOSITS_WALLET="$REPO_ROOT/target/release/deposits-wallet"
OP_DATA="$REPO_ROOT/deposits-tools/data/op0"
OP_SEED="6f70300000000000000000000000000000000000000000000000000000000000"

RELAY="ws://localhost:7779"
ELECTRUM="http://localhost:3201"
TEST_WALLET_DIR=$(mktemp -d)

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }

cleanup() {
    rm -rf "$TEST_WALLET_DIR" /tmp/ac-test-*.nsec 2>/dev/null || true
}
trap cleanup EXIT

# --- Pre-flight ---
if ! pgrep -f "name op0" >/dev/null; then
    fail "op0 is not running — start the cluster with ./bin/setup.sh first"
fi
if [ ! -x "$DEPOSITS_NODE" ] || [ ! -x "$DEPOSITS_WALLET" ]; then
    fail "release binaries missing — run 'cargo build --release -p deposits-node'"
fi

# --- Discover op0's ledger ---
log "discovering op0's ledger..."
OP0_LEDGER=$("$DEPOSITS_WALLET" discover --relay "$RELAY" --json --data-dir "$TEST_WALLET_DIR" 2>/dev/null \
    | python3 -c '
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    if d.get("type") == "ledger" and d.get("operator_name") == "op0":
        print(d["ledger_id"])
        break
')
[ -n "$OP0_LEDGER" ] || fail "couldn't find a ledger owned by op0"
log "  ledger: ${OP0_LEDGER:0:16}..."

# --- Generate two test keys ---
# keygen prints: <secret_hex> <compressed_pubkey_hex>
KEY_A=$("$DEPOSITS_NODE" keygen)
KEY_B=$("$DEPOSITS_NODE" keygen)
SEC_A=$(echo "$KEY_A" | awk '{print $1}')
SEC_B=$(echo "$KEY_B" | awk '{print $1}')
# Strip the compression prefix (02/03) to get xonly.
XONLY_A=$(echo "$KEY_A" | awk '{print substr($2, 3)}')
XONLY_B=$(echo "$KEY_B" | awk '{print substr($2, 3)}')
echo "$SEC_A" > /tmp/ac-test-a.nsec
echo "$SEC_B" > /tmp/ac-test-b.nsec
chmod 600 /tmp/ac-test-a.nsec /tmp/ac-test-b.nsec
log "  allowlisted npub: ${XONLY_A:0:16}..."
log "  outsider  npub:   ${XONLY_B:0:16}..."

# --- Restart op0 with ACL enabled + allowlist = [KEY_A] ---
log "restarting op0 with DEPOSIT_ACCESS_CONTROL + allowlist([KEY_A])..."
OP0_PID=$(pgrep -f "name op0" | head -1)
kill "$OP0_PID"
sleep 2

BACKUP=$(mktemp)
if [ -f "$OP_DATA/deposit_allowlist.txt" ]; then
    cp "$OP_DATA/deposit_allowlist.txt" "$BACKUP"
fi
echo "$XONLY_A" > "$OP_DATA/deposit_allowlist.txt"

start_op0_acl() {
    DEPOSIT_ACCESS_CONTROL=true \
    RUST_LOG=warn \
    "$DEPOSITS_NODE" run \
        --seed "$OP_SEED" --name op0 \
        --network regtest --data-dir "$OP_DATA" \
        --esplora "$ELECTRUM" \
        --relay ws://localhost:7779 --relay ws://localhost:7780 \
        >> "$OP_DATA/daemon.log" 2>&1 &
    NEW_PID=$!
    echo "$NEW_PID" > "$OP_DATA/daemon.pid"
    sleep 5
    if ! kill -0 "$NEW_PID" 2>/dev/null; then
        fail "op0 didn't come back up — check $OP_DATA/daemon.log"
    fi
}
start_op0_acl

restore_op0() {
    if [ -n "${NEW_PID:-}" ] && kill -0 "$NEW_PID" 2>/dev/null; then
        kill "$NEW_PID"
        sleep 2
    fi
    if [ -s "$BACKUP" ]; then
        cp "$BACKUP" "$OP_DATA/deposit_allowlist.txt"
    else
        rm -f "$OP_DATA/deposit_allowlist.txt"
    fi
    rm -f "$BACKUP"
    RUST_LOG=warn "$DEPOSITS_NODE" run \
        --seed "$OP_SEED" --name op0 \
        --network regtest --data-dir "$OP_DATA" \
        --esplora "$ELECTRUM" \
        --relay ws://localhost:7779 --relay ws://localhost:7780 \
        >> "$OP_DATA/daemon.log" 2>&1 &
    echo $! > "$OP_DATA/daemon.pid"
    log "op0 restored"
    cleanup
}
trap restore_op0 EXIT

# --- Case 1: allowlisted npub → SUCCESS ---
log ""
log "case 1: allowlisted npub should be accepted"
OUT_A=$("$DEPOSITS_WALLET" open "$OP0_LEDGER" 100000 \
    --alias ac-a --nsec-file /tmp/ac-test-a.nsec \
    --data-dir "$TEST_WALLET_DIR" \
    --relay "$RELAY" 2>&1 || true)
if echo "$OUT_A" | grep -q "Deposit account created\|Deposit account already exists"; then
    pass "allowlisted npub accepted"
else
    echo "$OUT_A" | tail -15
    fail "allowlisted npub rejected (expected accept)"
fi

# --- Case 2: outsider npub → REJECTED with not_authorized ---
log ""
log "case 2: outsider npub should be rejected with not_authorized"
rm -f "$TEST_WALLET_DIR"/deposits.json
OUT_B=$("$DEPOSITS_WALLET" open "$OP0_LEDGER" 100000 \
    --alias ac-b --nsec-file /tmp/ac-test-b.nsec \
    --data-dir "$TEST_WALLET_DIR" \
    --relay "$RELAY" 2>&1 || true)
if echo "$OUT_B" | grep -qE "code=not_authorized|not_authorized"; then
    pass "outsider npub rejected with not_authorized"
else
    echo "$OUT_B" | tail -15
    fail "expected code=not_authorized rejection"
fi

# --- Case 3: empty allowlist → previously-allowed npub also rejected ---
log ""
log "case 3: allowlist removal revokes access"
rm -f "$TEST_WALLET_DIR"/deposits.json
kill "$NEW_PID" 2>/dev/null || true
sleep 2
: > "$OP_DATA/deposit_allowlist.txt"
start_op0_acl

OUT_C=$("$DEPOSITS_WALLET" open "$OP0_LEDGER" 100000 \
    --alias ac-c --nsec-file /tmp/ac-test-a.nsec \
    --data-dir "$TEST_WALLET_DIR" \
    --relay "$RELAY" 2>&1 || true)
if echo "$OUT_C" | grep -qE "code=not_authorized|not_authorized"; then
    pass "removal revokes the previously-allowlisted npub"
else
    echo "$OUT_C" | tail -15
    fail "expected code=not_authorized after allowlist removal"
fi

log ""
pass "access control: all 3 cases passed"
