#!/bin/bash
# LDK CLI wrapper with self-pay support (subwallet approach)
#
# Drop-in replacement for ldk-server-cli. All operators share a single LDK node;
# when one operator pays an invoice created by another on the same node, this
# wrapper settles internally instead of asking LDK to route to itself.
#
# Also translates between the deposit-node's named-flag CLI style and the
# current ldk-server-cli's positional-arg style.
#
# Environment:
#   LDK_REAL_CLI   Path to the real ldk-server-cli binary
#   LDK_HOST       LDK server host (default: localhost)
#   LDK_PORT       LDK server port (default: 3000)
#   LDK_API_KEY    API key for authentication
#   LDK_TLS_CERT   Path to TLS certificate
#   LDK_SELF_PAY_DIR  Directory for shared self-pay state (default: /tmp/ldk-self-pay)

set -e

REAL_CLI="${LDK_REAL_CLI:-ldk-server-cli}"
SELF_PAY_DIR="${LDK_SELF_PAY_DIR:-/tmp/ldk-self-pay}"
INVOICES_FILE="$SELF_PAY_DIR/invoices.jsonl"
LOCK_FILE="$SELF_PAY_DIR/.lock"

mkdir -p "$SELF_PAY_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Build connection args for the real CLI
conn_args() {
    local args=""
    [ -n "$LDK_HOST" ] && [ -n "$LDK_PORT" ] && args="-b ${LDK_HOST}:${LDK_PORT}"
    [ -n "$LDK_API_KEY" ] && args="$args -a $LDK_API_KEY"
    [ -n "$LDK_TLS_CERT" ] && args="$args -t $LDK_TLS_CERT"
    echo "$args"
}

# Run the real CLI with connection args + given command args.
#
# LD_PRELOAD: gcompat 1.1.0 (Alpine 3.18, the version pluja/strfry:latest
# pins to) references `__res_init` as UND in libgcompat.so.0 but doesn't
# define it, and ships an empty libresolv.so.2 stub. Glibc binaries that
# need `__res_init` (e.g. ldk-server-cli) fail to relocate without a
# definition. The Dockerfile builds a tiny stub that defines
# `__res_init` to return 0 — safe because DNS resolution actually goes
# through musl's getaddrinfo, which doesn't read glibc resolver state.
# Preload the stub only for the CLI invocation, not for the (musl)
# deposit-node process that called us.
real_cli() {
    if [ -f /lib/libres_init_stub.so ]; then
        LD_PRELOAD="/lib/libres_init_stub.so${LD_PRELOAD:+:$LD_PRELOAD}" \
            $REAL_CLI $(conn_args) "$@"
    else
        $REAL_CLI $(conn_args) "$@"
    fi
}

# Atomic append to invoices file (uses flock for concurrent operators)
record_invoice() {
    python3 -c "
import fcntl, sys
lock_path, data, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(lock_path, 'w') as lf:
    fcntl.flock(lf, fcntl.LOCK_EX)
    with open(out_path, 'a') as f:
        f.write(data + '\n')
" "$LOCK_FILE" "$1" "$INVOICES_FILE"
}

# ── BOLT11 payment_hash extraction (pure Python, no deps) ───────────────────

extract_payment_hash() {
    python3 -c "
import sys
invoice = sys.argv[1].lower()
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
pos = invoice.rfind('1')
if pos < 0:
    sys.exit(1)
data = invoice[pos+1:-6]  # strip checksum
values = [CHARSET.find(c) for c in data]
if -1 in values:
    sys.exit(1)
idx = 7  # skip timestamp (7 words)
while idx < len(values) - 2:
    tag = values[idx]; idx += 1
    dlen = values[idx] * 32 + values[idx+1]; idx += 2
    if tag == 1 and dlen == 52:  # payment_hash (tag p = 1)
        bits = 0; acc = 0; result = []
        for v in values[idx:idx+dlen]:
            acc = (acc << 5) | v
            bits += 5
            while bits >= 8:
                bits -= 8
                result.append((acc >> bits) & 0xff)
        print(bytes(result[:32]).hex())
        sys.exit(0)
    idx += dlen
sys.exit(1)
" "$1" 2>/dev/null
}

# Check if a payment_hash exists in the self-pay invoice registry
lookup_invoice() {
    local payment_hash="$1"
    [ -f "$INVOICES_FILE" ] || return 1
    python3 -c "
import sys, json
target = sys.argv[1]
with open(sys.argv[2]) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            rec = json.loads(line)
            if rec.get('payment_hash') == target and rec.get('status') == 'pending':
                print(json.dumps(rec))
                sys.exit(0)
        except Exception: pass
sys.exit(1)
" "$payment_hash" "$INVOICES_FILE"
}

# Mark an invoice as succeeded in the registry
mark_succeeded() {
    local payment_hash="$1"
    python3 -c "
import sys, json, fcntl
target = sys.argv[1]
path = sys.argv[2]
lock = sys.argv[3]
with open(lock, 'w') as lf:
    fcntl.flock(lf, fcntl.LOCK_EX)
    lines = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                if rec.get('payment_hash') == target and rec.get('status') == 'pending':
                    rec['status'] = 'succeeded'
                    rec['preimage'] = '0' * 64
                lines.append(json.dumps(rec))
            except:
                lines.append(line)
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
" "$payment_hash" "$INVOICES_FILE" "$LOCK_FILE"
}

# ── Parse top-level CLI args (connection flags before the command) ───────────

# The deposit node calls us like:
#   ldk-server-cli -b host:port -a key -t cert <command> [args...]
# We need to skip the connection args to find the command.
# But we already get connection info from env vars, so we just need to find the command.

COMMAND=""
COMMAND_ARGS=()
skip_next=false
found_command=false

for arg in "$@"; do
    if $skip_next; then
        skip_next=false
        continue
    fi
    if ! $found_command; then
        case "$arg" in
            -b|-a|-t)
                skip_next=true
                continue
                ;;
            -*)
                # Unknown flag before command — skip
                continue
                ;;
            *)
                COMMAND="$arg"
                found_command=true
                ;;
        esac
    else
        COMMAND_ARGS+=("$arg")
    fi
done

# ── Command dispatch ─────────────────────────────────────────────────────────

case "$COMMAND" in

bolt11-receive)
    # Translate named flags to positional args
    # Deposit node sends: bolt11-receive --amount-msat <N> --description <D>
    # Real CLI expects:   bolt11-receive [AMOUNT] [-d DESCRIPTION] [-e EXPIRY]
    amount=""
    description=""
    description_hash=""
    expiry=""
    i=0
    while [ $i -lt ${#COMMAND_ARGS[@]} ]; do
        case "${COMMAND_ARGS[$i]}" in
            --amount-msat|--amount_msat)
                i=$((i+1)); amount="${COMMAND_ARGS[$i]}msat"
                ;;
            --amount)
                i=$((i+1)); amount="${COMMAND_ARGS[$i]}"
                ;;
            --description|-d)
                i=$((i+1)); description="${COMMAND_ARGS[$i]}"
                ;;
            --description-hash)
                i=$((i+1)); description_hash="${COMMAND_ARGS[$i]}"
                ;;
            --expiry-secs|-e)
                i=$((i+1)); expiry="${COMMAND_ARGS[$i]}"
                ;;
            *)
                # Positional amount (already in correct format)
                [ -z "$amount" ] && amount="${COMMAND_ARGS[$i]}"
                ;;
        esac
        i=$((i+1))
    done

    # Build real CLI args
    cli_args=(bolt11-receive)
    [ -n "$amount" ] && cli_args+=("$amount")
    [ -n "$description" ] && cli_args+=(-d "$description")
    [ -n "$description_hash" ] && cli_args+=(--description-hash "$description_hash")
    [ -n "$expiry" ] && cli_args+=(-e "$expiry")

    # Forward to real CLI
    output=$(real_cli "${cli_args[@]}")
    echo "$output"

    # Record the invoice for self-pay tracking
    payment_hash=$(echo "$output" | python3 -c "import json,sys; print(json.load(sys.stdin).get('payment_hash',''))" 2>/dev/null || echo "")
    if [ -n "$payment_hash" ]; then
        amount_msat=$(echo "$amount" | sed 's/msat$//' | sed 's/sat$/000/' 2>/dev/null || echo "0")
        record_invoice "{\"payment_hash\":\"$payment_hash\",\"amount_msat\":$amount_msat,\"status\":\"pending\",\"ts\":$(date +%s)}"
    fi
    ;;

bolt11-send)
    # Translate named flags to positional args
    # Deposit node sends: bolt11-send --invoice <BOLT11> [--amount-msat <N>]
    # Real CLI expects:   bolt11-send <INVOICE> [AMOUNT]
    invoice=""
    amount=""
    extra_args=()
    i=0
    while [ $i -lt ${#COMMAND_ARGS[@]} ]; do
        case "${COMMAND_ARGS[$i]}" in
            --invoice)
                i=$((i+1)); invoice="${COMMAND_ARGS[$i]}"
                ;;
            --amount-msat|--amount_msat)
                i=$((i+1)); amount="${COMMAND_ARGS[$i]}msat"
                ;;
            --amount)
                i=$((i+1)); amount="${COMMAND_ARGS[$i]}"
                ;;
            --max-total-routing-fee|--max-total-cltv-expiry-delta|--max-path-count|--max-channel-saturation-power-of-half)
                extra_args+=("${COMMAND_ARGS[$i]}")
                i=$((i+1)); extra_args+=("${COMMAND_ARGS[$i]}")
                ;;
            *)
                # Positional invoice
                [ -z "$invoice" ] && invoice="${COMMAND_ARGS[$i]}"
                ;;
        esac
        i=$((i+1))
    done

    if [ -z "$invoice" ]; then
        echo '{"error": "missing invoice argument"}' >&2
        exit 1
    fi

    # Extract payment_hash from the BOLT11 invoice
    payment_hash=$(extract_payment_hash "$invoice")

    # Check if this invoice is in our self-pay registry
    if [ -n "$payment_hash" ] && lookup_invoice "$payment_hash" >/dev/null 2>&1; then
        # Self-pay: settle internally
        mark_succeeded "$payment_hash"
        echo "{\"payment_id\":\"$payment_hash\"}"
    else
        # External payment: forward to real CLI
        cli_args=(bolt11-send "$invoice")
        [ -n "$amount" ] && cli_args+=("$amount")
        cli_args+=("${extra_args[@]}")
        real_cli "${cli_args[@]}"
    fi
    ;;

list-payments)
    # Forward to real CLI, translate response, merge self-pay records
    real_output=$(real_cli list-payments "${COMMAND_ARGS[@]}" 2>/dev/null || echo '{"list":[]}')

    python3 -c "
import json, sys

# Parse real CLI output (has 'list' key)
try:
    real = json.loads(sys.argv[1])
except:
    real = {}
payments = real.get('list', real.get('payments', []))

# Load self-pay succeeded records
invoices_file = sys.argv[2]
try:
    with open(invoices_file) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                if rec.get('status') == 'succeeded':
                    # Check if already in payments list
                    ph = rec['payment_hash']
                    if not any(p.get('id') == ph for p in payments):
                        payments.append({
                            'id': ph,
                            'status': 1,
                            'amount_msat': rec.get('amount_msat'),
                            'preimage': rec.get('preimage', '0' * 64),
                        })
            except: pass
except FileNotFoundError:
    pass

# Output in the format deposit-node expects
print(json.dumps({'payments': payments}))
" "$real_output" "$INVOICES_FILE"
    ;;

*)
    # Pass through everything else unchanged
    real_cli "$COMMAND" "${COMMAND_ARGS[@]}"
    ;;

esac
