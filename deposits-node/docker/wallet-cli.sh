#!/bin/bash
# Lightweight deposits wallet CLI.
#
# A standalone wallet for depositors — not tied to any operator node.
# Uses a local seed file and connects to relays directly.
#
# Usage:
#   ./wallet-cli.sh --wallet /path/to/wallet <command> [args...]
#
# Commands:
#   init                      Generate a new wallet seed
#   pubkey [--index N]        Show deposit pubkey at key index
#   open <ledger_id>          Open a deposit on a ledger
#   deposit-id <ledger_id>    Show deposit ID for our key on a ledger
#
# The wallet directory contains:
#   seed          - 32-byte hex secret
#   deposits.json - tracked deposits (auto-created)
#
# Environment:
#   DEPOSITS_NETWORK       - bitcoin/testnet/regtest (default: bitcoin)
#   DEPOSITS_LEDGER_RELAY  - relay for advertisements + requests (default: wss://relay.ynniv.com)
#   DEPOSITS_RELAYS        - comma-separated operator relays

set -e

# Derive a deposit pubkey from seed + index using BIP-84 path.
# Tries: 1) docker container, 2) python secp256k1
derive_pubkey() {
    local seed="$1"
    local index="$2"

    # Try docker container first
    local container=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^(alice|bob|charlie|diana)' | head -1)
    if [ -n "$container" ]; then
        docker exec "$container" deposits-node derive-deposit-key \
            --seed "$seed" --network "$NETWORK" --index "$index" 2>&1 | grep "^pubkey:" | awk '{print $2}'
        return
    fi

    # Fallback: pure Python BIP-32 derivation (no Docker needed)
    python3 - "$seed" "$index" << 'PYEOF'
import hmac, hashlib, struct, sys
seed_hex, key_index = sys.argv[1], int(sys.argv[2])
seed_bytes = bytes.fromhex(seed_hex)
I = hmac.new(b'Bitcoin seed', seed_bytes, hashlib.sha512).digest()
key, chain = I[:32], I[32:]
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def modinv(a, m):
    g, x = m, 0; g1, x1 = a % m, 1
    while g1: g, g1, x, x1 = g1, g % g1, x1, x - (g // g1) * x1
    return x % m
def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2: m = (3*x1*x1) * modinv(2*y1, P) % P
    else: m = (y2 - y1) * modinv(x2 - x1, P) % P
    x3 = (m*m - x1 - x2) % P; y3 = (m*(x1 - x3) - y1) % P
    return (x3, y3)
def scalar_mult(k, pt):
    r = None; a = pt
    while k:
        if k & 1: r = point_add(r, a)
        a = point_add(a, a); k >>= 1
    return r
def compress(pt):
    return (b'\x02' if pt[1] % 2 == 0 else b'\x03') + pt[0].to_bytes(32, 'big')
def ckd(k, c, idx):
    if idx >= 0x80000000:
        data = b'\x00' + k + struct.pack('>I', idx)
    else:
        data = compress(scalar_mult(int.from_bytes(k, 'big'), (Gx, Gy))) + struct.pack('>I', idx)
    h = hmac.new(c, data, hashlib.sha512).digest()
    return ((int.from_bytes(h[:32], 'big') + int.from_bytes(k, 'big')) % N).to_bytes(32, 'big'), h[32:]
for idx in [84 + 0x80000000, 0x80000000, 0x80000000, 0, key_index]:
    key, chain = ckd(key, chain, idx)
print(compress(scalar_mult(int.from_bytes(key, 'big'), (Gx, Gy))).hex())
PYEOF
}

WALLET_DIR=""
NETWORK="${DEPOSITS_NETWORK:-bitcoin}"
LEDGER_RELAY="${DEPOSITS_LEDGER_RELAY:-wss://relay.ynniv.com}"
EXTRA_RELAYS="${DEPOSITS_RELAYS:-}"

# Parse global flags
ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --wallet|-w)
            WALLET_DIR="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --relay)
            LEDGER_RELAY="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${ARGS[@]}"

COMMAND="${1:-}"
shift || true

if [ -z "$WALLET_DIR" ]; then
    echo "Usage: $0 --wallet /path/to/wallet <command> [args...]"
    echo ""
    echo "Commands:"
    echo "  init                Generate a new wallet seed"
    echo "  pubkey [--index N]  Show deposit pubkey"
    echo "  open <ledger_id>   Open a deposit"
    exit 1
fi

mkdir -p "$WALLET_DIR"
SEED_FILE="$WALLET_DIR/seed"

case "$COMMAND" in

init)
    if [ -f "$SEED_FILE" ]; then
        echo "Wallet already exists at $WALLET_DIR"
        echo "Seed: $(cat "$SEED_FILE" | head -c 16)..."
    else
        openssl rand -hex 32 > "$SEED_FILE"
        echo "Created wallet at $WALLET_DIR"
        echo "Seed: $(cat "$SEED_FILE" | head -c 16)..."
    fi
    echo ""
    echo "Your deposit pubkey (index 0):"
    derive_pubkey "$(cat "$SEED_FILE")" 0
    ;;

pubkey)
    INDEX=0
    if [ "$1" = "--index" ] && [ -n "$2" ]; then
        INDEX="$2"
    fi
    derive_pubkey "$(cat "$SEED_FILE")" "$INDEX"
    ;;

open)
    LEDGER_ID="$1"
    INDEX="${2:-0}"

    if [ -z "$LEDGER_ID" ]; then
        echo "Usage: $0 --wallet <dir> open <ledger_id> [key_index]"
        exit 1
    fi

    SEED=$(cat "$SEED_FILE")
    PUBKEY=$(derive_pubkey "$SEED" "$INDEX")

    if [ -z "$PUBKEY" ]; then
        echo "ERROR: Failed to derive key (need python3 with hmac/hashlib)"
        exit 1
    fi

    echo "Opening deposit..."
    echo "  Ledger: ${LEDGER_ID:0:16}..."
    echo "  Pubkey: $PUBKEY"
    echo "  Index:  $INDEX"
    echo "  Relay:  $LEDGER_RELAY"
    echo ""

    # Build relay list
    ALL_RELAYS="$LEDGER_RELAY"
    if [ -n "$EXTRA_RELAYS" ]; then
        ALL_RELAYS="$ALL_RELAYS,$EXTRA_RELAYS"
    fi

    # Send deposit_open request via Nostr (pure Python, no Docker needed)
    python3 -c "
import json, hashlib, time, sys

try:
    from secp256k1 import PrivateKey
except ImportError:
    print('ERROR: pip install secp256k1')
    sys.exit(1)
try:
    import websocket
except ImportError:
    print('ERROR: pip install websocket-client')
    sys.exit(1)

seed = bytes.fromhex('$SEED')
# Derive the same key as derive_pubkey to get the secret
import hmac, struct
I = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
key, chain = I[:32], I[32:]
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def ckd(k, c, idx):
    if idx >= 0x80000000:
        data = b'\x00' + k + struct.pack('>I', idx)
    else:
        pk = PrivateKey(k).pubkey.serialize()
        data = pk + struct.pack('>I', idx)
    I2 = hmac.new(c, data, hashlib.sha512).digest()
    return ((int.from_bytes(I2[:32],'big') + int.from_bytes(k,'big')) % N).to_bytes(32,'big'), I2[32:]
for idx in [84+0x80000000, 0x80000000, 0x80000000, 0, $INDEX]:
    key, chain = ckd(key, chain, idx)

pk = PrivateKey(key)
pubkey_hex = pk.pubkey.serialize().hex()

# Build and sign event
content = json.dumps({'deposit_pubkey': '$PUBKEY'})
created_at = int(time.time())
tags = [['l', '$LEDGER_ID'], ['action', 'deposit_open']]
serialized = json.dumps([0, pubkey_hex[2:], created_at, 20101, tags, content], separators=(',',':'))
event_hash = hashlib.sha256(serialized.encode()).digest()
sig = pk.schnorr_sign(event_hash, bip340tag=None, raw=True)
event = {
    'id': event_hash.hex(),
    'pubkey': pubkey_hex[2:],  # x-only
    'created_at': created_at,
    'kind': 20101,
    'tags': tags,
    'content': content,
    'sig': sig.hex(),
}

# Send to relays and wait for response
relays = [r.strip() for r in '$ALL_RELAYS'.split(',') if r.strip()]
for relay_url in relays:
    try:
        ws = websocket.create_connection(relay_url, timeout=5)
        ws.send(json.dumps(['REQ', 'sub1', {'kinds': [20102], '#e': [event['id']], 'since': created_at - 5}]))
        ws.send(json.dumps(['EVENT', event]))
        print(f'Sent to {relay_url}')

        ws.settimeout(30)
        while True:
            msg = json.loads(ws.recv())
            if msg[0] == 'EVENT' and msg[2].get('kind') == 20102:
                resp = json.loads(msg[2]['content'])
                if resp.get('success'):
                    print('Deposit opened!')
                    if resp.get('result'):
                        print(json.dumps(resp['result'], indent=2))
                else:
                    err = resp.get('error', 'Unknown error')
                    print(f'Error: {err}')
                    if resp.get('result'):
                        print(json.dumps(resp['result'], indent=2))
                ws.close()
                sys.exit(0 if resp.get('success') else 1)
            elif msg[0] == 'EOSE':
                continue
        ws.close()
    except websocket.WebSocketTimeoutException:
        print(f'  Timeout on {relay_url}, trying next...')
        try: ws.close()
        except: pass
    except Exception as e:
        print(f'  Failed on {relay_url}: {e}')

print('No response from any relay')
sys.exit(1)
" 2>&1

    if [ $? -eq 0 ]; then
        # Track the deposit locally (include relay so balance/invoice can find the operator)
        python3 - "$WALLET_DIR" "$LEDGER_ID" "$PUBKEY" "$INDEX" "$ALL_RELAYS" << 'PYEOF'
import json, os, sys
wallet_dir, ledger_id, pubkey, index, relays = sys.argv[1:6]
path = wallet_dir + '/deposits.json'
deps = json.load(open(path)) if os.path.exists(path) else []
deps.append({
    'ledger_id': ledger_id,
    'pubkey': pubkey,
    'key_index': int(index),
    'relay': relays.split(',')[0],
    'status': 'open'
})
with open(path, 'w') as f:
    json.dump(deps, f, indent=2)
print(f'Deposit tracked in {path}')
PYEOF
    fi
    ;;

invoice)
    DEPOSIT_INDEX="0"
    AMOUNT_SATS=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --index|-i) DEPOSIT_INDEX="$2"; shift 2 ;;
            *) [ -z "$AMOUNT_SATS" ] && AMOUNT_SATS="$1"; shift ;;
        esac
    done

    if [ -z "$AMOUNT_SATS" ]; then
        echo "Usage: $0 --wallet <dir> invoice <amount_sats> [--index N]"
        echo ""
        echo "Use 'balance' to see deposit indices."
        exit 1
    fi

    # Look up deposit from wallet json
    DEPOSIT_INFO=$(python3 - "$WALLET_DIR" "$DEPOSIT_INDEX" << 'PYEOF'
import json, sys
wallet_dir, idx_str = sys.argv[1], sys.argv[2]
idx = int(idx_str)
try:
    deps = json.load(open(wallet_dir + '/deposits.json'))
except FileNotFoundError:
    print("ERROR: No deposits.json — open a deposit first", file=sys.stderr)
    sys.exit(1)
if idx >= len(deps):
    print(f"ERROR: deposit index {idx} out of range (have {len(deps)})", file=sys.stderr)
    sys.exit(1)
d = deps[idx]
relay = d.get('relay', '')
print(f"{d['ledger_id']} {d['pubkey']} {d.get('key_index', 0)} {relay}")
PYEOF
    )

    if [ $? -ne 0 ] || echo "$DEPOSIT_INFO" | grep -q "^ERROR"; then
        echo "$DEPOSIT_INFO" >&2
        exit 1
    fi

    LEDGER_ID=$(echo "$DEPOSIT_INFO" | awk '{print $1}')
    PUBKEY=$(echo "$DEPOSIT_INFO" | awk '{print $2}')
    INDEX=$(echo "$DEPOSIT_INFO" | awk '{print $3}')
    STORED_RELAY=$(echo "$DEPOSIT_INFO" | awk '{print $4}')
    # Use stored relay if available
    if [ -n "$STORED_RELAY" ]; then
        LEDGER_RELAY="$STORED_RELAY"
    fi

    SEED=$(cat "$SEED_FILE")

    echo "Creating invoice..."
    echo "  Ledger: ${LEDGER_ID:0:16}..."
    echo "  Pubkey: $PUBKEY"
    echo "  Amount: $AMOUNT_SATS sats"
    echo ""

    ALL_RELAYS="$LEDGER_RELAY"
    [ -n "$EXTRA_RELAYS" ] && ALL_RELAYS="$ALL_RELAYS,$EXTRA_RELAYS"

    python3 - "$SEED" "$PUBKEY" "$LEDGER_ID" "$AMOUNT_SATS" "$ALL_RELAYS" << 'PYEOF'
import json, hashlib, time, sys
try:
    from secp256k1 import PrivateKey
    import websocket
except ImportError:
    print("pip install secp256k1 websocket-client"); sys.exit(1)
import hmac, struct

seed, pubkey, ledger_id, amount_sats, relays_str = sys.argv[1:6]

# Derive signing key (same BIP-32 path as pubkey derivation)
seed_bytes = bytes.fromhex(seed)
I = hmac.new(b'Bitcoin seed', seed_bytes, hashlib.sha512).digest()
key, chain = I[:32], I[32:]
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def ckd(k, c, idx):
    if idx >= 0x80000000:
        data = b'\x00' + k + struct.pack('>I', idx)
    else:
        pk = PrivateKey(k).pubkey.serialize()
        data = pk + struct.pack('>I', idx)
    h = hmac.new(c, data, hashlib.sha512).digest()
    return ((int.from_bytes(h[:32],'big') + int.from_bytes(k,'big')) % N).to_bytes(32,'big'), h[32:]
for idx in [84+0x80000000, 0x80000000, 0x80000000, 0, 0]:
    key, chain = ckd(key, chain, idx)

pk = PrivateKey(key)
pubkey_hex = pk.pubkey.serialize()[1:].hex()  # x-only

content = json.dumps({'deposit_pubkey': pubkey, 'amount_sats': int(amount_sats), 'description': 'Deposit funding'})
created_at = int(time.time())
tags = [['l', ledger_id], ['action', 'make_invoice']]
serialized = json.dumps([0, pubkey_hex, created_at, 20101, tags, content], separators=(',',':'))
event_hash = hashlib.sha256(serialized.encode()).digest()
sig = pk.schnorr_sign(event_hash, bip340tag=None, raw=True)
event = {'id': event_hash.hex(), 'pubkey': pubkey_hex, 'created_at': created_at,
         'kind': 20101, 'tags': tags, 'content': content, 'sig': sig.hex()}

relays = [r.strip() for r in relays_str.split(',') if r.strip()]
for relay_url in relays:
    try:
        ws = websocket.create_connection(relay_url, timeout=5)
        ws.send(json.dumps(['REQ', 'sub1', {'kinds': [20102], '#e': [event['id']], 'since': created_at - 5}]))
        ws.send(json.dumps(['EVENT', event]))
        ws.settimeout(30)
        while True:
            msg = json.loads(ws.recv())
            if msg[0] == 'EVENT' and msg[2].get('kind') == 20102:
                resp = json.loads(msg[2]['content'])
                if resp.get('success') and resp.get('result'):
                    result = resp['result']
                    invoice = result.get('invoice', '')
                    if invoice:
                        print(invoice)
                    else:
                        print(json.dumps(result, indent=2))
                else:
                    print(f"Error: {resp.get('error', 'Unknown')}", file=sys.stderr)
                    sys.exit(1)
                ws.close()
                sys.exit(0)
            elif msg[0] == 'EOSE':
                continue
        ws.close()
    except websocket.WebSocketTimeoutException:
        print(f'  Timeout on {relay_url}', file=sys.stderr)
        try: ws.close()
        except: pass
    except Exception as e:
        print(f'  Failed on {relay_url}: {e}', file=sys.stderr)
print('No response from any relay', file=sys.stderr)
sys.exit(1)
PYEOF
    ;;

fund)
    DEPOSIT_INDEX="0"
    AMOUNT_SATS=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --index|-i) DEPOSIT_INDEX="$2"; shift 2 ;;
            *) [ -z "$AMOUNT_SATS" ] && AMOUNT_SATS="$1"; shift ;;
        esac
    done

    if [ -z "$AMOUNT_SATS" ]; then
        echo "Usage: $0 --wallet <dir> fund <amount_sats> [--index N]"
        echo ""
        echo "Creates a lightning invoice and prints it for payment."
        echo "Use 'balance' to see deposit indices."
        exit 1
    fi

    echo "=== Fund deposit [$DEPOSIT_INDEX] ==="

    # Get the invoice
    INVOICE=$("$0" --wallet "$WALLET_DIR" --relay "$LEDGER_RELAY" --network "$NETWORK" invoice "$AMOUNT_SATS" --index "$DEPOSIT_INDEX" 2>&1)

    if echo "$INVOICE" | grep -q "^lnbc"; then
        echo ""
        echo "Pay this invoice to fund your deposit with $AMOUNT_SATS sats:"
        echo ""
        echo "$INVOICE"
        echo ""
        echo "After payment, the operator will auto-credit your deposit."
    else
        echo "Failed to create invoice:"
        echo "$INVOICE"
        exit 1
    fi
    ;;

balance)
    if [ ! -f "$WALLET_DIR/deposits.json" ]; then
        echo "No deposits. Use 'open' first."
        exit 0
    fi

    SEED=$(cat "$SEED_FILE")

    python3 - "$WALLET_DIR" "$SEED" "$LEDGER_RELAY" << 'PYEOF'
import json, hashlib, time, sys

wallet_dir, seed_hex, fallback_relay = sys.argv[1], sys.argv[2], sys.argv[3]
deps = json.load(open(wallet_dir + '/deposits.json'))
if not deps:
    print("No deposits.")
    sys.exit(0)

try:
    from secp256k1 import PrivateKey
    import websocket
except ImportError:
    # Fallback: just show local data
    for i, d in enumerate(deps):
        print(f"  [{i}] ledger:{d.get('ledger_id','?')[:16]}... pubkey:{d.get('pubkey','?')[:16]}... status:{d.get('status','?')}")
    sys.exit(0)

import hmac, struct
# Derive signing key from seed (BIP-32, index 0)
seed_bytes = bytes.fromhex(seed_hex)
I = hmac.new(b'Bitcoin seed', seed_bytes, hashlib.sha512).digest()
key, chain = I[:32], I[32:]
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def ckd(k, c, idx):
    if idx >= 0x80000000:
        data = b'\x00' + k + struct.pack('>I', idx)
    else:
        pk = PrivateKey(k).pubkey.serialize()
        data = pk + struct.pack('>I', idx)
    h = hmac.new(c, data, hashlib.sha512).digest()
    return ((int.from_bytes(h[:32],'big') + int.from_bytes(k,'big')) % N).to_bytes(32,'big'), h[32:]
for idx in [84+0x80000000, 0x80000000, 0x80000000, 0, 0]:
    key, chain = ckd(key, chain, idx)

pk = PrivateKey(key)
pubkey_hex = pk.pubkey.serialize()[1:].hex()

total_msats = 0
for i, d in enumerate(deps):
    ledger_id = d.get('ledger_id', '?')
    deposit_pubkey = d.get('pubkey', '?')
    # Use stored relay, fall back to CLI relay
    deposit_relay = d.get('relay', fallback_relay)
    relays = [r.strip() for r in deposit_relay.split(',') if r.strip()]
    if fallback_relay and fallback_relay not in relays:
        relays.append(fallback_relay)

    # Send balance_query via Nostr
    content = json.dumps({'deposit_pubkey': deposit_pubkey})
    created_at = int(time.time())
    tags = [['l', ledger_id], ['action', 'balance_query']]
    serialized = json.dumps([0, pubkey_hex, created_at, 20101, tags, content], separators=(',',':'))
    event_hash = hashlib.sha256(serialized.encode()).digest()
    sig = pk.schnorr_sign(event_hash, bip340tag=None, raw=True)
    event = {'id': event_hash.hex(), 'pubkey': pubkey_hex, 'created_at': created_at,
             'kind': 20101, 'tags': tags, 'content': content, 'sig': sig.hex()}

    balance_str = '?'
    bal_msats = 0
    for relay_url in relays:
        try:
            ws = websocket.create_connection(relay_url, timeout=5)
            ws.send(json.dumps(['REQ', 'sub1', {'kinds': [20102], '#e': [event['id']], 'since': created_at - 5}]))
            ws.send(json.dumps(['EVENT', event]))
            ws.settimeout(10)
            while True:
                msg = json.loads(ws.recv())
                if msg[0] == 'EVENT' and msg[2].get('kind') == 20102:
                    resp = json.loads(msg[2]['content'])
                    if resp.get('success') and resp.get('result'):
                        result = resp['result']
                        bal_msats = int(result.get('balance_msats', result.get('balance', 0)))
                        locked_msats = int(result.get('locked_msats', result.get('locked', 0)))
                        bal_sats = bal_msats / 1000
                        locked_sats = locked_msats / 1000
                        if locked_msats > 0:
                            balance_str = f'B {bal_sats:,.0f} ({locked_sats:,.0f} locked)'
                        else:
                            balance_str = f'B {bal_sats:,.0f}'
                    else:
                        balance_str = resp.get('error', 'error')
                    ws.close()
                    break
                elif msg[0] == 'EOSE':
                    continue
            break
        except Exception as e:
            balance_str = f'(unreachable: {e})'
            try: ws.close()
            except: pass

    total_msats += bal_msats
    print(f"  [{i}] {balance_str}  ledger:{ledger_id[:16]}...")

print()
total_sats = total_msats / 1000
print(f"  Total: B {total_sats:,.0f}")
PYEOF
    ;;

*)
    echo "Unknown command: $COMMAND"
    echo "Commands: init, pubkey, open, invoice, fund, balance"
    exit 1
    ;;

esac
