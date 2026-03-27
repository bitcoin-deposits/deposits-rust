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
        # Track the deposit locally
        python3 -c "
import json, os
path = '$WALLET_DIR/deposits.json'
deps = json.load(open(path)) if os.path.exists(path) else []
deps.append({
    'ledger_id': '$LEDGER_ID',
    'pubkey': '$PUBKEY',
    'key_index': $INDEX,
    'status': 'open'
})
with open(path, 'w') as f:
    json.dump(deps, f, indent=2)
print('Deposit tracked in $WALLET_DIR/deposits.json')
" 2>/dev/null || true
    fi
    ;;

*)
    echo "Unknown command: $COMMAND"
    echo "Commands: init, pubkey, open"
    exit 1
    ;;

esac
