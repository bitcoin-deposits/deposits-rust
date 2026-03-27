#!/bin/bash
# Discover operators and ledgers from Nostr relay advertisements.
#
# Usage:
#   ./discover.sh                         # Uses default relay
#   ./discover.sh wss://relay.ynniv.com   # Specify relay
#   ./discover.sh --node alice            # Use a node's connection

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$1" = "--node" ] && [ -n "$2" ]; then
    # Use a node to run the discover command
    exec "$SCRIPT_DIR/node-cli.sh" "$2" ledger discover
fi

RELAY="${1:-${DEPOSITS_LEDGER_RELAY:-wss://relay.ynniv.com}}"

# Query relay for kind 39100 (ledger advertisements)
python3 -c "
import json, sys, websocket

relay = '$RELAY'
ws = websocket.create_connection(relay)
ws.send(json.dumps(['REQ', 'disc', {'kinds': [39100], 'limit': 50}]))

ads = []
ws.settimeout(10)
try:
    while True:
        msg = json.loads(ws.recv())
        if msg[0] == 'EVENT':
            try:
                ad = json.loads(msg[2]['content'])
                ad['_pubkey'] = msg[2]['pubkey']
                ad['_created_at'] = msg[2]['created_at']
                ads.append(ad)
            except: pass
        elif msg[0] == 'EOSE':
            break
except: pass
ws.close()

if not ads:
    print('No ledger advertisements found on', relay)
    sys.exit(0)

# Deduplicate by ledger_id (keep newest)
by_ledger = {}
for ad in ads:
    lid = ad.get('ledger_id', '')
    if lid not in by_ledger or ad['_created_at'] > by_ledger[lid]['_created_at']:
        by_ledger[lid] = ad

print(f'Found {len(by_ledger)} ledger(s) on {relay}')
print()

for lid, ad in sorted(by_ledger.items()):
    name = ad.get('operator_name', 'Anonymous')
    network = ad.get('network', '?')
    reserves = ad.get('reserves_amount_msats', 0)
    obligations = ad.get('total_obligations_msats', 0)
    headroom = ad.get('available_headroom_msats', 0)
    collateral = ad.get('attested_collateral_msats', 0)
    annual_bps = ad.get('annual_fee_bps', 0)
    min_fee = ad.get('min_fee_sats', 0)
    max_dep = ad.get('max_deposit_msats', 0)
    access = ad.get('access_control', False)
    domains = ad.get('allowed_domains', [])

    print(f'{name} ({network})')
    print(f'  Ledger:     {lid[:16]}...')
    print(f'  Operator:   {ad.get(\"operator_pubkey\", \"?\")[:16]}...')
    print(f'  Reserves:   {reserves // 1000:,} sats')
    print(f'  Obligations: {obligations // 1000:,} sats')
    print(f'  Available:  {headroom // 1000:,} sats')
    if collateral > 0:
        print(f'  Collateral: {collateral // 1000:,} sats')
    print(f'  Fees:       {annual_bps}bps/year, min {min_fee} sats')
    if max_dep > 0 and max_dep < 2**63:
        print(f'  Max deposit: {max_dep // 1000:,} sats')
    if access:
        print(f'  Access:     restricted (domains: {', '.join(domains) if domains else 'allowlist only'})')
    if ad.get('relay_url'):
        print(f'  Relay:      {ad[\"relay_url\"]}')
    print()
" 2>&1
