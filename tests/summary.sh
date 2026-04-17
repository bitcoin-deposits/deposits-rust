#!/bin/bash
# Print adversarial test summary.
# Usage: ./tests/summary.sh

set -e
cd "$(dirname "$0")/.."

RESULTS_DIR=$(mktemp -d)
trap "rm -rf $RESULTS_DIR" EXIT

ADVERSARIAL_RESULTS_DIR="$RESULTS_DIR" \
  cargo test -p deposits-integration-tests -- --test-threads=1 2>/dev/null

RESULTS_FILE="$RESULTS_DIR/results.jsonl"
if [ ! -f "$RESULTS_FILE" ]; then
    echo "No adversarial results found."
    exit 1
fi

python3 -c "
import json

results = []
with open('$RESULTS_FILE') as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except:
                pass

seen = {}
for r in results:
    seen[r['name']] = r

blocked = {n: r for n, r in seen.items() if r.get('blocked')}
exploitable = {n: r for n, r in seen.items() if not r.get('blocked')}

print(f'=== ADVERSARIAL TEST SUMMARY ({len(seen)} attacks) ===')
print(f'  Blocked: {len(blocked)}')
print(f'  Exploitable: {len(exploitable)}')

by_layer = {}
for n, r in seen.items():
    res = r.get('result', '?')
    for layer in ['protocol', 'implementation', 'wallet-policy', 'node-policy', 'UNDEFENDED']:
        if layer in res:
            by_layer.setdefault(layer, {'blocked': 0, 'exploitable': 0})
            if r.get('blocked'):
                by_layer[layer]['blocked'] += 1
            else:
                by_layer[layer]['exploitable'] += 1

print()
for layer in ['protocol', 'implementation', 'wallet-policy', 'node-policy', 'UNDEFENDED']:
    if layer in by_layer:
        d = by_layer[layer]
        print(f'  {layer:20s}  {d[\"blocked\"]} blocked, {d[\"exploitable\"]} exploitable')

if exploitable:
    print()
    print('--- EXPLOITABLE ---')
    for name in sorted(exploitable):
        r = exploitable[name]
        notes = r.get('notes', '')[:140]
        print(f'  {name}')
        if notes:
            print(f'    {notes}')

print()
print('--- BLOCKED ---')
for name in sorted(blocked):
    r = blocked[name]
    res = r.get('result', '').replace('BLOCKED at ', '')
    print(f'  [{res:15s}]  {name}')
"
