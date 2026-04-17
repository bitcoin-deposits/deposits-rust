#!/bin/bash
# Print adversarial test summary.
# Usage: ./tests/summary.sh

set -e
cd "$(dirname "$0")/.."

cargo test -p deposits-integration-tests -- --nocapture 2>&1 | python3 -c "
import sys

attacks = []
current = {}
for line in sys.stdin:
    line = line.rstrip()
    if line.startswith('Attack: '):
        if current:
            attacks.append(current)
        current = {'name': line[8:]}
    elif '  Result: ' in line:
        current['result'] = line.strip().replace('Result: ', '')
    elif '  Notes: ' in line:
        current['notes'] = line.strip().replace('Notes: ', '')[:120]
    elif '  Steps:' in line:
        current['has_steps'] = True
    elif line.strip().startswith(('1.', '2.', '3.', '4.', '5.', '6.', '7.')):
        current.setdefault('step_lines', []).append(line.strip())
if current:
    attacks.append(current)

seen = {}
for a in attacks:
    name = a.get('name', '?')
    if name not in seen:
        seen[name] = a

blocked = [(n,a) for n,a in seen.items() if 'BLOCKED' in a.get('result','')]
exploitable = [(n,a) for n,a in seen.items() if 'EXPLOITABLE' in a.get('result','')]

print(f'=== ADVERSARIAL TEST SUMMARY ({len(seen)} attacks) ===')
print(f'  Blocked: {len(blocked)}')
print(f'  Exploitable: {len(exploitable)}')

by_layer = {}
for n,a in seen.items():
    r = a.get('result','?')
    for layer in ['protocol', 'implementation', 'wallet-policy', 'node-policy', 'UNDEFENDED']:
        if layer in r:
            by_layer.setdefault(layer, []).append(n)

print()
print('By defense layer:')
for layer in ['protocol', 'implementation', 'wallet-policy', 'node-policy', 'UNDEFENDED']:
    if layer in by_layer:
        b = sum(1 for n in by_layer[layer] if 'BLOCKED' in seen[n].get('result',''))
        e = sum(1 for n in by_layer[layer] if 'EXPLOITABLE' in seen[n].get('result',''))
        print(f'  {layer:20s}  {b} blocked, {e} exploitable')

print()
print('--- EXPLOITABLE ---')
for name, a in sorted(exploitable):
    print(f'  [{a[\"result\"].split(\"(\")[1].split(\")\")[0] if \"(\" in a.get(\"result\",\"\") else \"?\":20s}]  {name}')
    if 'notes' in a:
        print(f'    {a[\"notes\"]}')
    for s in a.get('step_lines', []):
        print(f'    {s}')

print()
print('--- BLOCKED ---')
for name, a in sorted(blocked):
    layer = a.get('result','').replace('BLOCKED at ','')
    print(f'  [{layer:15s}]  {name}')
"
