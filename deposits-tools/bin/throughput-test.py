#!/usr/bin/env python3
"""
High-throughput transfer test using existing deposits.
Uses shell backgrounding like bash for maximum throughput.
"""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
WALLET_SH = SCRIPT_DIR / "wallet.sh"
DATA_DIR = Path.home() / ".deposits-wallet"


def compute_deposit_id(deposit_pubkey: str) -> str:
    """Compute deposit_id from pubkey: SHA256("pk(<pubkey>)")[0:16] as hex."""
    descriptor = f"pk({deposit_pubkey})"
    hash_bytes = hashlib.sha256(descriptor.encode()).digest()
    return hash_bytes[:16].hex()


def get_deposits_by_ledger():
    """Get existing deposits grouped by ledger."""
    deposits_file = DATA_DIR / "deposits.json"
    if not deposits_file.exists():
        return {}

    with open(deposits_file) as f:
        deposits = json.load(f)

    by_ledger = {}
    for d in deposits:
        ledger = d.get("ledger_id", "")
        if ledger not in by_ledger:
            by_ledger[ledger] = []
        by_ledger[ledger].append(d)

    return by_ledger


def main():
    parser = argparse.ArgumentParser(description="High-throughput transfer test")
    parser.add_argument("--count", type=int, default=100, help="Total transfers to execute")
    parser.add_argument("--concurrent", type=int, default=50, help="Max concurrent transfers")
    parser.add_argument("--amount", type=int, default=1, help="Sats per transfer")
    args = parser.parse_args()

    print("=" * 60)
    print("High-Throughput Transfer Test (shell bg)")
    print("=" * 60)
    print()

    by_ledger = get_deposits_by_ledger()
    if not by_ledger:
        print("No deposits found. Run payment-simulator first to create deposits.")
        sys.exit(1)

    source = None
    dest_id = None
    for ledger_id, deposits in by_ledger.items():
        if len(deposits) >= 2:
            source = deposits[0]
            dest = deposits[1]
            dest_pubkey = dest.get("deposit_pubkey", "")
            dest_id = compute_deposit_id(dest_pubkey)
            break

    if not source or not dest_id:
        print("Need at least 2 deposits on the same ledger.")
        sys.exit(1)

    source_alias = source.get("alias", "")
    print(f"Source: {source_alias}")
    print(f"Dest:   {dest_id[:16]}...")
    print(f"Amount: {args.amount} sats per transfer")
    print(f"Count:  {args.count} transfers")
    print(f"Concurrent: {args.concurrent}")
    print()

    timeout_block = 5000

    # Build a bash script that does all the work like the original bash version
    script_lines = [
        "#!/bin/bash",
        f'DEST_DEPOSIT_ID="{dest_id}"',
        f'WALLET_SH="{WALLET_SH}"',
        f'SOURCE_ALIAS="{source_alias}"',
        f'AMOUNT={args.amount}',
        f'TIMEOUT={timeout_block}',
        f'CONCURRENT={args.concurrent}',
        f'TOTAL={args.count}',
        '',
        'for batch_start in $(seq 1 $CONCURRENT $TOTAL); do',
        '    batch_end=$((batch_start + CONCURRENT - 1))',
        '    if [ $batch_end -gt $TOTAL ]; then',
        '        batch_end=$TOTAL',
        '    fi',
        '    for i in $(seq $batch_start $batch_end); do',
        '        (',
        '            PREIMAGE=$(openssl rand -hex 32)',
        '            HASH=$(echo -n "$PREIMAGE" | xxd -r -p | sha256sum | cut -d\' \' -f1)',
        '            if $WALLET_SH transfer $SOURCE_ALIAS $AMOUNT --to $DEST_DEPOSIT_ID --hash $HASH --timeout $TIMEOUT 2>&1 | grep -q "Transfer ID:"; then',
        '                echo -n "."',
        '            else',
        '                echo -n "x"',
        '            fi',
        '        ) &',
        '    done',
        '    wait',
        'done',
    ]

    script = '\n'.join(script_lines)

    print("Running transfers...", flush=True)
    sys.stdout.flush()
    start_time = time.time()

    # Run the generated bash script
    result = subprocess.run(['bash', '-c', script], capture_output=False, text=True)
    sys.stdout.flush()

    elapsed = time.time() - start_time

    print()
    print()
    print("=" * 60)
    print("Results")
    print("=" * 60)
    print(f"  Elapsed:     {elapsed:.2f}s")
    print(f"  Total:       {args.count} transfers")
    print(f"  Throughput:  {args.count / elapsed:.1f} tx/sec")


if __name__ == "__main__":
    main()
