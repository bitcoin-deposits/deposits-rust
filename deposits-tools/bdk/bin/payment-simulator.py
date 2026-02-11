#!/usr/bin/env python3
"""
Payment Simulator for Bitcoin Deposits Protocol

Drives wallet.sh to create real ledger activity:
1. Discovers available ledgers
2. Opens deposits with random aliases
3. Funds them via faucet
4. Makes withdrawals between deposits (actual ledger operations)

Usage:
    python3 payment-simulator.py [--wallets N] [--payment-interval SECS]
"""

import argparse
import json
import os
import random
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
WALLET_SH = SCRIPT_DIR / "wallet.sh"
DATA_DIR = Path.home() / ".deposits-wallet"


@dataclass
class Deposit:
    """Represents a deposit opened via wallet.sh"""
    alias: str
    ledger_id: str
    funding_address: str
    min_sats: int
    max_sats: int
    status: str = "pending"


def run_wallet(*args, capture: bool = True) -> tuple[int, str, str]:
    """Run wallet.sh with given arguments"""
    cmd = [str(WALLET_SH)] + list(args)
    result = subprocess.run(cmd, capture_output=capture, text=True)
    return result.returncode, result.stdout, result.stderr


def discover_ledgers() -> list[str]:
    """Discover available ledgers on the network"""
    code, stdout, stderr = run_wallet("discover")

    if code != 0:
        print(f"  Warning: discover failed: {stderr}")
        return []

    # Parse ledger IDs from output
    # Format: "Ledger: <64-char-hex>"
    ledgers = []
    for line in stdout.split("\n"):
        if "Ledger:" in line or line.strip().startswith("Ledger ID:"):
            # Extract the hex ID
            parts = line.split(":")
            if len(parts) >= 2:
                ledger_id = parts[-1].strip()
                if len(ledger_id) == 64:
                    ledgers.append(ledger_id)
        # Also check for lines that are just 64-char hex (ledger list format)
        stripped = line.strip()
        if len(stripped) == 64 and all(c in '0123456789abcdef' for c in stripped):
            if stripped not in ledgers:
                ledgers.append(stripped)

    return ledgers


def load_deposits() -> list[Deposit]:
    """Load deposits from wallet.sh's data file"""
    deposits_file = DATA_DIR / "deposits.json"

    if not deposits_file.exists():
        return []

    try:
        with open(deposits_file) as f:
            data = json.load(f)

        deposits = []
        for item in data:
            deposits.append(Deposit(
                alias=item.get("alias", "unknown"),
                ledger_id=item.get("ledger_id", ""),
                funding_address=item.get("funding_address", ""),
                min_sats=item.get("min_sats", 0),
                max_sats=item.get("max_sats", 0),
                status=item.get("status", "unknown"),
            ))
        return deposits
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  Warning: Failed to parse deposits.json: {e}")
        return []


def open_deposit(ledger_id: str, alias: str, amount_sats: int = 100000) -> Optional[Deposit]:
    """Open a new deposit on a ledger"""
    print(f"  Opening deposit '{alias}' for {amount_sats} sats...")

    code, stdout, stderr = run_wallet(
        "open", ledger_id, str(amount_sats),
        "--alias", alias
    )

    if code != 0:
        print(f"  Warning: Failed to open deposit: {stderr}")
        return None

    # Parse output for funding address
    funding_address = None
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("bcrt1") or line.startswith("bc1") or line.startswith("tb1"):
            funding_address = line
            break

    if not funding_address:
        # Try to load from deposits.json
        deposits = load_deposits()
        for d in deposits:
            if d.alias == alias:
                funding_address = d.funding_address
                break

    if funding_address:
        print(f"  Created: {alias} -> {funding_address[:25]}...")
        return Deposit(
            alias=alias,
            ledger_id=ledger_id,
            funding_address=funding_address,
            min_sats=1000,
            max_sats=amount_sats,
            status="pending"
        )
    else:
        print(f"  Warning: No funding address found for {alias}")
        return None


def fund_deposit(alias: str, amount_sats: Optional[int] = None) -> bool:
    """Fund a deposit via faucet"""
    args = ["faucet", alias]
    if amount_sats:
        args.append(str(amount_sats))

    code, stdout, stderr = run_wallet(*args)

    if code != 0:
        print(f"  Warning: Failed to fund {alias}: {stderr}")
        return False

    if "Sent!" in stdout or "Done!" in stdout:
        print(f"  Funded {alias}")
        return True

    print(f"  Warning: Unexpected faucet output: {stdout[:100]}")
    return False


def get_balance(alias: str) -> Optional[int]:
    """Get balance for a deposit alias (in msats)"""
    code, stdout, stderr = run_wallet("balance")

    if code != 0:
        return None

    # Parse balance output - look for alias and balance
    # Format varies, look for lines with the alias and msat/sat amounts
    for line in stdout.split("\n"):
        if alias in line:
            # Try to extract balance
            import re
            # Look for patterns like "1000 msat" or "1000msat" or "balance: 1000"
            match = re.search(r'(\d+)\s*msat', line, re.IGNORECASE)
            if match:
                return int(match.group(1))
            match = re.search(r'(\d+)\s*sat', line, re.IGNORECASE)
            if match:
                return int(match.group(1)) * 1000  # Convert to msats

    return None


def withdraw_to(from_alias: str, to_address: str, amount_sats: int) -> bool:
    """
    Withdraw from one deposit to an address.
    This creates actual ledger operations (OnchainLock, OnchainFulfill).
    """
    print(f"  Withdrawing {amount_sats} sats from {from_alias}...")

    code, stdout, stderr = run_wallet(
        "withdraw", from_alias, str(amount_sats),
        "--to", to_address
    )

    if code != 0:
        print(f"  Warning: Withdrawal failed: {stderr}")
        return False

    if "success" in stdout.lower() or "withdraw" in stdout.lower():
        print(f"  Withdrawal initiated: {from_alias} -> {to_address[:20]}...")
        return True

    return False


def mine_block():
    """Mine a block to confirm transactions"""
    subprocess.run([
        "docker", "exec", "bdk-bitcoind",
        "bitcoin-cli", "-regtest",
        "-rpcuser=user", "-rpcpassword=pass",
        "-rpcwallet=faucet", "-generate", "1"
    ], capture_output=True)


def run_simulation(
    num_wallets: int = 4,
    wallet_creation_interval: float = 30.0,
    payment_interval: float = 10.0,
    funding_amount_sats: int = 100000,
    min_payment_sats: int = 1000,
    max_payment_sats: int = 5000,
):
    """Run the payment simulation"""

    print("=" * 60)
    print("Bitcoin Deposits Payment Simulator")
    print("=" * 60)
    print()

    # Check wallet.sh exists
    if not WALLET_SH.exists():
        print(f"Error: wallet.sh not found at {WALLET_SH}")
        sys.exit(1)

    # Discover ledgers
    print("Discovering ledgers...")
    ledgers = discover_ledgers()

    if not ledgers:
        print("Error: No ledgers found. Make sure operators are running.")
        print("Try: ./bin/wallet.sh discover")
        sys.exit(1)

    print(f"Found {len(ledgers)} ledgers:")
    for lid in ledgers:
        print(f"  {lid[:16]}...")
    print()

    # Track deposits we've created
    our_deposits: list[Deposit] = []
    wallet_counter = 0
    last_wallet_time = 0.0
    last_payment_time = 0.0

    print("Starting simulation...")
    print(f"  - Creating up to {num_wallets} wallets")
    print(f"  - New wallet every {wallet_creation_interval}s")
    print(f"  - Payment every {payment_interval}s")
    print()

    try:
        while True:
            now = time.time()

            # Create new deposits periodically
            if now - last_wallet_time >= wallet_creation_interval:
                if len(our_deposits) < num_wallets:
                    wallet_counter += 1
                    # Use timestamp-based alias to avoid conflicts with old deposits
                    ts = int(time.time()) % 100000
                    alias = f"sim-{ts}-{wallet_counter:02d}"
                    ledger_id = random.choice(ledgers)

                    print(f"\n[{time.strftime('%H:%M:%S')}] Creating deposit {alias}...")
                    deposit = open_deposit(ledger_id, alias, funding_amount_sats)

                    if deposit:
                        our_deposits.append(deposit)

                        # Fund it
                        print(f"[{time.strftime('%H:%M:%S')}] Funding {alias}...")
                        if fund_deposit(alias):
                            # Mark as credited - auto_complete runs every 60s on daemon
                            # and we've already mined a block to confirm the funding tx
                            deposit.status = "credited"
                            print(f"  Deposit funded and should be credited soon")

                last_wallet_time = now

            # Make payments (withdrawals) periodically
            if now - last_payment_time >= payment_interval and len(our_deposits) >= 2:
                # Find deposits that are credited (funded + auto_complete should have run)
                credited = [d for d in our_deposits if d.status == "credited"]

                if len(credited) >= 2:
                    # Pick sender and receiver
                    sender = random.choice(credited)
                    receiver = random.choice([d for d in credited if d != sender])

                    # Random payment amount
                    amount = random.randint(min_payment_sats, max_payment_sats)

                    print(f"\n[{time.strftime('%H:%M:%S')}] Payment: {sender.alias} -> {receiver.alias}")

                    if withdraw_to(sender.alias, receiver.funding_address, amount):
                        # Mine to confirm
                        mine_block()
                        print(f"  Mined block to confirm")

                last_payment_time = now

            # Print status periodically
            if int(now) % 60 == 0:
                funded_count = len([d for d in our_deposits if d.status == "funded"])
                print(f"\n[{time.strftime('%H:%M:%S')}] Status: {len(our_deposits)} deposits ({funded_count} funded)")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\nSimulation stopped by user")
        print(f"Final state: {len(our_deposits)} deposits")
        for d in our_deposits:
            print(f"  {d.alias}: {d.status} on ledger {d.ledger_id[:16]}...")


def main():
    parser = argparse.ArgumentParser(description="Bitcoin Deposits Payment Simulator")
    parser.add_argument("--wallets", type=int, default=4,
                        help="Number of wallets to create (default: 4)")
    parser.add_argument("--wallet-interval", type=float, default=30.0,
                        help="Seconds between wallet creations (default: 30)")
    parser.add_argument("--payment-interval", type=float, default=10.0,
                        help="Seconds between payments (default: 10)")
    parser.add_argument("--funding-sats", type=int, default=100000,
                        help="Sats to fund each wallet (default: 100000)")
    parser.add_argument("--min-payment", type=int, default=1000,
                        help="Minimum payment in sats (default: 1000)")
    parser.add_argument("--max-payment", type=int, default=5000,
                        help="Maximum payment in sats (default: 5000)")

    args = parser.parse_args()

    run_simulation(
        num_wallets=args.wallets,
        wallet_creation_interval=args.wallet_interval,
        payment_interval=args.payment_interval,
        funding_amount_sats=args.funding_sats,
        min_payment_sats=args.min_payment,
        max_payment_sats=args.max_payment,
    )


if __name__ == "__main__":
    main()
