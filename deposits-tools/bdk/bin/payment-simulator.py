#!/usr/bin/env python3
"""
Payment Simulator for Bitcoin Deposits Protocol

This script:
1. Periodically generates wallets on random ledgers
2. Funds them from the faucet
3. Continuously makes small payments between all of them

Usage:
    python3 payment-simulator.py [--operators N] [--wallets-per-op N] [--payment-interval SECS]
"""

import argparse
import json
import os
import random
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional


# Configuration
DOCKER_COMPOSE_FILE = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
OPERATORS = ["bdk-alice", "bdk-bob", "bdk-charlie", "bdk-diana"]
RELAY_URL = "ws://nostr-relay:7777"
NETWORK = "regtest"

# Operator seeds (must match _common.sh)
OPERATOR_SEEDS = {
    "bdk-alice": "416c696365000000000000000000000000000000000000000000000000000001",
    "bdk-bob": "426f620000000000000000000000000000000000000000000000000000000002",
    "bdk-charlie": "436861726c696500000000000000000000000000000000000000000000000003",
    "bdk-diana": "4469616e61000000000000000000000000000000000000000000000000000004",
}


@dataclass
class Wallet:
    """Represents a depositor wallet"""
    seed: str
    alias: str
    ledger_id: str
    operator: str
    funding_address: Optional[str] = None
    balance_msats: int = 0
    deposit_pubkey: Optional[str] = None


@dataclass
class Ledger:
    """Represents an operator's ledger"""
    ledger_id: str
    operator: str
    operator_seed: str


def run_cmd(cmd: list[str], capture: bool = True) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)"""
    result = subprocess.run(cmd, capture_output=capture, text=True)
    return result.returncode, result.stdout, result.stderr


def docker_exec(container: str, cmd: list[str]) -> tuple[int, str, str]:
    """Execute command in a Docker container"""
    full_cmd = ["docker", "exec", container] + cmd
    return run_cmd(full_cmd)


def bitcoin_cli(*args) -> tuple[int, str, str]:
    """Run bitcoin-cli command"""
    cmd = [
        "docker", "exec", "bdk-bitcoind",
        "bitcoin-cli", "-regtest",
        "-rpcuser=user", "-rpcpassword=pass",
        "-rpcwallet=faucet"
    ] + list(args)
    return run_cmd(cmd)


def mine_blocks(n: int = 1):
    """Mine n blocks"""
    bitcoin_cli("-generate", str(n))


def get_ledger_id(operator: str) -> Optional[str]:
    """Get the ledger ID for an operator"""
    seed = OPERATOR_SEEDS[operator]
    code, stdout, stderr = docker_exec(operator, [
        "deposits-bdk", "ledger", "list",
        "--seed", seed,
        "--network", NETWORK,
        "--relay", RELAY_URL,
        "--data-dir", "/data"
    ])

    if code != 0:
        print(f"  Warning: Failed to get ledger for {operator}: {stderr}")
        return None

    # Parse ledger ID from output
    for line in stdout.split("\n"):
        if "Ledger ID:" in line:
            return line.split("Ledger ID:")[1].strip()

    return None


def discover_ledgers() -> list[Ledger]:
    """Discover all available ledgers from operators"""
    ledgers = []

    for operator in OPERATORS:
        ledger_id = get_ledger_id(operator)
        if ledger_id:
            ledgers.append(Ledger(
                ledger_id=ledger_id,
                operator=operator,
                operator_seed=OPERATOR_SEEDS[operator]
            ))
            print(f"  Found ledger {ledger_id[:16]}... on {operator}")

    return ledgers


def generate_wallet_seed() -> str:
    """Generate a random 32-byte hex seed"""
    return secrets.token_hex(32)


def get_deposit_pubkey(container: str, seed: str) -> Optional[str]:
    """Get the deposit public key for a wallet seed"""
    code, stdout, stderr = docker_exec(container, [
        "deposits-wallet", "balance",
        "--seed", seed,
        "--network", NETWORK,
        "--relay", RELAY_URL,
        "--data-dir", f"/data/wallet-{seed[:8]}"
    ])

    # Try to extract pubkey from keygen instead
    code, stdout, stderr = docker_exec(container, [
        "deposits-bdk", "keygen",
        "--seed", seed,
        "--network", NETWORK,
        "--data-dir", f"/data/wallet-{seed[:8]}"
    ])

    for line in stdout.split("\n"):
        if "Public key:" in line or "pubkey:" in line.lower():
            return line.split(":")[-1].strip()

    return None


def create_wallet(ledger: Ledger, alias: str) -> Optional[Wallet]:
    """Create a new wallet with a deposit on the given ledger"""
    seed = generate_wallet_seed()

    # Open deposit on the ledger
    code, stdout, stderr = docker_exec(ledger.operator, [
        "deposits-wallet", "open",
        ledger.ledger_id,
        "100000",  # 100k sats initial request
        "--alias", alias,
        "--seed", seed,
        "--network", NETWORK,
        "--relay", RELAY_URL,
        "--data-dir", f"/data/wallet-{seed[:8]}"
    ])

    if code != 0:
        print(f"  Warning: Failed to open deposit for {alias}: {stderr}")
        return None

    # Extract funding address from output
    funding_address = None
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("bcrt1"):
            funding_address = line
            break

    if not funding_address:
        print(f"  Warning: No funding address in output for {alias}")
        print(f"  Output: {stdout[:200]}")
        return None

    wallet = Wallet(
        seed=seed,
        alias=alias,
        ledger_id=ledger.ledger_id,
        operator=ledger.operator,
        funding_address=funding_address,
        balance_msats=0
    )

    print(f"  Created wallet '{alias}' on {ledger.operator}: {funding_address[:25]}...")
    return wallet


def fund_wallet(wallet: Wallet, amount_btc: float = 0.001) -> bool:
    """Fund a wallet from the faucet"""
    if not wallet.funding_address:
        print(f"  Warning: No funding address for {wallet.alias}")
        return False

    code, stdout, stderr = bitcoin_cli(
        "sendtoaddress",
        wallet.funding_address,
        str(amount_btc)
    )

    if code != 0:
        print(f"  Warning: Failed to fund {wallet.alias}: {stderr}")
        return False

    txid = stdout.strip()
    wallet.balance_msats = int(amount_btc * 100_000_000 * 1000)  # Convert to msats
    print(f"  Funded {wallet.alias} with {amount_btc} BTC (txid: {txid[:16]}...)")
    return True


def get_wallet_balance(wallet: Wallet) -> int:
    """Get the current balance of a wallet in msats"""
    code, stdout, stderr = docker_exec(wallet.operator, [
        "deposits-wallet", "balance",
        "--seed", wallet.seed,
        "--network", NETWORK,
        "--relay", RELAY_URL,
        "--data-dir", f"/data/wallet-{wallet.seed[:8]}"
    ])

    # Parse balance from output
    for line in stdout.split("\n"):
        if wallet.alias in line and "msat" in line.lower():
            # Try to extract number
            import re
            match = re.search(r'(\d+)\s*msat', line, re.IGNORECASE)
            if match:
                return int(match.group(1))

    return wallet.balance_msats


def make_payment(from_wallet: Wallet, to_wallet: Wallet, amount_msats: int, ledger: Ledger) -> bool:
    """
    Make a payment from one wallet to another.

    Since direct wallet-to-wallet payments aren't directly supported,
    we simulate this by having the operator credit the destination deposit.
    In a real system, this would be done via Lightning invoices or on-chain withdrawals.
    """
    # For simulation, we'll use the operator's deposit credit command
    # This credits the destination wallet on the same ledger

    if from_wallet.ledger_id != to_wallet.ledger_id:
        # Cross-ledger payments would need Lightning or on-chain
        print(f"  Skip: Cross-ledger payment not yet implemented")
        return False

    # Generate a unique invoice ID for tracking
    invoice_id = f"sim-{secrets.token_hex(8)}"

    # Get the destination's deposit pubkey (derive from seed)
    # For now, we'll use a simpler approach - just track balances locally

    # Simulate the payment by updating local balances
    if from_wallet.balance_msats < amount_msats:
        print(f"  Skip: {from_wallet.alias} has insufficient balance ({from_wallet.balance_msats} < {amount_msats})")
        return False

    from_wallet.balance_msats -= amount_msats
    to_wallet.balance_msats += amount_msats

    print(f"  Payment: {from_wallet.alias} -> {to_wallet.alias}: {amount_msats} msats")
    return True


def run_simulation(
    num_wallets_per_operator: int = 2,
    wallet_creation_interval: float = 30.0,
    payment_interval: float = 5.0,
    funding_amount_btc: float = 0.001,
    min_payment_msats: int = 1000,
    max_payment_msats: int = 10000,
):
    """Run the payment simulation"""

    print("=" * 60)
    print("Bitcoin Deposits Payment Simulator")
    print("=" * 60)
    print()

    # Discover ledgers
    print("Discovering ledgers...")
    ledgers = discover_ledgers()

    if not ledgers:
        print("Error: No ledgers found. Make sure operators are running.")
        sys.exit(1)

    print(f"Found {len(ledgers)} ledgers")
    print()

    # Track all wallets
    wallets: list[Wallet] = []
    wallet_counter = 0
    last_wallet_time = 0.0
    last_payment_time = 0.0

    print("Starting simulation...")
    print(f"  - Creating up to {num_wallets_per_operator} wallets per operator")
    print(f"  - New wallet every {wallet_creation_interval}s")
    print(f"  - Payment every {payment_interval}s")
    print()

    try:
        while True:
            now = time.time()

            # Create new wallets periodically
            if now - last_wallet_time >= wallet_creation_interval:
                # Check if we need more wallets
                wallets_needed = len(ledgers) * num_wallets_per_operator - len(wallets)

                if wallets_needed > 0:
                    # Pick a random ledger
                    ledger = random.choice(ledgers)

                    # Count existing wallets on this ledger
                    ledger_wallets = [w for w in wallets if w.ledger_id == ledger.ledger_id]

                    if len(ledger_wallets) < num_wallets_per_operator:
                        wallet_counter += 1
                        alias = f"sim-wallet-{wallet_counter:04d}"

                        print(f"\n[{time.strftime('%H:%M:%S')}] Creating wallet {alias}...")
                        wallet = create_wallet(ledger, alias)

                        if wallet:
                            wallets.append(wallet)

                            # Fund the wallet
                            print(f"[{time.strftime('%H:%M:%S')}] Funding {alias}...")
                            if fund_wallet(wallet, funding_amount_btc):
                                # Mine a block to confirm
                                mine_blocks(1)
                                print(f"  Mined 1 block to confirm funding")

                last_wallet_time = now

            # Make payments periodically
            if now - last_payment_time >= payment_interval and len(wallets) >= 2:
                # Pick two different wallets on the same ledger
                ledger_groups = {}
                for w in wallets:
                    if w.ledger_id not in ledger_groups:
                        ledger_groups[w.ledger_id] = []
                    ledger_groups[w.ledger_id].append(w)

                # Find a ledger with at least 2 wallets
                eligible_ledgers = [lid for lid, ws in ledger_groups.items() if len(ws) >= 2]

                if eligible_ledgers:
                    ledger_id = random.choice(eligible_ledgers)
                    ledger_wallets = ledger_groups[ledger_id]

                    # Pick sender and receiver
                    sender = random.choice(ledger_wallets)
                    receiver = random.choice([w for w in ledger_wallets if w != sender])

                    # Random payment amount
                    amount = random.randint(min_payment_msats, max_payment_msats)

                    # Find the ledger object
                    ledger = next((l for l in ledgers if l.ledger_id == ledger_id), None)

                    if ledger and sender.balance_msats >= amount:
                        print(f"\n[{time.strftime('%H:%M:%S')}] Making payment...")
                        make_payment(sender, receiver, amount, ledger)

                last_payment_time = now

            # Print status periodically
            if int(now) % 30 == 0:
                total_balance = sum(w.balance_msats for w in wallets)
                print(f"\n[{time.strftime('%H:%M:%S')}] Status: {len(wallets)} wallets, {total_balance:,} total msats")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\nSimulation stopped by user")
        print(f"Final state: {len(wallets)} wallets created")
        for w in wallets:
            print(f"  {w.alias}: {w.balance_msats:,} msats on {w.operator}")


def main():
    parser = argparse.ArgumentParser(description="Bitcoin Deposits Payment Simulator")
    parser.add_argument("--wallets-per-op", type=int, default=2,
                        help="Number of wallets to create per operator (default: 2)")
    parser.add_argument("--wallet-interval", type=float, default=30.0,
                        help="Seconds between wallet creations (default: 30)")
    parser.add_argument("--payment-interval", type=float, default=5.0,
                        help="Seconds between payments (default: 5)")
    parser.add_argument("--funding-btc", type=float, default=0.001,
                        help="BTC to fund each wallet (default: 0.001)")
    parser.add_argument("--min-payment", type=int, default=1000,
                        help="Minimum payment in msats (default: 1000)")
    parser.add_argument("--max-payment", type=int, default=10000,
                        help="Maximum payment in msats (default: 10000)")

    args = parser.parse_args()

    run_simulation(
        num_wallets_per_operator=args.wallets_per_op,
        wallet_creation_interval=args.wallet_interval,
        payment_interval=args.payment_interval,
        funding_amount_btc=args.funding_btc,
        min_payment_msats=args.min_payment,
        max_payment_msats=args.max_payment,
    )


if __name__ == "__main__":
    main()
