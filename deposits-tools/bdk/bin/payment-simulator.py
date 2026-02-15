#!/usr/bin/env python3
"""
Payment Simulator for Bitcoin Deposits Protocol

Drives wallet.sh to create real ledger activity:
1. Discovers available ledgers
2. Opens deposits with random aliases
3. Funds them via faucet
4. Makes withdrawals between deposits (actual ledger operations)

With --lightning flag, uses Lightning invoices instead of on-chain withdrawals:
- Creates invoices via operator's LDK sidecar
- Pays invoices via sender's operator's LDK sidecar

Usage:
    python3 payment-simulator.py [--wallets N] [--payment-interval SECS]
    python3 payment-simulator.py --lightning  # Use Lightning instead of on-chain
"""

import argparse
import json
import os
import random
import secrets
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Prometheus metrics (optional - gracefully degrade if not installed)
try:
    from prometheus_client import Counter, Gauge, start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    print("Note: prometheus_client not installed, metrics will not be exported to Grafana")
    print("      Install with: pip install prometheus_client")


# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
WALLET_SH = SCRIPT_DIR / "wallet.sh"
DATA_DIR = Path.home() / ".deposits-wallet"
METRICS_PORT = 9200  # Prometheus metrics port

# Global payment counter - used to make each invoice unique by adding msat offset
PAYMENT_COUNTER = 0

# Payment metrics (local counters)
PAYMENTS_SUCCESS = 0
PAYMENTS_FAILED = 0
VOLUME_SATS = 0
FUNDING_SUCCESS = 0
FUNDING_FAILED = 0
FUNDING_VOLUME_SATS = 0

# Prometheus metrics (if available)
if PROMETHEUS_AVAILABLE:
    PROM_PAYMENTS_TOTAL = Counter(
        'simulator_payments_total',
        'Total number of Lightning payments attempted',
        ['status']  # 'success' or 'failed'
    )
    PROM_PAYMENTS_SATS = Counter(
        'simulator_payments_sats_total',
        'Total sats transferred via Lightning payments'
    )
    PROM_FUNDING_TOTAL = Counter(
        'simulator_funding_total',
        'Total number of Lightning funding operations attempted',
        ['status']  # 'success' or 'failed'
    )
    PROM_FUNDING_SATS = Counter(
        'simulator_funding_sats_total',
        'Total sats transferred via Lightning funding'
    )
    PROM_DEPOSITS_COUNT = Gauge(
        'simulator_deposits_count',
        'Current number of deposits',
        ['status']  # 'total', 'funded'
    )
    PROM_DEPOSITS_BALANCE = Gauge(
        'simulator_deposits_balance_sats',
        'Total balance across all deposits in sats'
    )
    PROM_LEDGERS_COUNT = Gauge(
        'simulator_ledgers_count',
        'Number of discovered ledgers'
    )


@dataclass
class Deposit:
    """Represents a deposit opened via wallet.sh"""
    alias: str
    ledger_id: str
    funding_address: str
    min_sats: int
    max_sats: int
    status: str = "pending"
    balance_sats: int = 0  # Actual confirmed balance from ledger


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


def sync_and_get_balances() -> dict[str, int]:
    """Sync deposits and get balances from the ledger. Returns alias -> sats."""
    # First sync to get latest balances from ledger
    run_wallet("sync")

    # Then read balance output
    code, stdout, stderr = run_wallet("balance")

    if code != 0:
        return {}

    # Parse balance output
    # Format: "  + alias     12345 sats  (pubkey)"
    balances = {}
    import re
    for line in stdout.split("\n"):
        # Look for lines with alias and sats
        match = re.search(r'[+~?]\s+(\S+)\s+(\d+)\s+sats', line)
        if match:
            alias = match.group(1)
            sats = int(match.group(2))
            balances[alias] = sats

    return balances


def get_balance(alias: str) -> Optional[int]:
    """Get balance for a deposit alias (in sats)"""
    balances = sync_and_get_balances()
    return balances.get(alias)


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


# Lightning payment functions
# These use wallet.sh to talk to BDK nodes via Nostr
# The BDK node handles LDK interaction internally


def make_invoice(alias: str, amount_sats: int) -> Optional[str]:
    """
    Request a Lightning invoice for a deposit.
    The BDK node creates the invoice via its LDK sidecar.
    """
    code, stdout, stderr = run_wallet("make_invoice", alias, str(amount_sats))

    if code != 0:
        print(f"  Warning: Failed to create invoice: {stderr}")
        return None

    # Parse invoice from output (bolt11 string)
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("lnbcrt") or line.startswith("lnbc") or line.startswith("lntb"):
            return line

    # Try JSON format
    try:
        data = json.loads(stdout)
        return data.get("invoice") or data.get("bolt11")
    except json.JSONDecodeError:
        pass

    print(f"  Warning: Could not parse invoice from output")
    return None


def pay_invoice(alias: str, invoice: str) -> bool:
    """
    Pay a Lightning invoice from a deposit.
    The BDK node pays via its LDK sidecar.
    """
    code, stdout, stderr = run_wallet("pay_invoice", alias, invoice)

    if code != 0:
        print(f"  Warning: Payment failed: {stderr}")
        # Small delay after failure to let LDK clean up pending payment state
        time.sleep(2)
        return False

    # Check for success
    if "success" in stdout.lower() or "paid" in stdout.lower() or "preimage" in stdout.lower():
        return True

    # Payment didn't clearly succeed, add delay before retry
    time.sleep(1)
    return False


def lightning_payment(sender: Deposit, receiver: Deposit, amount_sats: int) -> Optional[int]:
    """
    Make a Lightning payment between two deposits.
    1. Receiver requests invoice from their operator
    2. Sender pays invoice via their operator

    Uses PAYMENT_COUNTER to ensure unique invoice amounts.
    Returns the actual amount paid (with counter offset) on success, None on failure.
    """
    global PAYMENT_COUNTER, PAYMENTS_SUCCESS, PAYMENTS_FAILED, VOLUME_SATS
    PAYMENT_COUNTER += 1

    # Add counter as extra sats to ensure unique payment hash
    unique_amount = amount_sats + PAYMENT_COUNTER

    print(f"  Creating invoice for {receiver.alias} ({unique_amount} sats, payment #{PAYMENT_COUNTER})...")
    invoice = make_invoice(receiver.alias, unique_amount)
    if not invoice:
        PAYMENTS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_PAYMENTS_TOTAL.labels(status='failed').inc()
        return None

    print(f"  Invoice: {invoice[:50]}...")
    print(f"  Paying {unique_amount} sats from {sender.alias}...")

    if pay_invoice(sender.alias, invoice):
        print(f"  Lightning payment #{PAYMENT_COUNTER} successful!")
        PAYMENTS_SUCCESS += 1
        VOLUME_SATS += unique_amount
        if PROMETHEUS_AVAILABLE:
            PROM_PAYMENTS_TOTAL.labels(status='success').inc()
            PROM_PAYMENTS_SATS.inc(unique_amount)
        return unique_amount

    PAYMENTS_FAILED += 1
    if PROMETHEUS_AVAILABLE:
        PROM_PAYMENTS_TOTAL.labels(status='failed').inc()
    return None


def fund_deposit_lightning(funder: Deposit, recipient_alias: str, amount_sats: int) -> bool:
    """
    Fund a new deposit via Lightning from an existing funded deposit.
    1. Create invoice for the new deposit
    2. Pay it from the funder deposit

    Uses PAYMENT_COUNTER to ensure unique invoice amounts.
    """
    global PAYMENT_COUNTER, FUNDING_SUCCESS, FUNDING_FAILED, FUNDING_VOLUME_SATS
    PAYMENT_COUNTER += 1

    # Add counter as extra sats to ensure unique payment hash
    unique_amount = amount_sats + PAYMENT_COUNTER

    print(f"  Creating invoice for {recipient_alias} ({unique_amount} sats, funding #{PAYMENT_COUNTER})...")
    invoice = make_invoice(recipient_alias, unique_amount)
    if not invoice:
        FUNDING_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_FUNDING_TOTAL.labels(status='failed').inc()
        return False

    print(f"  Invoice: {invoice[:50]}...")
    print(f"  Paying {unique_amount} sats from {funder.alias}...")

    if pay_invoice(funder.alias, invoice):
        print(f"  Lightning funding #{PAYMENT_COUNTER} successful!")
        funder.balance_sats -= unique_amount
        FUNDING_SUCCESS += 1
        FUNDING_VOLUME_SATS += unique_amount
        if PROMETHEUS_AVAILABLE:
            PROM_FUNDING_TOTAL.labels(status='success').inc()
            PROM_FUNDING_SATS.inc(unique_amount)
        return True

    print(f"  Warning: Lightning funding failed")
    FUNDING_FAILED += 1
    if PROMETHEUS_AVAILABLE:
        PROM_FUNDING_TOTAL.labels(status='failed').inc()
    return False


def mine_block(network: str = "regtest"):
    """Mine a block to confirm transactions (regtest only)"""
    if network != "regtest":
        return  # Can't mine on signet/mainnet
    subprocess.run([
        "docker", "exec", "bdk-bitcoind",
        "bitcoin-cli", "-regtest",
        "-rpcuser=user", "-rpcpassword=pass",
        "-rpcwallet=faucet", "-generate", "1"
    ], capture_output=True)


def run_simulation(
    wallets_per_ledger: float = 2.0,
    base_wallet_interval: float = 3.0,
    payment_interval: float = 2.0,
    funding_amount_sats: int = 100000,
    min_payment_sats: int = 1000,
    max_payment_sats: int = 5000,
    rediscover_interval: float = 60.0,
    network: str = "signet",
    lightning: bool = False,
):
    """Run the payment simulation

    Args:
        wallets_per_ledger: Target wallets per discovered ledger (scales with network)
        base_wallet_interval: Base interval between wallet creations (adjusted by ledger count)
        payment_interval: Seconds between payment attempts
        funding_amount_sats: Amount to fund each wallet
        min_payment_sats: Minimum payment amount
        max_payment_sats: Maximum payment amount
        rediscover_interval: Seconds between ledger re-discovery
        network: Bitcoin network (regtest, signet, mainnet)
        lightning: Use Lightning invoices instead of on-chain withdrawals
    """

    # Lightning payments are instant, so we can run 10x faster
    if lightning and payment_interval == 2.0:
        payment_interval = 0.2

    # Start Prometheus metrics server for Lightning mode
    if lightning and PROMETHEUS_AVAILABLE:
        start_http_server(METRICS_PORT)
        print(f"Prometheus metrics available at http://localhost:{METRICS_PORT}/metrics")

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

    # Scale wallet count and creation rate based on ledger count
    num_wallets = max(4, int(len(ledgers) * wallets_per_ledger))
    # More ledgers = faster wallet creation (but with diminishing returns)
    # With 1 ledger: base interval, with 10 ledgers: base/3, with 25 ledgers: base/5
    wallet_creation_interval = base_wallet_interval / (1 + len(ledgers) * 0.2)
    wallet_creation_interval = max(1.0, wallet_creation_interval)  # Floor at 1 second

    # Track deposits we've created
    our_deposits: list[Deposit] = []
    wallet_counter = 0
    last_wallet_time = 0.0
    last_payment_time = 0.0
    last_rediscover_time = time.time()

    print("Starting simulation...")
    print(f"  - Network: {network}")
    print(f"  - Payment mode: {'Lightning' if lightning else 'On-chain'}")
    print(f"  - Target wallets: {num_wallets} ({wallets_per_ledger:.1f} per ledger)")
    print(f"  - New wallet every {wallet_creation_interval:.1f}s")
    print(f"  - Payment every {payment_interval}s")
    print(f"  - Re-discover ledgers every {rediscover_interval}s")
    if network != "regtest":
        print(f"  - Note: No block mining on {network}")
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

                        # Fund it - use Lightning if enabled and we have a funded deposit
                        print(f"[{time.strftime('%H:%M:%S')}] Funding {alias}...")

                        # Find a deposit with enough balance to fund via Lightning
                        funded_deposits = [d for d in our_deposits if d.balance_sats >= funding_amount_sats + 1000 and d.alias != alias]

                        if lightning and funded_deposits:
                            # Fund via Lightning from existing deposit
                            funder = random.choice(funded_deposits)
                            print(f"  Funding via Lightning from {funder.alias}...")
                            if fund_deposit_lightning(funder, alias, funding_amount_sats):
                                deposit.status = "funded"
                                deposit.balance_sats = funding_amount_sats  # Update recipient balance
                                print(f"  Deposit funded via Lightning")
                            else:
                                # Fall back to faucet
                                print(f"  Lightning funding failed, falling back to faucet...")
                                if fund_deposit(alias):
                                    mine_block(network)
                                    deposit.status = "funded"
                                    print(f"  Deposit funded via faucet")
                        else:
                            # Fund via faucet (on-chain)
                            if fund_deposit(alias):
                                mine_block(network)
                                deposit.status = "funded"
                                print(f"  Deposit funded, waiting for balance sync")

                last_wallet_time = now

            # Make payments (withdrawals) periodically
            if now - last_payment_time >= payment_interval and len(our_deposits) >= 2:
                # Find deposits with sufficient balance (need balance > payment + fee)
                min_balance_needed = max_payment_sats + 1000  # payment + fee buffer
                funded = [d for d in our_deposits if d.balance_sats >= min_balance_needed]

                # Only sync if we don't have enough funded deposits yet
                # (avoids constant syncing once Lightning funding is working)
                if len(funded) < 2:
                    balances = sync_and_get_balances()
                    # Update deposit balances from ledger
                    for d in our_deposits:
                        if d.alias in balances:
                            d.balance_sats = balances[d.alias]
                            if d.balance_sats > 0:
                                d.status = "credited"
                    # Recalculate funded list after sync
                    funded = [d for d in our_deposits if d.balance_sats >= min_balance_needed]

                if len(funded) >= 2:
                    # Pick sender and receiver
                    sender = random.choice(funded)
                    receiver = random.choice([d for d in our_deposits if d != sender and d.funding_address])

                    # Random payment amount, but don't exceed sender's balance
                    max_amount = min(max_payment_sats, sender.balance_sats - 1000)  # Leave 1000 for fee
                    if max_amount >= min_payment_sats:
                        amount = random.randint(min_payment_sats, max_amount)

                        if lightning:
                            print(f"\n[{time.strftime('%H:%M:%S')}] Lightning: {sender.alias} ({sender.balance_sats} sats) -> {receiver.alias}")
                            paid_amount = lightning_payment(sender, receiver, amount)
                            if paid_amount:
                                # Lightning is instant, update both balances with actual amount
                                sender.balance_sats -= paid_amount
                                receiver.balance_sats += paid_amount
                        else:
                            print(f"\n[{time.strftime('%H:%M:%S')}] Payment: {sender.alias} ({sender.balance_sats} sats) -> {receiver.alias}")
                            if withdraw_to(sender.alias, receiver.funding_address, amount):
                                # Mine to confirm (regtest only)
                                mine_block(network)
                                if network == "regtest":
                                    print(f"  Mined block to confirm")
                                # Update sender balance estimate
                                sender.balance_sats -= (amount + 500)
                else:
                    print(f"\n[{time.strftime('%H:%M:%S')}] Waiting for funded deposits (need {min_balance_needed}+ sats, have: {[f'{d.alias}:{d.balance_sats}' for d in our_deposits]})")

                last_payment_time = now

            # Periodically re-discover ledgers to find new operators
            if now - last_rediscover_time >= rediscover_interval:
                new_ledgers = discover_ledgers()
                if len(new_ledgers) > len(ledgers):
                    added = len(new_ledgers) - len(ledgers)
                    print(f"\n[{time.strftime('%H:%M:%S')}] Discovered {added} new ledger(s)!")
                    ledgers = new_ledgers
                    # Recalculate targets
                    num_wallets = max(4, int(len(ledgers) * wallets_per_ledger))
                    wallet_creation_interval = base_wallet_interval / (1 + len(ledgers) * 0.2)
                    wallet_creation_interval = max(1.0, wallet_creation_interval)
                    print(f"  Adjusted: target {num_wallets} wallets, interval {wallet_creation_interval:.1f}s")
                last_rediscover_time = now

            # Print status periodically
            if int(now) % 30 == 0:
                funded_count = len([d for d in our_deposits if d.balance_sats > 0])
                total_balance = sum(d.balance_sats for d in our_deposits)
                print(f"\n[{time.strftime('%H:%M:%S')}] Status: {len(ledgers)} ledgers, {len(our_deposits)}/{num_wallets} wallets, {funded_count} funded, {total_balance} sats")
                if lightning:
                    total_payments = PAYMENTS_SUCCESS + PAYMENTS_FAILED
                    total_funding = FUNDING_SUCCESS + FUNDING_FAILED
                    print(f"  Payments: {PAYMENTS_SUCCESS}/{total_payments} ({VOLUME_SATS:,} sats) | Funding: {FUNDING_SUCCESS}/{total_funding} ({FUNDING_VOLUME_SATS:,} sats)")
                    # Update Prometheus gauges
                    if PROMETHEUS_AVAILABLE:
                        PROM_DEPOSITS_COUNT.labels(status='total').set(len(our_deposits))
                        PROM_DEPOSITS_COUNT.labels(status='funded').set(funded_count)
                        PROM_DEPOSITS_BALANCE.set(total_balance)
                        PROM_LEDGERS_COUNT.set(len(ledgers))

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n\nSimulation stopped by user")
        print(f"Final state: {len(our_deposits)} deposits")
        if lightning:
            print(f"\nLightning Metrics:")
            print(f"  Payments: {PAYMENTS_SUCCESS} success, {PAYMENTS_FAILED} failed, {VOLUME_SATS:,} sats volume")
            print(f"  Funding:  {FUNDING_SUCCESS} success, {FUNDING_FAILED} failed, {FUNDING_VOLUME_SATS:,} sats volume")
            print(f"  Total:    {PAYMENTS_SUCCESS + FUNDING_SUCCESS} success, {PAYMENTS_FAILED + FUNDING_FAILED} failed, {VOLUME_SATS + FUNDING_VOLUME_SATS:,} sats")
        for d in our_deposits:
            print(f"  {d.alias}: {d.status} on ledger {d.ledger_id[:16]}...")


def main():
    parser = argparse.ArgumentParser(description="Bitcoin Deposits Payment Simulator")
    parser.add_argument("--network", type=str, default="signet",
                        choices=["regtest", "signet", "mainnet"],
                        help="Bitcoin network (default: signet)")
    parser.add_argument("--lightning", action="store_true",
                        help="Use Lightning invoices instead of on-chain withdrawals")
    parser.add_argument("--wallets-per-ledger", type=float, default=2.0,
                        help="Target wallets per discovered ledger (default: 2.0)")
    parser.add_argument("--base-interval", type=float, default=3.0,
                        help="Base interval between wallet creations (default: 3)")
    parser.add_argument("--payment-interval", type=float, default=2.0,
                        help="Seconds between payments (default: 2)")
    parser.add_argument("--funding-sats", type=int, default=100000,
                        help="Sats to fund each wallet (default: 100000)")
    parser.add_argument("--min-payment", type=int, default=1000,
                        help="Minimum payment in sats (default: 1000)")
    parser.add_argument("--max-payment", type=int, default=5000,
                        help="Maximum payment in sats (default: 5000)")
    parser.add_argument("--rediscover-interval", type=float, default=60.0,
                        help="Seconds between ledger re-discovery (default: 60)")

    args = parser.parse_args()

    run_simulation(
        wallets_per_ledger=args.wallets_per_ledger,
        base_wallet_interval=args.base_interval,
        payment_interval=args.payment_interval,
        funding_amount_sats=args.funding_sats,
        min_payment_sats=args.min_payment,
        max_payment_sats=args.max_payment,
        rediscover_interval=args.rediscover_interval,
        network=args.network,
        lightning=args.lightning,
    )


if __name__ == "__main__":
    main()
