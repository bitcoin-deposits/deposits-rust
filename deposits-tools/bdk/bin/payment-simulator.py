#!/usr/bin/env python3
"""
Payment Simulator for Bitcoin Deposits Protocol

Drives wallet.sh to create real ledger activity:
1. Discovers available ledgers
2. Opens deposits with random aliases
3. Funds them via faucet
4. Makes withdrawals between deposits (actual ledger operations)

Modes:
  --lightning  Use Lightning invoices instead of on-chain withdrawals
  --transfers  Use same-ledger HTLC transfers (requires same ledger)

Usage:
    python3 payment-simulator.py [--wallets N] [--payment-interval SECS]
    python3 payment-simulator.py --lightning  # Lightning payments
    python3 payment-simulator.py --transfers  # Same-ledger transfers
"""

import argparse
import hashlib
import json
import os
import random
import secrets
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, Future
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
CONFIG_FILE = SCRIPT_DIR / "simulator-config.json"  # Runtime config file

# Dynamic configuration (can be changed at runtime via config file)
class DynamicConfig:
    """Configuration that can be reloaded at runtime."""
    def __init__(self):
        self.payment_interval = 0.2  # seconds between payments
        self.max_concurrent = 10  # max concurrent payment operations
        self.paused = False  # pause payments
        self._last_load_time = 0.0
        self._last_mtime = 0.0

    def maybe_reload(self):
        """Reload config from file if it changed (check at most once per second)."""
        now = time.time()
        if now - self._last_load_time < 1.0:
            return
        self._last_load_time = now

        if not CONFIG_FILE.exists():
            return

        try:
            mtime = CONFIG_FILE.stat().st_mtime
            if mtime <= self._last_mtime:
                return
            self._last_mtime = mtime

            with open(CONFIG_FILE) as f:
                data = json.load(f)

            old_interval = self.payment_interval
            old_concurrent = self.max_concurrent
            old_paused = self.paused

            self.payment_interval = float(data.get("payment_interval", self.payment_interval))
            self.max_concurrent = int(data.get("max_concurrent", self.max_concurrent))
            self.paused = bool(data.get("paused", self.paused))

            # Log changes
            if self.payment_interval != old_interval:
                print(f"\n[CONFIG] Payment interval: {old_interval}s -> {self.payment_interval}s")
            if self.max_concurrent != old_concurrent:
                print(f"\n[CONFIG] Max concurrent: {old_concurrent} -> {self.max_concurrent}")
            if self.paused != old_paused:
                print(f"\n[CONFIG] Paused: {old_paused} -> {self.paused}")

        except (json.JSONDecodeError, IOError) as e:
            pass  # Silently ignore config errors

    def write_default(self):
        """Write default config file if it doesn't exist."""
        if not CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'w') as f:
                json.dump({
                    "payment_interval": self.payment_interval,
                    "max_concurrent": self.max_concurrent,
                    "paused": self.paused,
                }, f, indent=2)
            print(f"  Config file: {CONFIG_FILE}")

DYNAMIC_CONFIG = DynamicConfig()

# Global payment counter - used to make each invoice unique by adding msat offset
PAYMENT_COUNTER = 0

# Payment metrics (local counters)
PAYMENTS_SUCCESS = 0
PAYMENTS_FAILED = 0
VOLUME_SATS = 0
FUNDING_SUCCESS = 0
FUNDING_FAILED = 0
FUNDING_VOLUME_SATS = 0
TRANSFERS_SUCCESS = 0
TRANSFERS_FAILED = 0
TRANSFERS_VOLUME_SATS = 0

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
    PROM_TRANSFERS_TOTAL = Counter(
        'simulator_transfers_total',
        'Total number of same-ledger transfers attempted',
        ['status']  # 'success' or 'failed'
    )
    PROM_TRANSFERS_SATS = Counter(
        'simulator_transfers_sats_total',
        'Total sats transferred via same-ledger transfers'
    )
    PROM_INFLIGHT = Gauge(
        'simulator_inflight_count',
        'Number of in-flight async operations'
    )
    PROM_PAYMENT_INTERVAL = Gauge(
        'simulator_payment_interval_seconds',
        'Current payment interval in seconds'
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
    deposit_pubkey: str = ""  # 33-byte compressed pubkey in hex
    deposit_id: str = ""  # 16-byte ID in hex (first 16 bytes of SHA256(descriptor))


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


def compute_deposit_id(pubkey_hex: str) -> str:
    """Compute deposit_id from pubkey (same as Rust implementation)"""
    if not pubkey_hex:
        return ""
    descriptor = f"pk({pubkey_hex})"
    hash_bytes = hashlib.sha256(descriptor.encode()).digest()
    return hash_bytes[:16].hex()  # First 16 bytes


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
            pubkey = item.get("deposit_pubkey", "")
            deposits.append(Deposit(
                alias=item.get("alias", "unknown"),
                ledger_id=item.get("ledger_id", ""),
                funding_address=item.get("funding_address", ""),
                min_sats=item.get("min_sats", 0),
                max_sats=item.get("max_sats", 0),
                status=item.get("status", "unknown"),
                deposit_pubkey=pubkey,
                deposit_id=compute_deposit_id(pubkey),
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

    # Always load from deposits.json to get deposit_pubkey and deposit_id
    deposit_pubkey = ""
    deposit_id = ""
    deposits = load_deposits()
    for d in deposits:
        if d.alias == alias:
            if not funding_address:
                funding_address = d.funding_address
            deposit_pubkey = d.deposit_pubkey
            deposit_id = d.deposit_id
            break

    if funding_address:
        print(f"  Created: {alias} -> {funding_address[:25]}...")
        return Deposit(
            alias=alias,
            ledger_id=ledger_id,
            funding_address=funding_address,
            min_sats=1000,
            max_sats=amount_sats,
            status="pending",
            deposit_pubkey=deposit_pubkey,
            deposit_id=deposit_id,
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


# Same-ledger transfer functions
# These use HTLC-style hash-locked transfers


def get_current_block_height() -> int:
    """Get current block height from bitcoind"""
    try:
        result = subprocess.run([
            "docker", "exec", "bdk-bitcoind",
            "bitcoin-cli", "-regtest",
            "-rpcuser=user", "-rpcpassword=pass",
            "getblockcount"
        ], capture_output=True, text=True)
        return int(result.stdout.strip())
    except:
        return 100  # Fallback


def transfer_lock(sender_alias: str, dest_deposit_id: str, amount_sats: int,
                  hash_hex: str, timeout_height: int) -> Optional[str]:
    """
    Create a transfer lock (HTLC) from sender to destination deposit.
    Returns the transfer_id on success, None on failure.
    """
    code, stdout, stderr = run_wallet(
        "transfer", sender_alias, str(amount_sats),
        "--to", dest_deposit_id,
        "--hash", hash_hex,
        "--timeout", str(timeout_height)
    )

    if code != 0:
        print(f"  Warning: Transfer lock failed: {stderr}")
        return None

    # Parse transfer_id from output
    # Format: "  Transfer ID: <hex>"
    for line in stdout.split("\n"):
        if "Transfer ID:" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                transfer_id = parts[-1].strip()
                if len(transfer_id) >= 32:
                    return transfer_id

    print(f"  Warning: Could not parse transfer_id from output")
    return None


def transfer_complete(transfer_id: str, preimage_hex: str, ledger_id: str) -> bool:
    """
    Complete a transfer by revealing the preimage.
    """
    code, stdout, stderr = run_wallet(
        "transfer_complete", transfer_id,
        "--preimage", preimage_hex,
        "--ledger", ledger_id
    )

    if code != 0:
        print(f"  Warning: Transfer complete failed: {stderr}")
        return False

    if "completed" in stdout.lower() or "success" in stdout.lower():
        return True

    return False


def same_ledger_transfer(sender: Deposit, receiver: Deposit, amount_sats: int) -> Optional[int]:
    """
    Make a same-ledger HTLC transfer between two deposits.
    1. Generate preimage and hash
    2. Create TransferLock
    3. Complete with preimage

    Returns actual amount transferred on success, None on failure.
    """
    global TRANSFERS_SUCCESS, TRANSFERS_FAILED, TRANSFERS_VOLUME_SATS

    if sender.ledger_id != receiver.ledger_id:
        print(f"  Warning: Transfers require same ledger (sender: {sender.ledger_id[:8]}, receiver: {receiver.ledger_id[:8]})")
        TRANSFERS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
        return None

    if not receiver.deposit_id:
        print(f"  Warning: Receiver {receiver.alias} has no deposit_id")
        TRANSFERS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
        return None

    # Generate preimage and hash
    preimage = secrets.token_bytes(32)
    preimage_hex = preimage.hex()
    hash_hex = hashlib.sha256(preimage).hexdigest()

    # Set timeout 10 blocks in future
    current_height = get_current_block_height()
    timeout_height = current_height + 10

    print(f"  Creating transfer: {sender.alias} -> {receiver.alias} ({amount_sats} sats)")
    print(f"    Hash: {hash_hex[:16]}...")
    print(f"    Timeout: block {timeout_height}")

    # Create the lock
    transfer_id = transfer_lock(
        sender.alias,
        receiver.deposit_id,
        amount_sats,
        hash_hex,
        timeout_height
    )

    if not transfer_id:
        TRANSFERS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
        return None

    print(f"  Transfer locked: {transfer_id[:16]}...")
    print(f"  Completing with preimage...")

    # Complete immediately with preimage
    if transfer_complete(transfer_id, preimage_hex, sender.ledger_id):
        print(f"  Transfer completed!")
        TRANSFERS_SUCCESS += 1
        TRANSFERS_VOLUME_SATS += amount_sats
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='success').inc()
            PROM_TRANSFERS_SATS.inc(amount_sats)
        return amount_sats

    TRANSFERS_FAILED += 1
    if PROMETHEUS_AVAILABLE:
        PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
    return None


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
    transfers: bool = False,
    max_transfers: int = 0,
    single_fund: bool = False,
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
        transfers: Use same-ledger HTLC transfers
    """

    # Lightning and transfers are instant, so we can run 10x faster
    if (lightning or transfers) and payment_interval == 2.0:
        payment_interval = 0.2

    # Initialize dynamic config
    DYNAMIC_CONFIG.payment_interval = payment_interval
    DYNAMIC_CONFIG.write_default()

    # Start Prometheus metrics server for Lightning or transfers mode
    if (lightning or transfers) and PROMETHEUS_AVAILABLE:
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

    # Track ledgers that have been funded on-chain (for --single-fund mode)
    onchain_funded_ledgers: set[str] = set()

    print("Starting simulation...")
    print(f"  - Network: {network}")
    mode = "Transfers" if transfers else ("Lightning" if lightning else "On-chain")
    print(f"  - Payment mode: {mode}")
    if single_fund:
        print(f"  - Single-fund mode: only first deposit per ledger funded on-chain")
    print(f"  - Target wallets: {num_wallets} ({wallets_per_ledger:.1f} per ledger)")
    print(f"  - New wallet every {wallet_creation_interval:.1f}s")
    print(f"  - Payment every {payment_interval}s (adjustable via config file)")
    print(f"  - Max concurrent: {DYNAMIC_CONFIG.max_concurrent}")
    print(f"  - Re-discover ledgers every {rediscover_interval}s")
    if network != "regtest":
        print(f"  - Note: No block mining on {network}")
    print()
    print(f"  To adjust rate at runtime, edit: {CONFIG_FILE}")
    print()

    # Thread pool for async payments
    executor = ThreadPoolExecutor(max_workers=DYNAMIC_CONFIG.max_concurrent)
    inflight_futures: list[Future] = []

    # Lock for deposit balance updates from async operations
    deposits_lock = threading.Lock()

    try:
        while True:
            now = time.time()

            # Check for config changes
            DYNAMIC_CONFIG.maybe_reload()
            payment_interval = DYNAMIC_CONFIG.payment_interval

            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                PROM_PAYMENT_INTERVAL.set(payment_interval)
                PROM_INFLIGHT.set(len([f for f in inflight_futures if not f.done()]))

            # Clean up completed futures and process results
            still_pending = []
            for future in inflight_futures:
                if future.done():
                    try:
                        result = future.result()
                        if result:
                            sender_alias, receiver_alias, amount = result
                            with deposits_lock:
                                for d in our_deposits:
                                    if d.alias == sender_alias:
                                        d.balance_sats -= amount
                                    elif d.alias == receiver_alias:
                                        d.balance_sats += amount
                    except Exception as e:
                        pass  # Error already logged in the worker
                else:
                    still_pending.append(future)
            inflight_futures = still_pending

            # Skip payments if paused
            if DYNAMIC_CONFIG.paused:
                time.sleep(0.1)
                continue

            # Create new deposits periodically
            if now - last_wallet_time >= wallet_creation_interval:
                if len(our_deposits) < num_wallets:
                    wallet_counter += 1
                    # Use timestamp-based alias to avoid conflicts with old deposits
                    ts = int(time.time()) % 100000
                    alias = f"sim-{ts}-{wallet_counter:02d}"
                    ledger_id = random.choice(ledgers)

                    # In single-fund mode, first deposit on ledger needs larger max_sats
                    is_first_on_ledger = ledger_id not in onchain_funded_ledgers
                    if single_fund and is_first_on_ledger:
                        open_amount = int(funding_amount_sats * wallets_per_ledger * 1.2)
                    else:
                        open_amount = funding_amount_sats

                    print(f"\n[{time.strftime('%H:%M:%S')}] Creating deposit {alias}...")
                    deposit = open_deposit(ledger_id, alias, open_amount)

                    if deposit:
                        our_deposits.append(deposit)

                        # Fund it - use Lightning/transfers if enabled and we have a funded deposit
                        print(f"[{time.strftime('%H:%M:%S')}] Funding {alias}...")

                        # In single-fund mode: only fund first deposit on each ledger via faucet
                        is_first_on_ledger = ledger_id not in onchain_funded_ledgers

                        if single_fund and not is_first_on_ledger:
                            # Must fund via transfer/lightning - wait for a funder
                            min_funder_balance = int(funding_amount_sats * 1.1) + 5000

                            # Sync balances first
                            balances = sync_and_get_balances()
                            for d in our_deposits:
                                if d.alias in balances:
                                    d.balance_sats = balances[d.alias]

                            same_ledger_funders = [d for d in our_deposits
                                                   if d.ledger_id == ledger_id
                                                   and d.balance_sats >= min_funder_balance
                                                   and d.alias != alias]

                            if same_ledger_funders:
                                funder = random.choice(same_ledger_funders)
                                print(f"  Funding via transfer from {funder.alias} ({funder.balance_sats} sats)...")
                                transferred = same_ledger_transfer(funder, deposit, funding_amount_sats)
                                if transferred:
                                    deposit.status = "funded"
                                    deposit.balance_sats = transferred
                                    funder.balance_sats -= transferred
                                    print(f"  Deposit funded via transfer")
                                else:
                                    print(f"  Transfer funding failed (single-fund mode, not falling back)")
                            else:
                                print(f"  No same-ledger funders yet, will retry later...")
                                # Keep deposit but don't fund yet
                        else:
                            # Find a deposit with enough balance to fund via Lightning/transfers
                            # Require 10% buffer to account for fees and balance drift
                            min_funder_balance = int(funding_amount_sats * 1.1) + 5000
                            funded_deposits = [d for d in our_deposits if d.balance_sats >= min_funder_balance and d.alias != alias]

                            if (lightning or transfers) and funded_deposits and not (single_fund and is_first_on_ledger):
                                # Sync balances first to get accurate ledger state
                                balances = sync_and_get_balances()
                                for d in our_deposits:
                                    if d.alias in balances:
                                        d.balance_sats = balances[d.alias]

                                # Re-check with fresh balances
                                funded_deposits = [d for d in our_deposits if d.balance_sats >= min_funder_balance and d.alias != alias]
                                if not funded_deposits:
                                    print(f"  No deposits with sufficient balance after sync, using faucet...")

                            if transfers and funded_deposits and not (single_fund and is_first_on_ledger):
                                # For transfers, funder must be on same ledger
                                same_ledger_funders = [d for d in funded_deposits if d.ledger_id == ledger_id]
                                if same_ledger_funders:
                                    funder = random.choice(same_ledger_funders)
                                    print(f"  Funding via transfer from {funder.alias} ({funder.balance_sats} sats)...")
                                    transferred = same_ledger_transfer(funder, deposit, funding_amount_sats)
                                    if transferred:
                                        deposit.status = "funded"
                                        deposit.balance_sats = transferred
                                        funder.balance_sats -= transferred
                                        print(f"  Deposit funded via transfer")
                                    else:
                                        # Fall back to faucet
                                        print(f"  Transfer funding failed, falling back to faucet...")
                                        if fund_deposit(alias):
                                            mine_block(network)
                                            deposit.status = "funded"
                                            onchain_funded_ledgers.add(ledger_id)
                                            print(f"  Deposit funded via faucet")
                                else:
                                    # No same-ledger funders, use faucet
                                    print(f"  No same-ledger funders, using faucet...")
                                    if fund_deposit(alias):
                                        mine_block(network)
                                        deposit.status = "funded"
                                        onchain_funded_ledgers.add(ledger_id)
                                        print(f"  Deposit funded via faucet")
                            elif lightning and funded_deposits and not (single_fund and is_first_on_ledger):
                                # Fund via Lightning from existing deposit
                                funder = random.choice(funded_deposits)
                                print(f"  Funding via Lightning from {funder.alias} ({funder.balance_sats} sats)...")
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
                                        onchain_funded_ledgers.add(ledger_id)
                                        print(f"  Deposit funded via faucet")
                            else:
                                # Fund via faucet (on-chain)
                                # In single-fund mode with multiple wallets, fund first with larger amount
                                faucet_amount = funding_amount_sats
                                if single_fund and is_first_on_ledger:
                                    # Fund with enough for all wallets on this ledger
                                    faucet_amount = int(funding_amount_sats * wallets_per_ledger * 1.2)
                                    print(f"  First deposit on ledger, funding with {faucet_amount} sats (for splits)...")
                                if fund_deposit(alias, faucet_amount if single_fund else None):
                                    mine_block(network)
                                    onchain_funded_ledgers.add(ledger_id)
                                    deposit.status = "funded"
                                    print(f"  Deposit funded, waiting for balance sync")

                last_wallet_time = now

            # In single-fund mode, try to fund unfunded deposits via transfers
            if single_fund and transfers:
                unfunded = [d for d in our_deposits if d.status == "pending"]
                if unfunded:
                    # Sync balances
                    balances = sync_and_get_balances()
                    for d in our_deposits:
                        if d.alias in balances:
                            d.balance_sats = balances[d.alias]

                    for deposit in unfunded:
                        min_funder_balance = int(funding_amount_sats * 1.1) + 5000
                        same_ledger_funders = [d for d in our_deposits
                                               if d.ledger_id == deposit.ledger_id
                                               and d.balance_sats >= min_funder_balance
                                               and d.alias != deposit.alias]
                        if same_ledger_funders:
                            funder = random.choice(same_ledger_funders)
                            print(f"\n[{time.strftime('%H:%M:%S')}] Retrying funding {deposit.alias} via transfer from {funder.alias}...")
                            transferred = same_ledger_transfer(funder, deposit, funding_amount_sats)
                            if transferred:
                                deposit.status = "funded"
                                deposit.balance_sats = transferred
                                funder.balance_sats -= transferred
                                print(f"  Deposit funded via transfer")

            # Make payments (withdrawals) periodically
            # Check if we have capacity for more async operations
            inflight_count = len([f for f in inflight_futures if not f.done()])
            can_submit = inflight_count < DYNAMIC_CONFIG.max_concurrent

            if now - last_payment_time >= payment_interval and len(our_deposits) >= 2 and can_submit:
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
                    # Pick sender
                    sender = random.choice(funded)

                    # For transfers, receiver must be on same ledger
                    if transfers:
                        same_ledger = [d for d in our_deposits if d != sender and d.ledger_id == sender.ledger_id and d.deposit_id]
                        if not same_ledger:
                            print(f"\n[{time.strftime('%H:%M:%S')}] No same-ledger receivers for {sender.alias}")
                            last_payment_time = now
                            time.sleep(0.1)
                            continue
                        receiver = random.choice(same_ledger)
                    else:
                        receiver = random.choice([d for d in our_deposits if d != sender and d.funding_address])

                    # Random payment amount, but don't exceed sender's balance
                    max_amount = min(max_payment_sats, sender.balance_sats - 1000)  # Leave 1000 for fee
                    if max_amount >= min_payment_sats:
                        amount = random.randint(min_payment_sats, max_amount)

                        if transfers:
                            # Optimistically update balances before async operation
                            # (prevents double-spending the same funds)
                            sender.balance_sats -= amount
                            print(f"\n[{time.strftime('%H:%M:%S')}] Transfer[async]: {sender.alias} -> {receiver.alias} ({amount} sats) [inflight: {inflight_count + 1}]")

                            # Submit async transfer
                            def do_transfer(s_alias, s_ledger, s_deposit_id, r_alias, r_deposit_id, amt):
                                """Worker function for async transfer."""
                                # Create minimal deposit objects for the transfer
                                s = Deposit(alias=s_alias, ledger_id=s_ledger, deposit_id=s_deposit_id)
                                r = Deposit(alias=r_alias, ledger_id=s_ledger, deposit_id=r_deposit_id)
                                transferred = same_ledger_transfer(s, r, amt)
                                if transferred:
                                    return (s_alias, r_alias, transferred)
                                else:
                                    # Transfer failed, return negative to restore balance
                                    return (s_alias, r_alias, -amt)

                            future = executor.submit(
                                do_transfer,
                                sender.alias, sender.ledger_id, sender.deposit_id,
                                receiver.alias, receiver.deposit_id, amount
                            )
                            inflight_futures.append(future)

                            # Check if we've reached the target
                            if max_transfers > 0 and TRANSFERS_SUCCESS >= max_transfers:
                                # Wait for in-flight to complete
                                for f in inflight_futures:
                                    try:
                                        f.result(timeout=30)
                                    except:
                                        pass
                                print(f"\n[{time.strftime('%H:%M:%S')}] Reached target of {max_transfers} successful transfers!")
                                print(f"\nFinal Metrics:")
                                print(f"  Transfers: {TRANSFERS_SUCCESS} success, {TRANSFERS_FAILED} failed, {TRANSFERS_VOLUME_SATS:,} sats volume")
                                executor.shutdown(wait=False)
                                return
                        elif lightning:
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
                inflight_count = len([f for f in inflight_futures if not f.done()])
                print(f"\n[{time.strftime('%H:%M:%S')}] Status: {len(ledgers)} ledgers, {len(our_deposits)}/{num_wallets} wallets, {funded_count} funded, {total_balance} sats")
                if transfers:
                    total_transfers = TRANSFERS_SUCCESS + TRANSFERS_FAILED
                    print(f"  Transfers: {TRANSFERS_SUCCESS}/{total_transfers} ({TRANSFERS_VOLUME_SATS:,} sats) | interval: {payment_interval}s | inflight: {inflight_count}")
                    # Check if we've reached the target
                    if max_transfers > 0 and TRANSFERS_SUCCESS >= max_transfers:
                        print(f"\n[{time.strftime('%H:%M:%S')}] Reached target of {max_transfers} successful transfers!")
                        print(f"\nFinal Metrics:")
                        print(f"  Transfers: {TRANSFERS_SUCCESS} success, {TRANSFERS_FAILED} failed, {TRANSFERS_VOLUME_SATS:,} sats volume")
                        return
                    # Update Prometheus gauges
                    if PROMETHEUS_AVAILABLE:
                        PROM_DEPOSITS_COUNT.labels(status='total').set(len(our_deposits))
                        PROM_DEPOSITS_COUNT.labels(status='funded').set(funded_count)
                        PROM_DEPOSITS_BALANCE.set(total_balance)
                        PROM_LEDGERS_COUNT.set(len(ledgers))
                elif lightning:
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
        print("Waiting for in-flight operations to complete...")
        executor.shutdown(wait=True, cancel_futures=True)
        print(f"Final state: {len(our_deposits)} deposits")
        if transfers:
            print(f"\nTransfer Metrics:")
            print(f"  Transfers: {TRANSFERS_SUCCESS} success, {TRANSFERS_FAILED} failed, {TRANSFERS_VOLUME_SATS:,} sats volume")
        elif lightning:
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
    parser.add_argument("--transfers", action="store_true",
                        help="Use same-ledger HTLC transfers")
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
    parser.add_argument("--max-transfers", type=int, default=0,
                        help="Stop after this many successful transfers (0 = unlimited)")
    parser.add_argument("--max-concurrent", type=int, default=10,
                        help="Maximum concurrent async operations (default: 10)")
    parser.add_argument("--single-fund", action="store_true",
                        help="Fund only first deposit per ledger on-chain, then use transfers/lightning for others")

    args = parser.parse_args()

    # Set initial config from args
    DYNAMIC_CONFIG.max_concurrent = args.max_concurrent

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
        transfers=args.transfers,
        max_transfers=args.max_transfers,
        single_fund=args.single_fund,
    )


if __name__ == "__main__":
    main()
