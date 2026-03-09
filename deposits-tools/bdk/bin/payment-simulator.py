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
    python3 payment-simulator.py --transfers --target-tps 100  # 100 transfers/sec
    python3 payment-simulator.py --transfers --target-tps 50   # 50 transfers/sec
    python3 payment-simulator.py --lightning  # Lightning payments
"""

import argparse
import hashlib
import json
import os
import queue
import random
import secrets
import sqlite3
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
REPO_ROOT = SCRIPT_DIR.parent.parent.parent  # deposits-rust root
WALLET_BINARY = REPO_ROOT / "target" / "release" / "deposits-wallet"
TRANSFER_SIMULATOR_BINARY = REPO_ROOT / "target" / "release" / "transfer-simulator"
DATA_DIR = Path.home() / ".deposits-wallet"
METRICS_PORT = 9200  # Prometheus metrics port
CONFIG_FILE = SCRIPT_DIR / "simulator-config.json"  # Runtime config file

# Dynamic configuration (can be changed at runtime via config file)
class DynamicConfig:
    """Configuration that can be reloaded at runtime."""
    def __init__(self):
        self.payment_interval = 0.1  # seconds between payment batches
        self.max_concurrent = 20  # max concurrent payment operations
        self.target_tps = 100  # target transactions per second (0 = unlimited)
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
            old_target_tps = self.target_tps
            old_paused = self.paused

            self.max_concurrent = int(data.get("max_concurrent", self.max_concurrent))
            self.target_tps = float(data.get("target_tps", data.get("target_qps", self.target_tps)))
            self.paused = bool(data.get("paused", self.paused))

            # Calculate payment_interval from target_tps
            # With N concurrent workers achieving ~225 tx/s max at N=20,
            # we submit batches of up to N transfers per interval
            if self.target_tps > 0:
                # Interval = concurrent / target_tps (submit one batch per interval)
                self.payment_interval = self.max_concurrent / self.target_tps
            else:
                self.payment_interval = float(data.get("payment_interval", 0.01))

            # Log changes
            if self.target_tps != old_target_tps:
                print(f"\n[CONFIG] Target TPS: {old_target_tps} -> {self.target_tps} (interval: {self.payment_interval:.3f}s)")
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
                    "max_concurrent": self.max_concurrent,
                    "target_tps": self.target_tps,
                    "paused": self.paused,
                }, f, indent=2)
            print(f"  Config file: {CONFIG_FILE}")

DYNAMIC_CONFIG = DynamicConfig()


class WalletBatchProcess:
    """Persistent subprocess wrapper for deposits-wallet batch mode.

    Keeps a single WebSocket connection to the Nostr relay and accepts
    JSON commands on stdin, returning JSON responses on stdout.
    One instance per worker thread (not shared across threads).
    """

    def __init__(self, relay: str, network: str, data_dir: str, seed: Optional[str] = None):
        cmd = [str(WALLET_BINARY), "batch", "--relay", relay, "--network", network, "--data-dir", data_dir]
        if seed:
            cmd.extend(["--seed", seed])
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
        )
        self._counter = 0
        # Wait for ready signal
        ready_line = self._proc.stdout.readline()
        if not ready_line:
            raise RuntimeError(f"Batch process exited immediately: {self._proc.stderr.read()}")
        ready = json.loads(ready_line)
        if not ready.get("ready"):
            raise RuntimeError(f"Unexpected ready response: {ready_line}")

    def _next_id(self) -> str:
        self._counter += 1
        return str(self._counter)

    def send_command(self, cmd: dict) -> dict:
        """Send a JSON command and return the parsed response."""
        if self._proc.poll() is not None:
            return {"success": False, "error": "Batch process has exited"}
        cmd_id = self._next_id()
        cmd["id"] = cmd_id
        line = json.dumps(cmd, separators=(',', ':'))
        try:
            self._proc.stdin.write(line + "\n")
            self._proc.stdin.flush()
        except BrokenPipeError:
            return {"success": False, "error": "Batch process pipe broken"}
        resp_line = self._proc.stdout.readline()
        if not resp_line:
            return {"success": False, "error": "Batch process closed stdout"}
        return json.loads(resp_line)

    def transfer_lock(self, alias: str, amount: int, dest_id: str,
                      hash_hex: str, timeout: int, fee: Optional[int] = None) -> dict:
        if fee is None:
            fee = calculate_transfer_fee(amount)
        return self.send_command({
            "cmd": "transfer_lock",
            "alias": alias,
            "amount": amount,
            "to": dest_id,
            "hash": hash_hex,
            "timeout": timeout,
            "fee": fee,
        })

    def transfer_complete(self, transfer_id: str, preimage: str, ledger: str) -> dict:
        return self.send_command({
            "cmd": "transfer_complete",
            "transfer_id": transfer_id,
            "preimage": preimage,
            "ledger": ledger,
        })

    def close(self):
        if self._proc.poll() is None:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)

    def is_alive(self) -> bool:
        return self._proc.poll() is None


# Global payment counter - used to make each invoice unique by adding msat offset
PAYMENT_COUNTER = 0

# Transfer fee schedule: fee = TRANSFER_FEE_FIXED + (amount * TRANSFER_FEE_RATE_BPS / 10000)
# Must match the deposit's TransferFeeSchedule (set at deposit open time).
# Default: 2 sats fixed + 20 bps (matches TransferFeeSchedule::default())
TRANSFER_FEE_FIXED = 2   # Fixed fee per transfer in sats
TRANSFER_FEE_RATE_BPS = 20  # Proportional fee in basis points (1 bps = 0.01%)


def calculate_transfer_fee(amount_sats: int) -> int:
    """Calculate transfer fee for a given amount using the fee schedule."""
    proportional = (amount_sats * TRANSFER_FEE_RATE_BPS) // 10000
    return TRANSFER_FEE_FIXED + proportional

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

# Accounting is now tracked in SimulatorLedger (SQLite)
# ACCT_FUNDED, ACCT_FEES, ACCT_LOCKED, ACCT_LOCK_COUNT are derived from ledger queries

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
    funding_address: str = ""  # Optional for transfer-only operations
    min_sats: int = 0
    max_sats: int = 0
    status: str = "pending"
    balance_sats: int = 0  # Actual confirmed balance from ledger
    deposit_pubkey: str = ""  # 33-byte compressed pubkey in hex
    deposit_id: str = ""  # 16-byte ID in hex (first 16 bytes of SHA256(descriptor))


@dataclass
class TransferWorkItem:
    """Work item for the transfer producer -> worker queue."""
    sender_alias: str
    sender_ledger: str
    sender_deposit_id: str
    receiver_alias: str
    receiver_deposit_id: str
    amount: int
    fee: int


@dataclass
class TransferResult:
    """Result from a completed transfer worker."""
    sender_alias: str
    receiver_alias: str
    amount: int
    success: bool
    locked: bool = False  # True if daemon locked funds (even if complete failed)
    sender_daemon_balance_sats: Optional[int] = None  # Daemon-reported balance on lock failure
    fee: int = 0  # Transfer fee in sats


class SimulatorLedger:
    """SQLite-backed transaction ledger for precise msat-level balance tracking.

    Every balance-changing event is a row. Balance for a deposit = SUM(amount_msats).
    Thread-safe: each thread gets its own connection via thread-local storage.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or str(SCRIPT_DIR / "simulator-ledger.db")
        self._local = threading.local()
        self._create_tables(self._get_conn())

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, timeout=10.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _create_tables(self, conn):
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ledger_events (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp            REAL    NOT NULL,
                deposit_alias        TEXT    NOT NULL,
                event_type           TEXT    NOT NULL,
                amount_msats         INTEGER NOT NULL,
                transfer_id          TEXT,
                counterparty_alias   TEXT,
                daemon_balance_msats INTEGER,
                detail               TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ledger_deposit ON ledger_events(deposit_alias);
            CREATE INDEX IF NOT EXISTS idx_ledger_event_type ON ledger_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_ledger_transfer_id ON ledger_events(transfer_id);
        """)

    def _insert(self, deposit_alias: str, event_type: str, amount_msats: int,
                transfer_id: str = None, counterparty: str = None,
                daemon_balance_msats: int = None, detail: dict = None):
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO ledger_events
               (timestamp, deposit_alias, event_type, amount_msats,
                transfer_id, counterparty_alias, daemon_balance_msats, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (time.time(), deposit_alias, event_type, amount_msats,
             transfer_id, counterparty, daemon_balance_msats,
             json.dumps(detail) if detail else None)
        )
        conn.commit()

    # --- Event recording ---

    def record_fund_confirmed(self, alias: str, balance_msats: int):
        self._insert(alias, 'fund_confirmed', balance_msats,
                     daemon_balance_msats=balance_msats)

    def record_transfer_debit(self, sender: str, receiver: str,
                              amount_sats: int, fee_sats: int):
        total_msats = (amount_sats + fee_sats) * 1000
        self._insert(sender, 'transfer_debit', -total_msats,
                     counterparty=receiver,
                     detail={'amount_sats': amount_sats, 'fee_sats': fee_sats})

    def record_transfer_debit_restore(self, sender: str,
                                      amount_sats: int, fee_sats: int,
                                      daemon_balance_msats: int = None):
        total_msats = (amount_sats + fee_sats) * 1000
        self._insert(sender, 'transfer_debit_restore', total_msats,
                     daemon_balance_msats=daemon_balance_msats)

    def record_transfer_credit(self, receiver: str, sender: str,
                               amount_sats: int, transfer_id: str = None):
        self._insert(receiver, 'transfer_credit', amount_sats * 1000,
                     transfer_id=transfer_id, counterparty=sender)

    def record_transfer_fee(self, sender: str, fee_sats: int, transfer_id: str = None):
        """Marker event (amount=0). Fee already included in transfer_debit."""
        self._insert(sender, 'transfer_fee', 0,
                     transfer_id=transfer_id,
                     detail={'fee_msats': fee_sats * 1000})

    def record_transfer_stuck(self, sender: str, amount_sats: int, fee_sats: int,
                              transfer_id: str = None):
        """Marker event (amount=0). Lock succeeded, complete failed."""
        stuck_msats = (amount_sats + fee_sats) * 1000
        self._insert(sender, 'transfer_stuck', 0,
                     transfer_id=transfer_id,
                     detail={'stuck_msats': stuck_msats,
                             'amount_sats': amount_sats, 'fee_sats': fee_sats})

    def record_daemon_correction(self, alias: str, daemon_balance_msats: int) -> int:
        """Record delta to align with daemon-reported balance. Returns delta in msats."""
        ledger_msats = self.get_balance_msats(alias)
        delta = daemon_balance_msats - ledger_msats
        if delta != 0:
            self._insert(alias, 'daemon_correction', delta,
                         daemon_balance_msats=daemon_balance_msats,
                         detail={'ledger_before_msats': ledger_msats})
        return delta

    def record_resync_adjustment(self, alias: str, daemon_balance_msats: int) -> int:
        """Record delta during periodic resync. Returns delta in msats."""
        ledger_msats = self.get_balance_msats(alias)
        delta = daemon_balance_msats - ledger_msats
        if delta != 0:
            self._insert(alias, 'resync_adjustment', delta,
                         daemon_balance_msats=daemon_balance_msats,
                         detail={'ledger_before_msats': ledger_msats})
        return delta

    # --- Balance queries ---

    def get_balance_msats(self, alias: str) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_msats), 0) FROM ledger_events WHERE deposit_alias = ?",
            (alias,)
        ).fetchone()
        return row[0]

    def get_balance_sats(self, alias: str) -> int:
        return self.get_balance_msats(alias) // 1000

    def get_all_balances_sats(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT deposit_alias, SUM(amount_msats) FROM ledger_events GROUP BY deposit_alias"
        ).fetchall()
        return {row[0]: row[1] // 1000 for row in rows}

    def get_total_balance_msats(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_msats), 0) FROM ledger_events"
        ).fetchone()
        return row[0]

    # --- Accounting queries (replace ACCT_* globals) ---

    def get_total_funded_msats(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_msats), 0) FROM ledger_events "
            "WHERE event_type = 'fund_confirmed'"
        ).fetchone()
        return row[0]

    def get_total_fees_msats(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(CAST(json_extract(detail, '$.fee_msats') AS INTEGER)), 0) "
            "FROM ledger_events WHERE event_type = 'transfer_fee'"
        ).fetchone()
        return row[0]

    def get_total_locked_msats(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(CAST(json_extract(detail, '$.stuck_msats') AS INTEGER)), 0) "
            "FROM ledger_events WHERE event_type = 'transfer_stuck'"
        ).fetchone()
        return row[0]

    def get_lock_stuck_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'transfer_stuck'"
        ).fetchone()
        return row[0]

    def get_total_corrections_msats(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_msats), 0) FROM ledger_events "
            "WHERE event_type IN ('daemon_correction', 'resync_adjustment')"
        ).fetchone()
        return row[0]

    def has_events(self, alias: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM ledger_events WHERE deposit_alias = ? LIMIT 1",
            (alias,)
        ).fetchone()
        return row is not None

    def reset(self):
        conn = self._get_conn()
        conn.execute("DELETE FROM ledger_events")
        conn.commit()


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


def get_balances_local() -> dict[str, int]:
    """Read balances from local deposits.json without network sync. Returns alias -> sats."""
    deposits_file = DATA_DIR / "deposits.json"
    if not deposits_file.exists():
        return {}

    try:
        with open(deposits_file) as f:
            deposits = json.load(f)
        return {d.get("alias", ""): d.get("amount_sats", 0) for d in deposits if d.get("alias")}
    except (json.JSONDecodeError, IOError):
        return {}


def sync_and_get_balances() -> dict[str, int]:
    """Sync deposits and get balances from the ledger. Returns alias -> sats.
    This does a network sync which can be slow - prefer get_balances_local() for fast reads.
    """
    # First sync to get latest balances from ledger
    run_wallet("sync")

    # Then read balance output
    code, stdout, stderr = run_wallet("balance")

    if code != 0:
        return get_balances_local()  # Fallback to local data

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

    # If parsing failed, fallback to local
    if not balances:
        balances = get_balances_local()

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


_cached_block_height = 100
_cached_block_height_time = 0.0
_cached_block_height_lock = threading.Lock()

def get_current_block_height() -> int:
    """Get current block height from bitcoind (cached for 5s to avoid docker exec per transfer)"""
    global _cached_block_height, _cached_block_height_time
    now = time.monotonic()
    if now - _cached_block_height_time < 5.0:
        return _cached_block_height
    with _cached_block_height_lock:
        # Double-check after acquiring lock
        if now - _cached_block_height_time < 5.0:
            return _cached_block_height
        try:
            result = subprocess.run([
                "docker", "exec", "bdk-bitcoind",
                "bitcoin-cli", "-regtest",
                "-rpcuser=user", "-rpcpassword=pass",
                "getblockcount"
            ], capture_output=True, text=True, timeout=5)
            _cached_block_height = int(result.stdout.strip())
            _cached_block_height_time = time.monotonic()
        except:
            pass  # Keep using cached value
        return _cached_block_height


def transfer_lock(sender_alias: str, dest_deposit_id: str, amount_sats: int,
                  hash_hex: str, timeout_height: int, fee: Optional[int] = None) -> tuple[Optional[str], Optional[int]]:
    """
    Create a transfer lock (HTLC) from sender to destination deposit.
    Returns (transfer_id, daemon_balance_sats):
      - (transfer_id, None) on success
      - (None, balance_sats) on insufficient balance (daemon-reported)
      - (None, None) on other failures
    """
    if fee is None:
        fee = calculate_transfer_fee(amount_sats)
    code, stdout, stderr = run_wallet(
        "transfer", sender_alias, str(amount_sats),
        "--to", dest_deposit_id,
        "--hash", hash_hex,
        "--timeout", str(timeout_height),
        "--fee", str(fee),
    )

    if code != 0:
        print(f"  Warning: Transfer lock failed: {stderr}")
        # Parse daemon-reported balance from "Insufficient balance: N msats available"
        daemon_balance_sats = None
        import re
        match = re.search(r'Insufficient balance: (\d+) msats available', stderr)
        if match:
            daemon_balance_sats = int(match.group(1)) // 1000
        return (None, daemon_balance_sats)

    # Parse transfer_id from output
    # Format: "  Transfer ID: <hex>"
    for line in stdout.split("\n"):
        if "Transfer ID:" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                transfer_id = parts[-1].strip()
                if len(transfer_id) >= 32:
                    return (transfer_id, None)

    print(f"  Warning: Could not parse transfer_id from output")
    return (None, None)


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


def do_async_transfer(s_alias: str, s_ledger: str, s_deposit_id: str,
                      r_alias: str, r_deposit_id: str, amt: int,
                      batch_process=None) -> tuple:
    """
    Worker function for async transfers (runs in thread pool).
    Returns (sender_alias, receiver_alias, amount, success, locked, daemon_balance_sats) tuple.
    locked=True means daemon has the funds locked (don't restore sender balance on failure).
    daemon_balance_sats: daemon-reported sender balance on insufficient balance failure.
    """
    try:
        # Validate inputs before creating deposits
        if not s_deposit_id:
            print(f"  [async] Warning: Sender {s_alias} has no deposit_id", flush=True)
            return (s_alias, r_alias, amt, False, False, None)
        if not r_deposit_id:
            print(f"  [async] Warning: Receiver {r_alias} has no deposit_id", flush=True)
            return (s_alias, r_alias, amt, False, False, None)

        # Create minimal deposit objects for the transfer
        sender = Deposit(alias=s_alias, ledger_id=s_ledger, deposit_id=s_deposit_id)
        receiver = Deposit(alias=r_alias, ledger_id=s_ledger, deposit_id=r_deposit_id)

        transferred, locked, daemon_balance = same_ledger_transfer(
            sender, receiver, amt, batch_process=batch_process)
        if transferred is not None and transferred > 0:
            return (s_alias, r_alias, transferred, True, True, None)
        else:
            return (s_alias, r_alias, amt, False, locked, daemon_balance)
    except Exception as e:
        print(f"  [async] Error in transfer {s_alias} -> {r_alias}: {e}", flush=True)
        return (s_alias, r_alias, amt, False, False, None)


def transfer_producer(work_queue, our_deposits, deposits_lock, config,
                      min_payment_sats, max_payment_sats, shutdown_event,
                      consecutive_failures, ledger=None, deposits_by_alias=None):
    """
    Producer thread: generates transfer work items at target TPS rate.
    Acquires deposits_lock to pick sender/receiver and optimistically debit sender.
    Puts TransferWorkItem on work_queue (blocks if full = backpressure).
    Backs off exponentially when consecutive failures are detected.
    """
    # Burst rate limiter: emit up to `burst_size` items, then sleep for the batch interval.
    # This avoids per-item sleep overhead which caps throughput at ~50 TPS.
    last_burst_time = time.monotonic()
    items_this_burst = 0

    while not shutdown_event.is_set():
        # Check pause
        if config.paused:
            time.sleep(0.1)
            continue

        # Failure backoff: when transfers keep failing, slow down to avoid flooding
        failures = consecutive_failures[0]
        if failures >= 5:
            # Exponential backoff: 1s, 2s, 4s, 8s, capped at 15s
            backoff = min(15.0, 2 ** (failures // 5 - 1))
            time.sleep(backoff)
            if shutdown_event.is_set():
                break

        # Rate control: burst-based instead of per-item sleep
        target_tps = config.target_tps
        if target_tps > 0:
            burst_interval = 0.05  # 50ms burst windows
            burst_size = max(1, int(target_tps * burst_interval))
            now = time.monotonic()
            if items_this_burst >= burst_size:
                elapsed = now - last_burst_time
                remaining = burst_interval - elapsed
                if remaining > 0:
                    time.sleep(remaining)
                last_burst_time = time.monotonic()
                items_this_burst = 0

        if shutdown_event.is_set():
            break

        # Pick sender and receiver under lock
        picked = False
        with deposits_lock:
            max_fee = calculate_transfer_fee(max_payment_sats)
            min_balance_needed = max_payment_sats + max_fee + 1000
            funded = [d for d in our_deposits
                      if d.balance_sats >= min_balance_needed and d.status == "funded"]
            if funded:
                sender = random.choice(funded)
                same_ledger = [d for d in our_deposits
                               if d != sender and d.ledger_id == sender.ledger_id
                               and d.deposit_id and d.status == "funded"]
                if same_ledger:
                    receiver = random.choice(same_ledger)
                    max_amount = min(max_payment_sats, sender.balance_sats - calculate_transfer_fee(max_payment_sats) - 1000)
                    if max_amount >= min_payment_sats and sender.deposit_id and receiver.deposit_id:
                        amount = random.randint(min_payment_sats, max_amount)
                        fee = calculate_transfer_fee(amount)
                        if ledger:
                            ledger.record_transfer_debit(sender.alias, receiver.alias, amount, fee)
                            sender.balance_sats = ledger.get_balance_sats(sender.alias)
                        else:
                            sender.balance_sats -= (amount + fee)
                        picked = True

        if not picked:
            time.sleep(0.5)  # No valid pair found - avoid tight spin
            continue

        item = TransferWorkItem(
            sender_alias=sender.alias,
            sender_ledger=sender.ledger_id,
            sender_deposit_id=sender.deposit_id,
            receiver_alias=receiver.alias,
            receiver_deposit_id=receiver.deposit_id,
            amount=amount,
            fee=fee,
        )

        # Put on queue (blocks if full - backpressure)
        try:
            work_queue.put(item, timeout=1.0)
            items_this_burst += 1
        except queue.Full:
            # Queue full, restore sender balance (amount + fee)
            with deposits_lock:
                d = deposits_by_alias.get(item.sender_alias)
                if d:
                    if ledger:
                        ledger.record_transfer_debit_restore(d.alias, item.amount, item.fee)
                        d.balance_sats = ledger.get_balance_sats(d.alias)
                    else:
                        d.balance_sats += item.amount + item.fee


def transfer_worker(work_queue, result_queue, batch_process=None):
    """
    Worker thread: pulls TransferWorkItems from work_queue, executes transfers,
    puts TransferResults on result_queue.
    Uses batch_process (persistent WebSocket) if provided, otherwise falls back to subprocess.
    """
    while True:
        item = work_queue.get()
        if item is None:
            break  # Shutdown sentinel

        result = do_async_transfer(
            item.sender_alias, item.sender_ledger, item.sender_deposit_id,
            item.receiver_alias, item.receiver_deposit_id, item.amount,
            batch_process=batch_process,
        )

        _, _, _, success, locked, daemon_balance = result
        result_queue.put(TransferResult(
            sender_alias=item.sender_alias,
            receiver_alias=item.receiver_alias,
            amount=item.amount,
            success=success,
            locked=locked,
            sender_daemon_balance_sats=daemon_balance,
            fee=item.fee,
        ))


def same_ledger_transfer(sender: Deposit, receiver: Deposit, amount_sats: int,
                         batch_process=None) -> tuple[Optional[int], bool, Optional[int]]:
    """
    Make a same-ledger HTLC transfer between two deposits.
    1. Generate preimage and hash
    2. Create TransferLock
    3. Complete with preimage

    If batch_process is provided, uses persistent WebSocket connection.
    Otherwise falls back to subprocess per operation.

    Returns (amount_transferred, was_locked, daemon_balance_sats):
      (amount, True, None)     - success: both lock and complete succeeded
      (None, True, None)       - lock succeeded but complete failed; funds locked on daemon
      (None, False, balance)   - lock failed; daemon-reported sender balance (or None)
    """
    global TRANSFERS_SUCCESS, TRANSFERS_FAILED, TRANSFERS_VOLUME_SATS

    if sender.ledger_id != receiver.ledger_id:
        print(f"  Warning: Transfers require same ledger (sender: {sender.ledger_id[:8]}, receiver: {receiver.ledger_id[:8]})", flush=True)
        TRANSFERS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
        return (None, False, None)

    if not receiver.deposit_id:
        print(f"  Warning: Receiver {receiver.alias} has no deposit_id", flush=True)
        TRANSFERS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
        return (None, False, None)

    # Generate preimage and hash
    preimage = secrets.token_bytes(32)
    preimage_hex = preimage.hex()
    hash_hex = hashlib.sha256(preimage).hexdigest()

    # Set timeout far enough that transfers complete before expiry.
    # With regtest mining 1 block/sec, +1000 gives ~16 minutes.
    current_height = get_current_block_height()
    timeout_height = current_height + 1000

    # Verbose per-transfer logging disabled for performance (uncomment to debug)
    # print(f"  [async] Creating transfer: {sender.alias} -> {receiver.alias} ({amount_sats} sats)", flush=True)

    # Compute fee from schedule (must match daemon's TransferFeeSchedule on the deposit)
    lock_fee = calculate_transfer_fee(amount_sats)

    t_lock_start = time.monotonic()

    # Create the lock — use batch process if available
    if batch_process and batch_process.is_alive():
        resp = batch_process.transfer_lock(
            sender.alias, amount_sats, receiver.deposit_id,
            hash_hex, timeout_height, fee=lock_fee)
        if resp.get("success"):
            transfer_id = resp.get("transfer_id")
            daemon_balance_sats = None
        else:
            print(f"  Warning: Transfer lock failed: {resp.get('error', 'Unknown')}", flush=True)
            transfer_id = None
            balance_msats = resp.get("balance_msats")
            daemon_balance_sats = balance_msats // 1000 if balance_msats is not None else None
    else:
        transfer_id, daemon_balance_sats = transfer_lock(
            sender.alias,
            receiver.deposit_id,
            amount_sats,
            hash_hex,
            timeout_height,
            fee=lock_fee,
        )

    t_lock_end = time.monotonic()
    lock_ms = (t_lock_end - t_lock_start) * 1000

    if not transfer_id:
        TRANSFERS_FAILED += 1
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
        return (None, False, daemon_balance_sats)

    # Complete immediately with preimage — use batch process if available
    if batch_process and batch_process.is_alive():
        resp = batch_process.transfer_complete(transfer_id, preimage_hex, sender.ledger_id)
        complete_ok = resp.get("success", False)
        if not complete_ok:
            print(f"  Warning: Transfer complete failed: {resp.get('error', 'Unknown')}", flush=True)
    else:
        complete_ok = transfer_complete(transfer_id, preimage_hex, sender.ledger_id)

    t_complete_end = time.monotonic()
    complete_ms = (t_complete_end - t_lock_end) * 1000
    total_ms = (t_complete_end - t_lock_start) * 1000
    # Periodic e2e timing sample (every ~50th transfer to avoid log spam)
    if TRANSFERS_SUCCESS % 50 == 0:
        print(f"  [TIMING] e2e={total_ms:.0f}ms lock={lock_ms:.0f}ms complete={complete_ms:.0f}ms", flush=True)

    fee_sats = calculate_transfer_fee(amount_sats)

    if complete_ok:
        TRANSFERS_SUCCESS += 1
        TRANSFERS_VOLUME_SATS += amount_sats
        # Fee tracking now happens in the main loop via ledger.record_transfer_fee()
        if PROMETHEUS_AVAILABLE:
            PROM_TRANSFERS_TOTAL.labels(status='success').inc()
            PROM_TRANSFERS_SATS.inc(amount_sats)
        return (amount_sats, True, None)

    # Lock succeeded but complete failed - funds are locked on daemon until timeout
    # Stuck tracking now happens in the main loop via ledger.record_transfer_stuck()
    TRANSFERS_FAILED += 1
    print(f"  [ACCT] Lock stuck: {amount_sats + fee_sats:,} sats locked on daemon", flush=True)
    if PROMETHEUS_AVAILABLE:
        PROM_TRANSFERS_TOTAL.labels(status='failed').inc()
    return (None, True, None)



def run_simulation(
    wallets_per_ledger: float = 2.0,
    base_wallet_interval: float = 3.0,
    payment_interval: float = 2.0,
    funding_amount_sats: int = 1000000,
    min_payment_sats: int = 1000,
    max_payment_sats: int = 5000,
    rediscover_interval: float = 60.0,
    network: str = "signet",
    lightning: bool = False,
    transfers: bool = False,
    max_transfers: int = 0,
    single_fund: bool = False,
    auto_topoff: bool = False,
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
    # Initialize SQLite transaction ledger
    ledger = SimulatorLedger()

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
        # Fall back to ledger IDs from existing deposits
        existing = load_deposits()
        ledger_set = set(d.ledger_id for d in existing if d.ledger_id)
        if ledger_set:
            ledgers = list(ledger_set)
            print(f"  Discovery returned nothing, but found {len(ledgers)} ledgers from existing deposits")
        else:
            print("Error: No ledgers found. Make sure operators are running.")
            print("Try: ./bin/wallet.sh discover")
            sys.exit(1)

    print(f"Found {len(ledgers)} ledgers:")
    for lid in ledgers:
        print(f"  {lid[:16]}...")
    print()

    # Fast path: if using Rust transfer simulator, skip wallet warmup/sync/deposit creation
    # The Rust binary handles its own deposit loading and balance tracking
    if transfers and TRANSFER_SIMULATOR_BINARY.exists():
        data_dir = os.environ.get("WALLET_DATA_DIR", str(Path.home() / ".deposits-wallet"))
        seed = os.environ.get("WALLET_SEED")
        if not seed:
            seed_file = Path(data_dir) / "seed.hex"
            if seed_file.exists():
                seed = seed_file.read_text().strip()

        if seed:
            relay = os.environ.get("WALLET_RELAY", "ws://localhost:7801")
            sim_cmd = [
                str(TRANSFER_SIMULATOR_BINARY),
                "--relay", relay,
                "--node", f"sim:{seed}:{data_dir}",
                "--target-tps", str(int(DYNAMIC_CONFIG.target_tps)),
                "--workers", str(DYNAMIC_CONFIG.max_concurrent),
                "--min-amount", str(min_payment_sats),
                "--max-amount", str(max_payment_sats),
                "--fee-fixed", str(TRANSFER_FEE_FIXED),
                "--fee-rate-bps", str(TRANSFER_FEE_RATE_BPS),
                "--config", str(CONFIG_FILE),
            ]
            print(f"Starting Rust transfer simulator...")
            print(f"  {' '.join(sim_cmd[-8:])}")
            rust_sim_proc = subprocess.Popen(
                sim_cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                text=True,
            )

            def rust_sim_reader(proc):
                global TRANSFERS_SUCCESS, TRANSFERS_FAILED, TRANSFERS_VOLUME_SATS
                import re
                status_re = re.compile(
                    r'\[(\d+)s\] TPS: ([\d.]+) \| ok: (\d+) fail: (\d+) timeout: (\d+) \| vol: (\d+) sats')
                for line in proc.stderr:
                    line = line.rstrip()
                    m = status_re.search(line)
                    if m:
                        TRANSFERS_SUCCESS = int(m.group(3))
                        TRANSFERS_FAILED = int(m.group(4))
                        TRANSFERS_VOLUME_SATS = int(m.group(6))
                    print(f"  [rust-sim] {line}", flush=True)

            sim_reader_thread = threading.Thread(
                target=rust_sim_reader,
                args=(rust_sim_proc,),
                daemon=True,
            )
            sim_reader_thread.start()
            print(f"  PID {rust_sim_proc.pid}")
            print()

            # Simple main loop for Rust simulator path
            last_status_time = 0.0
            last_tps_snapshot_time = time.time()
            last_tps_snapshot_count = 0
            last_topoff_time = 0.0
            topoff_deposits: list[Deposit] = []
            if auto_topoff:
                topoff_deposits = load_deposits()
                topoff_threshold = funding_amount_sats // 5  # 20% of funding amount
                if topoff_deposits:
                    print(f"  Auto top-off enabled for {len(topoff_deposits)} deposits (threshold: {topoff_threshold:,} sats)")
            try:
                while True:
                    now = time.time()
                    DYNAMIC_CONFIG.maybe_reload()

                    if rust_sim_proc.poll() is not None:
                        print(f"\n  Rust simulator exited (code {rust_sim_proc.returncode})")
                        break

                    if now - last_status_time >= 30:
                        last_status_time = now
                        total_transfers = TRANSFERS_SUCCESS + TRANSFERS_FAILED
                        elapsed_since_snap = now - last_tps_snapshot_time
                        actual_tps = (TRANSFERS_SUCCESS - last_tps_snapshot_count) / elapsed_since_snap if elapsed_since_snap > 0 else 0
                        last_tps_snapshot_time = now
                        last_tps_snapshot_count = TRANSFERS_SUCCESS
                        pct = f"{100*TRANSFERS_SUCCESS/total_transfers:.0f}%" if total_transfers > 0 else "n/a"
                        print(f"\n[{time.strftime('%H:%M:%S')}] Transfers: {TRANSFERS_SUCCESS}/{total_transfers} ({pct}) ({TRANSFERS_VOLUME_SATS:,} sats) | tps: {actual_tps:.1f}/{DYNAMIC_CONFIG.target_tps:.0f}")

                    # Auto top-off: check balances every 60s, refund low deposits
                    if auto_topoff and topoff_deposits and now - last_topoff_time >= 60:
                        last_topoff_time = now
                        balances = sync_and_get_balances()
                        topped_off = 0
                        for d in topoff_deposits:
                            bal = balances.get(d.alias, 0)
                            if 0 < bal < topoff_threshold:
                                amount = funding_amount_sats - bal
                                print(f"  Top-off: {d.alias} has {bal:,} sats, adding {amount:,}")
                                if fund_deposit(d.alias, amount):
                                    topped_off += 1
                        if topped_off:
                            print(f"  Topped off {topped_off} deposit(s)")

                    time.sleep(0.1)

            except KeyboardInterrupt:
                print("\n\nStopping Rust transfer simulator...")
                rust_sim_proc.terminate()
                try:
                    rust_sim_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    rust_sim_proc.kill()
                print(f"Final: {TRANSFERS_SUCCESS} successes, {TRANSFERS_FAILED} failures, {TRANSFERS_VOLUME_SATS:,} sats volume")

            return  # Exit run_simulation — no need for the rest

    # Warm up the wallet connection with a sync attempt
    # This establishes the Nostr subscription so subsequent syncs are faster
    print("Warming up wallet connection...")
    run_wallet("sync")
    time.sleep(0.5)
    print()

    # Scale wallet count and creation rate based on ledger count
    num_wallets = max(4, int(len(ledgers) * wallets_per_ledger))
    # More ledgers = faster wallet creation (but with diminishing returns)
    # With 1 ledger: base interval, with 10 ledgers: base/3, with 25 ledgers: base/5
    wallet_creation_interval = base_wallet_interval / (1 + len(ledgers) * 0.2)
    wallet_creation_interval = max(1.0, wallet_creation_interval)  # Floor at 1 second

    # Load existing deposits from disk so we don't lose state across restarts
    our_deposits: list[Deposit] = load_deposits()
    if our_deposits:
        # Sync actual balances from ledger for loaded deposits
        print(f"Loaded {len(our_deposits)} existing deposits, syncing balances...")
        balances = sync_and_get_balances()
        for d in our_deposits:
            if d.alias in balances:
                daemon_msats = balances[d.alias] * 1000
                if not ledger.has_events(d.alias):
                    # First run with this DB — seed from daemon
                    if daemon_msats > 0:
                        ledger.record_fund_confirmed(d.alias, daemon_msats)
                else:
                    # DB exists — reconcile with daemon
                    ledger.record_resync_adjustment(d.alias, daemon_msats)
                d.balance_sats = ledger.get_balance_sats(d.alias)
                if d.balance_sats > 0:
                    d.status = "funded"
        funded_count = len([d for d in our_deposits if d.balance_sats > 0])
        # Drop deposits that no longer exist in the ledger (balance never returned)
        missing = [d.alias for d in our_deposits if d.alias not in balances]
        our_deposits = [d for d in our_deposits if d.alias in balances]
        print(f"  {funded_count} funded, {len(our_deposits) - funded_count} empty"
              + (f", {len(missing)} stale (dropped)" if missing else ""))
    wallet_counter = len(our_deposits)

    # Dict index for O(1) deposit lookup by alias (hot path optimization)
    deposits_by_alias: dict[str, Deposit] = {d.alias: d for d in our_deposits}

    # Track ledgers that have been funded on-chain (for --single-fund mode)
    onchain_funded_ledgers: set[str] = set()

    # Create and fund all deposits upfront (batch mode)
    # This ensures all deposits confirm at roughly the same time
    needed = num_wallets - len(our_deposits)
    if needed > 0:
        print(f"Creating {needed} deposits (batch)...")
        ts = int(time.time()) % 100000
        created = []
        for i in range(needed):
            wallet_counter += 1
            alias = f"sim-{ts}-{wallet_counter:02d}"
            ledger_id = ledgers[(wallet_counter - 1) % len(ledgers)]

            if single_fund:
                is_first_on_ledger = ledger_id not in onchain_funded_ledgers
                if is_first_on_ledger:
                    open_amount = int(funding_amount_sats * wallets_per_ledger * 1.2)
                else:
                    open_amount = funding_amount_sats
            else:
                open_amount = funding_amount_sats

            deposit = open_deposit(ledger_id, alias, open_amount)
            if deposit:
                our_deposits.append(deposit)
                deposits_by_alias[deposit.alias] = deposit
                created.append(deposit)
            else:
                print(f"  Warning: Failed to create {alias}, skipping")

        # Fund all newly created deposits
        print(f"\nFunding {len(created)} deposits...")
        for deposit in created:
            ledger_id = deposit.ledger_id
            is_first_on_ledger = ledger_id not in onchain_funded_ledgers

            if single_fund and is_first_on_ledger:
                faucet_amount = int(funding_amount_sats * wallets_per_ledger * 1.2)
                print(f"  {deposit.alias}: faucet {faucet_amount} sats (first on ledger, for splits)...")
            else:
                faucet_amount = funding_amount_sats
                print(f"  {deposit.alias}: faucet {faucet_amount} sats...")

            if fund_deposit(deposit.alias, faucet_amount if single_fund else None):
                onchain_funded_ledgers.add(ledger_id)
                deposit.status = "confirming"
                deposit.balance_sats = 0
            else:
                print(f"  Warning: Failed to fund {deposit.alias}")

        # Wait for all deposits to confirm
        confirming = [d for d in our_deposits if d.status == "confirming"]
        if confirming:
            print(f"\nWaiting for {len(confirming)} deposits to confirm...")
            max_wait = 120  # seconds
            start_wait = time.time()
            while confirming and (time.time() - start_wait) < max_wait:
                time.sleep(3)
                balances = sync_and_get_balances()
                still_confirming = []
                for d in confirming:
                    if d.alias in balances and balances[d.alias] > 0:
                        daemon_msats = balances[d.alias] * 1000
                        d.status = "funded"
                        ledger.record_fund_confirmed(d.alias, daemon_msats)
                        d.balance_sats = ledger.get_balance_sats(d.alias)
                        print(f"  Confirmed: {d.alias} has {d.balance_sats:,} sats")
                    else:
                        still_confirming.append(d)
                confirming = still_confirming
                if confirming:
                    elapsed = int(time.time() - start_wait)
                    print(f"  Still waiting on {len(confirming)} deposits... ({elapsed}s)")

            if confirming:
                print(f"  Warning: {len(confirming)} deposits did not confirm within {max_wait}s")
                print(f"  They will be picked up by the confirmation check in the main loop.")

        funded_count = len([d for d in our_deposits if d.balance_sats > 0])
        acct_funded = ledger.get_total_funded_msats() // 1000
        print(f"\nAll deposits ready: {funded_count} funded, {acct_funded:,} sats total")
    print()

    last_wallet_time = time.time()  # All wallets created, no more needed
    last_payment_time = 0.0
    last_rediscover_time = time.time()
    last_balance_sync_time = time.time()  # Don't sync immediately on startup
    last_full_resync_time = time.time()  # Full balance resync every 10s
    last_status_time = 0.0
    last_tps_snapshot_time = time.time()
    last_tps_snapshot_count = 0  # TRANSFERS_SUCCESS at last snapshot
    last_unfunded_retry_time = 0.0  # Rate-limit unfunded deposit retries
    last_topoff_time = 0.0  # Auto top-off check interval
    topoff_threshold = funding_amount_sats // 5  # 20% of funding amount

    print("Starting simulation...")
    print(f"  - Network: {network}")
    mode = "Transfers" if transfers else ("Lightning" if lightning else "On-chain")
    print(f"  - Payment mode: {mode}")
    if single_fund:
        print(f"  - Single-fund mode: only first deposit per ledger funded on-chain")
    print(f"  - Target wallets: {num_wallets} ({wallets_per_ledger:.1f} per ledger, batch-funded upfront)")
    if transfers:
        print(f"  - Target TPS: {DYNAMIC_CONFIG.target_tps} (work queue model)")
        print(f"  - Worker threads: {DYNAMIC_CONFIG.max_concurrent}")
    else:
        print(f"  - Target TPS: {DYNAMIC_CONFIG.target_tps} (interval: {payment_interval:.3f}s)")
        print(f"  - Max concurrent: {DYNAMIC_CONFIG.max_concurrent}")
    print(f"  - Re-discover ledgers every {rediscover_interval}s")
    if network != "regtest":
        print(f"  - Note: No block mining on {network}")
    print()
    print(f"  To adjust rate at runtime, edit: {CONFIG_FILE}")
    print()

    # Lock for deposit balance updates from async operations
    deposits_lock = threading.Lock()

    if transfers:
        # Python fallback transfer loop (Rust simulator path returns early above)
        shutdown_event = threading.Event()
        consecutive_failures = [0]

        relay = os.environ.get("WALLET_RELAY", "ws://localhost:7801")
        data_dir = os.environ.get("WALLET_DATA_DIR", str(Path.home() / ".deposits-wallet"))
        seed = os.environ.get("WALLET_SEED")
        if not seed:
            seed_file = Path(data_dir) / "seed.hex"
            if seed_file.exists():
                seed = seed_file.read_text().strip()

        rust_sim_proc = None  # Always None here (Rust path returned early)

        work_queue = queue.Queue(maxsize=DYNAMIC_CONFIG.max_concurrent * 2)
        result_queue: queue.Queue[TransferResult] = queue.Queue()

        batch_processes = []
        for i in range(DYNAMIC_CONFIG.max_concurrent):
            try:
                bp = WalletBatchProcess(relay, network, data_dir, seed)
                batch_processes.append(bp)
            except Exception as e:
                print(f"  Warning: batch process {i} failed to start: {e}")
                batch_processes.append(None)
        alive_count = sum(1 for bp in batch_processes if bp is not None)
        print(f"  Started {alive_count}/{DYNAMIC_CONFIG.max_concurrent} batch processes (persistent WebSocket)")

        worker_threads = []
        for i in range(DYNAMIC_CONFIG.max_concurrent):
            t = threading.Thread(
                target=transfer_worker,
                args=(work_queue, result_queue),
                kwargs={"batch_process": batch_processes[i]},
                daemon=True,
            )
            t.start()
            worker_threads.append(t)

        producer_thread = threading.Thread(
            target=transfer_producer,
            args=(work_queue, our_deposits, deposits_lock, DYNAMIC_CONFIG,
                  min_payment_sats, max_payment_sats, shutdown_event,
                  consecutive_failures),
            kwargs={"ledger": ledger, "deposits_by_alias": deposits_by_alias},
            daemon=True,
        )
        producer_thread.start()
    else:
        # Batch model for lightning/onchain modes
        executor = ThreadPoolExecutor(max_workers=DYNAMIC_CONFIG.max_concurrent)
        inflight_futures: list[Future] = []

    try:
        while True:
            now = time.time()

            # Check for config changes
            DYNAMIC_CONFIG.maybe_reload()

            if transfers:
                # Python fallback: drain result queue
                drain_count = 0
                while True:
                    try:
                        if drain_count == 0:
                            result = result_queue.get(timeout=0.01)
                        else:
                            result = result_queue.get_nowait()
                        drain_count += 1
                        if result.success:
                            consecutive_failures[0] = 0  # Reset on any success
                        else:
                            consecutive_failures[0] += 1
                        with deposits_lock:
                            fee_sats = result.fee or calculate_transfer_fee(result.amount)
                            if result.success:
                                # Transfer succeeded - credit receiver, record fee
                                ledger.record_transfer_credit(result.receiver_alias, result.sender_alias, result.amount)
                                ledger.record_transfer_fee(result.sender_alias, fee_sats)
                                d = deposits_by_alias.get(result.receiver_alias)
                                if d:
                                    d.balance_sats = ledger.get_balance_sats(d.alias)
                            elif not result.locked:
                                # Lock failed - restore sender balance
                                daemon_msats = result.sender_daemon_balance_sats * 1000 if result.sender_daemon_balance_sats is not None else None
                                ledger.record_transfer_debit_restore(result.sender_alias, result.amount, fee_sats, daemon_balance_msats=daemon_msats)
                                if daemon_msats is not None:
                                    delta = ledger.record_daemon_correction(result.sender_alias, daemon_msats)
                                    if delta != 0:
                                        print(f"  [ledger] {result.sender_alias}: daemon correction {delta:+,} msats ({delta // 1000:+,} sats)", flush=True)
                                d = deposits_by_alias.get(result.sender_alias)
                                if d:
                                    d.balance_sats = ledger.get_balance_sats(d.alias)
                            else:
                                # Lock succeeded but complete failed - funds stuck on daemon
                                ledger.record_transfer_stuck(result.sender_alias, result.amount, fee_sats)
                    except queue.Empty:
                        break

                # Update Prometheus metrics
                if PROMETHEUS_AVAILABLE:
                    PROM_INFLIGHT.set(work_queue.qsize())
            else:
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
                                sender_alias, receiver_alias, amount, success = result
                                with deposits_lock:
                                    for d in our_deposits:
                                        if success:
                                            if d.alias == receiver_alias:
                                                d.balance_sats += amount
                                        else:
                                            if d.alias == sender_alias:
                                                d.balance_sats += amount
                        except Exception as e:
                            pass  # Error already logged in the worker
                    else:
                        still_pending.append(future)
                inflight_futures = still_pending

            # Skip payments if paused (transfers mode handles pause in producer thread)
            if not transfers and DYNAMIC_CONFIG.paused:
                time.sleep(0.1)
                continue

            # Create new deposits periodically
            if now - last_wallet_time >= wallet_creation_interval:
                if len(our_deposits) < num_wallets:
                    wallet_counter += 1
                    # Use timestamp-based alias to avoid conflicts with old deposits
                    ts = int(time.time()) % 100000
                    alias = f"sim-{ts}-{wallet_counter:02d}"

                    # Cycle through ledgers to ensure even distribution
                    # This ensures we get pairs on each ledger before spreading further
                    ledger_id = ledgers[(wallet_counter - 1) % len(ledgers)]

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
                        deposits_by_alias[deposit.alias] = deposit

                        # Fund it - use Lightning/transfers if enabled and we have a funded deposit
                        print(f"[{time.strftime('%H:%M:%S')}] Funding {alias}...")

                        # In single-fund mode: only fund first deposit on each ledger via faucet
                        is_first_on_ledger = ledger_id not in onchain_funded_ledgers

                        if single_fund and not is_first_on_ledger:
                            # In single-fund mode, second+ deposits still need on-chain funding
                            # to trigger daemon's DepositOpen + DepositCredit. Without it, the
                            # deposit exists as an offer but not on the ledger, so transfers fail.
                            # Fund with the standard amount via faucet.
                            print(f"  Funding via faucet (deposit must be completed on-chain)...")
                            if fund_deposit(alias):
                                onchain_funded_ledgers.add(ledger_id)
                                deposit.status = "confirming"
                                deposit.balance_sats = 0
                                print(f"  Faucet sent, awaiting next block for confirmation...")
                            else:
                                print(f"  Faucet funding failed, will retry later...")
                        else:
                            # Find a deposit with enough balance to fund via Lightning/transfers
                            # Require 10% buffer to account for fees and balance drift
                            min_funder_balance = int(funding_amount_sats * 1.1) + 5000
                            funded_deposits = [d for d in our_deposits if d.balance_sats >= min_funder_balance and d.alias != alias]

                            if transfers and not (single_fund and is_first_on_ledger):
                                # New deposits must be funded on-chain first so the daemon
                                # completes them (DepositOpen + DepositCredit). Without on-chain
                                # funding, the deposit exists as an offer but not on the ledger,
                                # so transfers to/from it will fail.
                                print(f"  Funding via faucet (deposit must be completed on-chain)...")
                                if fund_deposit(alias):
                                    onchain_funded_ledgers.add(ledger_id)
                                    deposit.status = "confirming"
                                    deposit.balance_sats = 0
                                    print(f"  Faucet sent, awaiting next block for confirmation...")
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
                                        onchain_funded_ledgers.add(ledger_id)
                                        deposit.status = "confirming"
                                        deposit.balance_sats = 0
                                        print(f"  Faucet sent, awaiting next block for confirmation...")
                            else:
                                # Fund via faucet (on-chain)
                                # In single-fund mode with multiple wallets, fund first with larger amount
                                faucet_amount = funding_amount_sats
                                if single_fund and is_first_on_ledger:
                                    # Fund with enough for all wallets on this ledger
                                    faucet_amount = int(funding_amount_sats * wallets_per_ledger * 1.2)
                                    print(f"  First deposit on ledger, funding with {faucet_amount} sats (for splits)...")
                                if fund_deposit(alias, faucet_amount if single_fund else None):
                                    onchain_funded_ledgers.add(ledger_id)
                                    # Don't assume balance - mark as awaiting on-chain confirmation.
                                    # The periodic confirmation check will set balance_sats and
                                    # promote to "funded" once the daemon auto-completes the deposit.
                                    deposit.status = "confirming"
                                    deposit.balance_sats = 0
                                    print(f"  Faucet sent, awaiting next block for confirmation...")

                last_wallet_time = now

            # In single-fund mode, retry unfunded deposits via faucet (rate-limited to every 10s)
            if single_fund and transfers and now - last_unfunded_retry_time >= 10:
                with deposits_lock:
                    unfunded = [d for d in our_deposits if d.status == "pending"]
                if unfunded:
                    last_unfunded_retry_time = now
                    for deposit in unfunded:
                        print(f"\n[{time.strftime('%H:%M:%S')}] Retrying funding {deposit.alias} via faucet...")
                        if fund_deposit(deposit.alias):
                            with deposits_lock:
                                deposit.status = "confirming"
                            print(f"  Faucet sent, awaiting next block for confirmation...")

            if transfers:
                # Transfers handled by producer + worker threads
                # Just check if we've reached the target
                if max_transfers > 0 and TRANSFERS_SUCCESS >= max_transfers:
                    print(f"\n[{time.strftime('%H:%M:%S')}] Reached target of {max_transfers} successful transfers!")
                    print(f"\nFinal Metrics:")
                    print(f"  Transfers: {TRANSFERS_SUCCESS} success, {TRANSFERS_FAILED} failed, {TRANSFERS_VOLUME_SATS:,} sats volume")
                    return
            else:
                # Batch submission for lightning/onchain modes
                inflight_count = len([f for f in inflight_futures if not f.done()])
                available_slots = DYNAMIC_CONFIG.max_concurrent - inflight_count

                if now - last_payment_time >= payment_interval and len(our_deposits) >= 2 and available_slots > 0:
                    min_balance_needed = max_payment_sats + 1000
                    funded = [d for d in our_deposits if d.balance_sats >= min_balance_needed]

                    if len(funded) < 2:
                        balances = sync_and_get_balances()
                        for d in our_deposits:
                            if d.alias in balances:
                                d.balance_sats = balances[d.alias]
                                if d.balance_sats > 0:
                                    d.status = "credited"
                        funded = [d for d in our_deposits if d.balance_sats >= min_balance_needed]

                    submitted_this_round = 0
                    for _ in range(available_slots):
                        funded = [d for d in our_deposits if d.balance_sats >= min_balance_needed]

                        can_transfer = False
                        sender = None
                        receiver = None

                        if len(funded) >= 2:
                            sender = random.choice(funded)
                            receiver = random.choice([d for d in our_deposits if d != sender and d.funding_address])
                            can_transfer = True

                        if can_transfer and sender and receiver:
                            max_amount = min(max_payment_sats, sender.balance_sats - 1000)
                            if max_amount >= min_payment_sats:
                                amount = random.randint(min_payment_sats, max_amount)

                                if lightning:
                                    print(f"\n[{time.strftime('%H:%M:%S')}] Lightning: {sender.alias} ({sender.balance_sats} sats) -> {receiver.alias}")
                                    paid_amount = lightning_payment(sender, receiver, amount)
                                    if paid_amount:
                                        sender.balance_sats -= paid_amount
                                        receiver.balance_sats += paid_amount
                                    submitted_this_round += 1
                                else:
                                    print(f"\n[{time.strftime('%H:%M:%S')}] Payment: {sender.alias} ({sender.balance_sats} sats) -> {receiver.alias}")
                                    if withdraw_to(sender.alias, receiver.funding_address, amount):
                                        sender.balance_sats -= (amount + 500)
                                    submitted_this_round += 1
                        else:
                            break

                    last_payment_time = now

            # Confirm on-chain funded deposits and periodically resync all balances
            if now - last_balance_sync_time >= 5:
                with deposits_lock:
                    confirming = [d for d in our_deposits if d.status == "confirming"]
                    needs_full_resync = (now - last_full_resync_time >= 10)
                if confirming or needs_full_resync:
                    balances = sync_and_get_balances()
                    with deposits_lock:
                        for d in our_deposits:
                            if d.alias in balances and balances[d.alias] > 0:
                                daemon_msats = balances[d.alias] * 1000
                                if d.status in ("confirming", "pending"):
                                    d.status = "funded"
                                    ledger.record_fund_confirmed(d.alias, daemon_msats)
                                    d.balance_sats = ledger.get_balance_sats(d.alias)
                                    acct_funded = ledger.get_total_funded_msats() // 1000
                                    print(f"  Confirmed: {d.alias} has {d.balance_sats:,} sats (total funded: {acct_funded:,})")
                                elif needs_full_resync and d.status == "funded":
                                    old_bal = d.balance_sats
                                    delta = ledger.record_resync_adjustment(d.alias, daemon_msats)
                                    d.balance_sats = ledger.get_balance_sats(d.alias)
                                    if abs(delta) > 1_000_000:  # > 1000 sats in msats
                                        print(f"  Resync: {d.alias} drift {delta // 1000:+,} sats (ledger {old_bal:,} -> {d.balance_sats:,})")
                    if needs_full_resync:
                        last_full_resync_time = now
                        daemon_total = sum(balances.get(d.alias, 0) for d in our_deposits)
                        acct_funded = ledger.get_total_funded_msats() // 1000
                        acct_fees = ledger.get_total_fees_msats() // 1000
                        acct_locked = ledger.get_total_locked_msats() // 1000
                        expected = acct_funded - acct_fees - acct_locked
                        corrections = ledger.get_total_corrections_msats() // 1000
                        print(f"  [ACCT] Daemon total: {daemon_total:,} | expected: {expected:,} | gap: {daemon_total - expected:+,} | corrections: {corrections:+,}")
                # Update Prometheus metrics
                if transfers:
                    with deposits_lock:
                        total_balance = sum(d.balance_sats for d in our_deposits)
                        funded_count = len([d for d in our_deposits if d.balance_sats > 0])
                    if PROMETHEUS_AVAILABLE:
                        PROM_DEPOSITS_BALANCE.set(total_balance)
                        PROM_DEPOSITS_COUNT.labels(status='funded').set(funded_count)
                last_balance_sync_time = now

            # Auto top-off: refund deposits that have dropped below threshold
            if auto_topoff and now - last_topoff_time >= 60:
                last_topoff_time = now
                balances = sync_and_get_balances()
                topped_off = 0
                with deposits_lock:
                    for d in our_deposits:
                        bal = balances.get(d.alias, 0)
                        if 0 < bal < topoff_threshold:
                            amount = funding_amount_sats - bal
                            print(f"  Top-off: {d.alias} has {bal:,} sats, adding {amount:,}")
                            if fund_deposit(d.alias, amount):
                                d.status = "confirming"
                                topped_off += 1
                if topped_off:
                    print(f"  Topped off {topped_off} deposit(s)")

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

            # Print status periodically (every 30s)
            if now - last_status_time >= 30:
                last_status_time = now
                funded_count = len([d for d in our_deposits if d.balance_sats > 0])
                confirming_count = len([d for d in our_deposits if d.status == "confirming"])
                total_balance = sum(d.balance_sats for d in our_deposits)
                status_parts = [f"{len(ledgers)} ledgers", f"{len(our_deposits)}/{num_wallets} wallets", f"{funded_count} funded"]
                if confirming_count > 0:
                    status_parts.append(f"{confirming_count} confirming")
                status_parts.append(f"{total_balance} sats")
                print(f"\n[{time.strftime('%H:%M:%S')}] Status: {', '.join(status_parts)}")
                if transfers:
                    total_transfers = TRANSFERS_SUCCESS + TRANSFERS_FAILED
                    # Compute actual TPS since last status
                    elapsed_since_snap = now - last_tps_snapshot_time
                    actual_tps = (TRANSFERS_SUCCESS - last_tps_snapshot_count) / elapsed_since_snap if elapsed_since_snap > 0 else 0
                    last_tps_snapshot_time = now
                    last_tps_snapshot_count = TRANSFERS_SUCCESS
                    pct = f"{100*TRANSFERS_SUCCESS/total_transfers:.0f}%" if total_transfers > 0 else "n/a"
                    queued = work_queue.qsize()
                    failures = consecutive_failures[0]
                    backoff_info = f" | backoff: {min(15, 2 ** (failures // 5 - 1)):.0f}s" if failures >= 5 else ""
                    pending_count = len([d for d in our_deposits if d.status == "pending"])
                    pending_info = f" | {pending_count} unfunded" if pending_count > 0 else ""
                    print(f"  Transfers: {TRANSFERS_SUCCESS}/{total_transfers} ({pct}) ({TRANSFERS_VOLUME_SATS:,} sats) | tps: {actual_tps:.1f}/{DYNAMIC_CONFIG.target_tps:.0f} | queued: {queued}{backoff_info}{pending_info}")
                    # Accounting: where did the money go? (all from sqlite ledger)
                    acct_funded = ledger.get_total_funded_msats() // 1000
                    acct_fees = ledger.get_total_fees_msats() // 1000
                    acct_locked = ledger.get_total_locked_msats() // 1000
                    acct_lock_count = ledger.get_lock_stuck_count()
                    corrections = ledger.get_total_corrections_msats() // 1000
                    expected_balance = acct_funded - acct_fees - acct_locked
                    ledger_balance = ledger.get_total_balance_msats() // 1000
                    discrepancy = ledger_balance - expected_balance
                    lock_info = f" | locked: {acct_locked:,} ({acct_lock_count})" if acct_lock_count > 0 else ""
                    corr_info = f" | corrections: {corrections:+,}" if corrections != 0 else ""
                    print(f"  Accounting: funded={acct_funded:,} - fees={acct_fees:,}{lock_info} = expected {expected_balance:,} | ledger {ledger_balance:,} | gap {discrepancy:+,}{corr_info}")
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

            if not transfers:
                time.sleep(0.01)  # 10ms main loop for non-transfer modes

    except KeyboardInterrupt:
        print("\n\nSimulation stopped by user")
        if transfers:
            print("Shutting down producer and workers...")
            shutdown_event.set()
            # Send sentinel values to workers
            for _ in worker_threads:
                try:
                    work_queue.put(None, timeout=1)
                except queue.Full:
                    pass
            # Join workers
            for t in worker_threads:
                t.join(timeout=5)
            # Close batch processes
            for bp in batch_processes:
                if bp is not None:
                    try:
                        bp.close()
                    except Exception:
                        pass
            # Drain remaining results
            while True:
                try:
                    result = result_queue.get_nowait()
                    fee_sats = result.fee or calculate_transfer_fee(result.amount)
                    with deposits_lock:
                        if result.success:
                            ledger.record_transfer_credit(result.receiver_alias, result.sender_alias, result.amount)
                            ledger.record_transfer_fee(result.sender_alias, fee_sats)
                        elif not result.locked:
                            ledger.record_transfer_debit_restore(result.sender_alias, result.amount, fee_sats)
                        else:
                            ledger.record_transfer_stuck(result.sender_alias, result.amount, fee_sats)
                        for d in our_deposits:
                            d.balance_sats = ledger.get_balance_sats(d.alias)
                except queue.Empty:
                    break
        else:
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
    parser.add_argument("--base-interval", type=float, default=1.0,
                        help="Base interval between wallet creations (default: 1)")
    parser.add_argument("--target-tps", type=float, default=100,
                        help="Target transactions per second (default: 100, 0 = unlimited)")
    parser.add_argument("--payment-interval", type=float, default=None,
                        help="Override: seconds between payment batches (default: auto from target-tps)")
    parser.add_argument("--funding-sats", type=int, default=1000000,
                        help="Sats to fund each wallet (default: 1000000)")
    parser.add_argument("--min-payment", type=int, default=10,
                        help="Minimum payment in sats (default: 10)")
    parser.add_argument("--max-payment", type=int, default=50,
                        help="Maximum payment in sats (default: 50)")
    parser.add_argument("--rediscover-interval", type=float, default=60.0,
                        help="Seconds between ledger re-discovery (default: 60)")
    parser.add_argument("--max-transfers", type=int, default=0,
                        help="Stop after this many successful transfers (0 = unlimited)")
    parser.add_argument("--max-concurrent", type=int, default=20,
                        help="Maximum concurrent async operations (default: 20, optimal for throughput)")
    parser.add_argument("--single-fund", action="store_true",
                        help="Fund only first deposit per ledger on-chain, then use transfers/lightning for others")
    parser.add_argument("--auto-topoff", action="store_true",
                        help="Automatically top off deposits via faucet when balance drops below 20%% of funding amount")
    parser.add_argument("--transfer-fee-fixed", type=int, default=2,
                        help="Fixed fee per transfer in sats (default: 2)")
    parser.add_argument("--transfer-fee-rate-bps", type=int, default=20,
                        help="Proportional transfer fee in basis points (default: 20, 1 bps = 0.01%%)")

    args = parser.parse_args()

    # Set initial config from args
    DYNAMIC_CONFIG.max_concurrent = args.max_concurrent
    DYNAMIC_CONFIG.target_tps = args.target_tps

    # Set transfer fee schedule from args
    global TRANSFER_FEE_FIXED, TRANSFER_FEE_RATE_BPS
    TRANSFER_FEE_FIXED = args.transfer_fee_fixed
    TRANSFER_FEE_RATE_BPS = args.transfer_fee_rate_bps

    # Calculate payment_interval from target_tps unless explicitly overridden
    if args.payment_interval is not None:
        payment_interval = args.payment_interval
    elif args.target_tps > 0:
        # Interval = concurrent / target_tps
        payment_interval = args.max_concurrent / args.target_tps
    else:
        payment_interval = 0.01  # Fast as possible

    DYNAMIC_CONFIG.payment_interval = payment_interval

    run_simulation(
        wallets_per_ledger=args.wallets_per_ledger,
        base_wallet_interval=args.base_interval,
        payment_interval=payment_interval,
        funding_amount_sats=args.funding_sats,
        min_payment_sats=args.min_payment,
        max_payment_sats=args.max_payment,
        rediscover_interval=args.rediscover_interval,
        network=args.network,
        lightning=args.lightning,
        transfers=args.transfers,
        max_transfers=args.max_transfers,
        single_fund=args.single_fund,
        auto_topoff=args.auto_topoff,
    )


if __name__ == "__main__":
    main()
