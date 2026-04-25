#!/usr/bin/env python3
"""strfry Prometheus exporter.

Periodically runs `strfry scan --count` against native relay processes to
collect event counts by kind and exposes them as Prometheus metrics on HTTP.

Supports multiple relays (fast + slow) with a relay label.

Usage:
    python3 strfry-exporter.py [--port 9201] [--interval 10]
"""

import argparse
import os
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ── Metrics state ──────────────────────────────────────────────────────────
_lock = threading.Lock()
_metrics: dict[str, float] = {}

# Nostr kinds used by the deposits protocol
KINDS = {
    9100: "ledger_update",
    20101: "request",
    20102: "response",
    9103: "dispute",
    39100: "advertisement",
}

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent
DATA_ROOT = Path(os.environ.get("DATA_ROOT", TOOLS_DIR / "data"))
STRFRY_BIN = os.environ.get("STRFRY_BIN", str(SCRIPT_DIR / "strfry"))

# Relays to scrape: (name, label)
RELAYS = [
    ("alice", "fast"),
    ("ledgers", "slow"),
]


def _relay_config(name: str) -> str:
    """Return the config file path for a relay."""
    return str(DATA_ROOT / "relays" / name / "strfry.conf")


def _run_scan(name: str, kind_filter: str) -> int | None:
    """Run strfry scan --count against a native relay."""
    try:
        conf = _relay_config(name)
        cmd = [STRFRY_BIN, "--config", conf, "scan", "--count", kind_filter]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
    except Exception:
        pass
    return None


def _db_size_bytes(name: str) -> int | None:
    """Get LMDB data file size."""
    try:
        db_file = DATA_ROOT / "relays" / name / "data.mdb"
        if db_file.exists():
            return db_file.stat().st_size
    except Exception:
        pass
    return None


def _active_connections(name: str) -> int | None:
    """Estimate active WebSocket connections from /proc/net/tcp."""
    # Per-node ports follow 7800 + index (alice=7801, bob=7802, ...).
    # Ledgers/messaging come from env vars set by _common.sh, with the
    # 17779/17780 fallback matching the Rust + shell defaults.
    name_to_port = {
        "alice": 7801,
        "bob": 7802,
        "charlie": 7803,
        "diana": 7804,
        "ledgers": int(os.environ.get("RELAY_LEDGERS_PORT", "17779")),
        "messaging": int(os.environ.get("RELAY_MESSAGING_PORT", "17780")),
    }
    port = name_to_port.get(name)
    if port is None:
        return None
    hexport = f"{port:04X}"
    try:
        with open("/proc/net/tcp") as f:
            count = sum(1 for line in f if f":{hexport}" in line.split()[1])
        return max(0, count - 1)  # Subtract LISTEN socket
    except Exception:
        pass
    return None


def collect():
    """Collect all metrics (called periodically by background thread)."""
    new_metrics: dict[str, float] = {}

    for name, relay_label in RELAYS:
        pfx = f'relay="{relay_label}"'

        # Total event count
        total = _run_scan(name, "{}")
        if total is not None:
            new_metrics[f"strfry_events_total{{{pfx}}}"] = total

        # Events by kind
        for kind, label in KINDS.items():
            count = _run_scan(name, f'{{"kinds":[{kind}]}}')
            if count is not None:
                new_metrics[f'strfry_events_by_kind{{{pfx},kind="{kind}",name="{label}"}}'] = count

        # DB size
        db_size = _db_size_bytes(name)
        if db_size is not None:
            new_metrics[f"strfry_db_size_bytes{{{pfx}}}"] = db_size

        # Active connections
        conns = _active_connections(name)
        if conns is not None:
            new_metrics[f"strfry_connections_active{{{pfx}}}"] = conns

    with _lock:
        _metrics.clear()
        _metrics.update(new_metrics)


def collector_loop(interval: float):
    """Background thread that collects metrics."""
    while True:
        try:
            collect()
        except Exception as exc:
            print(f"[strfry-exporter] collection error: {exc}")
        time.sleep(interval)


# ── HTTP handler ───────────────────────────────────────────────────────────
class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        with _lock:
            lines = []
            for key, val in sorted(_metrics.items()):
                # Format: metric_name{labels} value
                lines.append(f"{key} {val}")
            body = "\n".join(lines) + "\n"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        pass  # Silence request logging


def main():
    parser = argparse.ArgumentParser(description="strfry Prometheus exporter")
    parser.add_argument("--port", type=int, default=9201, help="HTTP port (default 9201)")
    parser.add_argument("--interval", type=float, default=10, help="Collection interval seconds (default 10)")
    args = parser.parse_args()

    relay_names = ", ".join(f"{c} ({l})" for c, l, _ in RELAYS)
    print(f"[strfry-exporter] collecting from: {relay_names}")
    collect()
    with _lock:
        print(f"[strfry-exporter] initial metrics: {len(_metrics)} keys")

    # Start background collector
    t = threading.Thread(target=collector_loop, args=(args.interval,), daemon=True)
    t.start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", args.port), MetricsHandler)
    print(f"[strfry-exporter] serving on http://0.0.0.0:{args.port}/metrics")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[strfry-exporter] shutting down")


if __name__ == "__main__":
    main()
