#!/usr/bin/env python3
"""strfry Prometheus exporter.

Periodically runs `docker exec <container> strfry scan --count` to collect
event counts by kind and exposes them as Prometheus metrics on an HTTP port.

Supports multiple relay containers (fast + slow) with a relay label.

Usage:
    python3 strfry-exporter.py [--port 9201] [--interval 10]
"""

import argparse
import os
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

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

# Relay containers to scrape: (container_name, label, strfry_config_flag)
RELAYS = [
    ("bdk-relay-alice", "fast", ""),
    ("bdk-relay-ledgers", "slow", "--config /app/strfry-slow.conf"),
]


def _run_scan(container: str, config_flag: str, kind_filter: str) -> int | None:
    """Run strfry scan --count inside a relay container."""
    try:
        cmd = ["docker", "exec", container]
        if config_flag:
            parts = config_flag.split()
            cmd.extend(["/app/strfry"] + parts + ["scan", "--count", kind_filter])
        else:
            cmd.extend(["/app/strfry", "scan", "--count", kind_filter])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
    except Exception:
        pass
    return None


def _db_size_bytes(container: str) -> int | None:
    """Get LMDB data file size."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "stat", "-c", "%s", "/app/strfry-db/data.mdb"],
            capture_output=True, text=True, timeout=5,
        )
        val = result.stdout.strip()
        if val.isdigit():
            return int(val)
    except Exception:
        pass
    return None


def _active_connections(container: str) -> int | None:
    """Estimate active WebSocket connections from open TCP sockets on port 7777."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             "cat /proc/net/tcp 2>/dev/null | grep -c ':1E61' || echo 0"],
            capture_output=True, text=True, timeout=5,
        )
        val = result.stdout.strip()
        if val.isdigit():
            # Subtract 1 for the LISTEN socket itself
            return max(0, int(val) - 1)
    except Exception:
        pass
    return None


def collect():
    """Collect all metrics (called periodically by background thread)."""
    new_metrics: dict[str, float] = {}

    for container, relay_label, config_flag in RELAYS:
        pfx = f'relay="{relay_label}"'

        # Total event count
        total = _run_scan(container, config_flag, "{}")
        if total is not None:
            new_metrics[f"strfry_events_total{{{pfx}}}"] = total

        # Events by kind
        for kind, label in KINDS.items():
            count = _run_scan(container, config_flag, f'{{"kinds":[{kind}]}}')
            if count is not None:
                new_metrics[f'strfry_events_by_kind{{{pfx},kind="{kind}",name="{label}"}}'] = count

        # DB size
        db_size = _db_size_bytes(container)
        if db_size is not None:
            new_metrics[f"strfry_db_size_bytes{{{pfx}}}"] = db_size

        # Active connections
        conns = _active_connections(container)
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
