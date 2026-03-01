#!/usr/bin/env python3
"""strfry Prometheus exporter.

Periodically runs `docker exec bdk-nostr-relay strfry scan --count` to collect
event counts by kind and exposes them as Prometheus metrics on an HTTP port.

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
    9101: "request",
    9102: "response",
    9103: "dispute",
}

CONTAINER = os.environ.get("STRFRY_CONTAINER", "bdk-nostr-relay")


def _run_scan(kind_filter: str) -> int | None:
    """Run strfry scan --count inside the relay container."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "/app/strfry", "scan", "--count", kind_filter],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
    except Exception:
        pass
    return None


def _db_size_bytes() -> int | None:
    """Get LMDB data file size."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "stat", "-c", "%s", "/app/strfry-db/data.mdb"],
            capture_output=True, text=True, timeout=5,
        )
        val = result.stdout.strip()
        if val.isdigit():
            return int(val)
    except Exception:
        pass
    return None


def _active_connections() -> int | None:
    """Estimate active WebSocket connections from open TCP sockets on port 7777."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "sh", "-c",
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

    # Total event count
    total = _run_scan("{}")
    if total is not None:
        new_metrics["strfry_events_total"] = total

    # Events by kind
    for kind, label in KINDS.items():
        count = _run_scan(f'{{"kinds":[{kind}]}}')
        if count is not None:
            new_metrics[f"strfry_events_by_kind{{kind=\"{kind}\",name=\"{label}\"}}"] = count

    # DB size
    db_size = _db_size_bytes()
    if db_size is not None:
        new_metrics["strfry_db_size_bytes"] = db_size

    # Active connections
    conns = _active_connections()
    if conns is not None:
        new_metrics["strfry_connections_active"] = conns

    with _lock:
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
                # Format: metric_name value
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

    # Initial collection
    print(f"[strfry-exporter] collecting from container '{CONTAINER}'...")
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
