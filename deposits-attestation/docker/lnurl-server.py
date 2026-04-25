#!/usr/bin/env python3
"""Minimal LNURL-pay server for testing.

Serves .well-known/lnurlp/<user> and generates invoices via ldk-server-cli.
Also serves .well-known/nostr.json from a JSON file for NIP-05.

Environment:
    LDK_CLI      - Path to ldk-server-cli (default: ldk-server-cli)
    LDK_HOST     - LDK server host:port (default: lightning:3000)
    LDK_API_KEY  - API key (default: test_api_key)
    LDK_TLS_CERT - TLS cert path (optional)
    LNURL_HOST   - Hostname for callback URLs (default: 172.21.0.50)
    LNURL_PORT   - Listen port (default: 443)
    NIP05_FILE   - Path to nostr.json (default: /data/nostr.json)
    TLS_CERT     - Server TLS cert (default: /certs/nip05.crt)
    TLS_KEY      - Server TLS key (default: /certs/nip05.key)
"""

import http.server
import json
import os
import ssl
import subprocess
import urllib.parse

LDK_CLI = os.environ.get("LDK_CLI", "ldk-server-cli")
LDK_HOST = os.environ.get("LDK_HOST", "lightning:3000")
LDK_API_KEY = os.environ.get("LDK_API_KEY", "test_api_key")
LDK_TLS_CERT = os.environ.get("LDK_TLS_CERT", "")
LNURL_HOST = os.environ.get("LNURL_HOST", "172.21.0.50")
LNURL_PORT = os.environ.get("LNURL_PORT", "443")
NIP05_FILE = os.environ.get("NIP05_FILE", "/data/nostr.json")

MIN_SENDABLE = 1_000        # 1 sat in msat
MAX_SENDABLE = 1_000_000_000  # 1M sats in msat


def create_invoice(amount_msat, description="lnurl-pay"):
    """Create a BOLT11 invoice via ldk-server-cli."""
    cmd = [LDK_CLI, "-b", LDK_HOST, "-a", LDK_API_KEY]
    if LDK_TLS_CERT:
        cmd += ["-t", LDK_TLS_CERT]
    cmd += ["bolt11-receive", f"{amount_msat}msat", "--description", description]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ldk-server-cli failed: {result.stderr} {result.stdout}")
    data = json.loads(result.stdout)
    return data["invoice"]


class LnurlHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # NIP-05: /.well-known/nostr.json
        if path == "/.well-known/nostr.json":
            try:
                with open(NIP05_FILE) as f:
                    data = f.read()
                self.json_response(200, data)
            except FileNotFoundError:
                self.json_response(404, '{"error":"not found"}')
            return

        # LNURL-pay: /.well-known/lnurlp/<user>
        if path.startswith("/.well-known/lnurlp/"):
            user = path.split("/")[-1]
            scheme = "https" if LNURL_PORT == "443" else "http"
            callback = f"{scheme}://{LNURL_HOST}:{LNURL_PORT}/lnurlp/callback/{user}"
            self.json_response(200, json.dumps({
                "tag": "payRequest",
                "callback": callback,
                "minSendable": MIN_SENDABLE,
                "maxSendable": MAX_SENDABLE,
                "metadata": json.dumps([["text/plain", f"Pay {user}"]]),
            }))
            return

        # LNURL-pay callback: /lnurlp/callback/<user>?amount=<msat>
        if path.startswith("/lnurlp/callback/"):
            amount = qs.get("amount", [None])[0]
            if not amount:
                self.json_response(400, '{"error":"missing amount"}')
                return
            try:
                user = path.split("/")[-1]
                invoice = create_invoice(int(amount), f"lnurl-pay to {user}")
                self.json_response(200, json.dumps({"pr": invoice}))
            except Exception as e:
                self.json_response(500, json.dumps({"error": str(e)}))
            return

        self.json_response(404, '{"error":"not found"}')

    def json_response(self, code, body):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[lnurl] {args[0]}")


if __name__ == "__main__":
    port = int(LNURL_PORT)
    server = http.server.HTTPServer(("0.0.0.0", port), LnurlHandler)

    cert = os.environ.get("TLS_CERT", "/certs/nip05.crt")
    key = os.environ.get("TLS_KEY", "/certs/nip05.key")
    if os.path.exists(cert) and os.path.exists(key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        print(f"LNURL+NIP05 server listening on https://0.0.0.0:{port}")
    else:
        print(f"LNURL+NIP05 server listening on http://0.0.0.0:{port} (no TLS certs)")

    server.serve_forever()
