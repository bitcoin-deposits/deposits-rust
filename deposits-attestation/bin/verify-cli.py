#!/usr/bin/env python3
"""CLI for testing the lightning-verify service.

Usage:
    # NIP-05 path (free, if domain has .well-known/nostr.json):
    ./bin/verify-cli.py --relay wss://relay.example.com --verifier <hex> --address alice@example.com

    # Full challenge flow (interactive):
    ./bin/verify-cli.py --relay wss://relay.example.com --verifier <hex> --address alice@example.com --key <hex>

    # Use a specific secret key (otherwise generates a random one):
    ./bin/verify-cli.py --relay wss://... --verifier <hex> --address user@domain.com --key <hex-secret>

Environment:
    VERIFY_RELAY     - Default relay URL
    VERIFY_PUBKEY    - Default verifier hex pubkey
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time

try:
    from secp256k1 import PrivateKey
except ImportError:
    print("pip install secp256k1")
    sys.exit(1)

try:
    import websocket
except ImportError:
    print("pip install websocket-client")
    sys.exit(1)


def create_event(secret_key, kind, content, tags):
    pk = PrivateKey(secret_key)
    pubkey = pk.pubkey.serialize()[1:].hex()  # x-only
    created_at = int(time.time())
    serialized = json.dumps(
        [0, pubkey, created_at, kind, tags, content], separators=(",", ":")
    )
    event_hash = hashlib.sha256(serialized.encode()).digest()
    sig = pk.schnorr_sign(event_hash, bip340tag=None, raw=True)
    return {
        "id": event_hash.hex(),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig.hex(),
    }


def send_and_wait(ws, secret_key, verifier_pubkey, payload, timeout=30):
    content = json.dumps(payload)
    tags = [["p", verifier_pubkey]]
    event = create_event(secret_key, 25500, content, tags)
    ws.send(json.dumps(["EVENT", event]))
    ws.settimeout(timeout)
    while True:
        msg = json.loads(ws.recv())
        if msg[0] == "EVENT" and msg[2].get("kind") in (25501, 55502):
            return json.loads(msg[2]["content"])
        if msg[0] == "EOSE":
            continue


def main():
    parser = argparse.ArgumentParser(description="Test lightning-verify service")
    parser.add_argument("--relay", default=os.environ.get("VERIFY_RELAY", ""), help="Relay WebSocket URL")
    parser.add_argument("--verifier", default=os.environ.get("VERIFY_PUBKEY", ""), help="Verifier hex pubkey")
    parser.add_argument("--address", required=True, help="Lightning address to verify (user@domain)")
    parser.add_argument("--key", default="", help="Your hex secret key (random if omitted)")
    args = parser.parse_args()

    if not args.relay:
        print("--relay or VERIFY_RELAY required")
        sys.exit(1)
    if not args.verifier:
        print("--verifier or VERIFY_PUBKEY required")
        sys.exit(1)

    secret_key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(32)
    pk = PrivateKey(secret_key)
    pubkey = pk.pubkey.serialize()[1:].hex()

    print(f"Your pubkey: {pubkey}")
    print(f"Verifier:    {args.verifier[:32]}...")
    print(f"Relay:       {args.relay}")
    print(f"Address:     {args.address}")
    print()

    ws = websocket.create_connection(args.relay)
    ws.send(json.dumps(["REQ", "sub1", {
        "kinds": [25501, 55502],
        "since": int(time.time()) - 5,
    }]))

    # Step 1: Link
    print("=== Link ===")
    resp = send_and_wait(ws, secret_key, args.verifier, {
        "lightning_address": args.address,
    })

    if resp.get("status") == "verified":
        print(f"Verified via NIP-05!")
        print(f"  Method: {resp.get('method')}")
        print(f"  Attestation: {resp.get('attestation_event_id', '?')[:24]}...")
        ws.close()
        return

    if resp.get("status") == "already_verified":
        print(f"Already verified: {resp.get('message')}")
        ws.close()
        return

    if resp.get("status") == "error":
        print(f"Error: {resp.get('message')}")
        ws.close()
        sys.exit(1)

    if not resp.get("invoice"):
        print(f"Unexpected: {json.dumps(resp, indent=2)}")
        ws.close()
        sys.exit(1)

    session_id = resp["session_id"]
    print(f"  Invoice: {resp['invoice']}")
    print(f"  Amount:  {resp['amount_sats']} sats")
    print(f"  Session: {session_id}")
    print()

    # Step 2: Wait for payment
    input("Pay the invoice above, then press Enter...")

    # Step 3: Challenge
    print("\n=== Challenge ===")
    for attempt in range(10):
        resp = send_and_wait(ws, secret_key, args.verifier, {
            "action": "challenge",
            "session_id": session_id,
        })
        status = resp.get("status", "?")
        if status == "challenge_sent":
            print(f"  {resp.get('message', 'Challenge payments sent!')}")
            break
        if status == "payment_pending":
            print(f"  Payment not confirmed yet, retrying in 3s...")
            time.sleep(3)
            continue
        print(f"  Error: {json.dumps(resp)}")
        ws.close()
        sys.exit(1)

    if status != "challenge_sent":
        print("Payment not confirmed in time.")
        ws.close()
        sys.exit(1)

    # Step 4: Enter amounts
    print()
    amounts_str = input("Enter the amounts you received (comma-separated sats): ")
    amounts = [int(x.strip()) for x in amounts_str.split(",") if x.strip()]

    # Step 5: Verify
    print("\n=== Verify ===")
    resp = send_and_wait(ws, secret_key, args.verifier, {
        "action": "verify",
        "session_id": session_id,
        "amounts": amounts,
    })

    if resp.get("status") == "verified":
        print(f"Verified!")
        print(f"  Method:      {resp.get('method')}")
        print(f"  Attestation: {resp.get('attestation_event_id', '?')[:24]}...")
        print(f"  Verifier:    {resp.get('verifier_pubkey', '?')[:24]}...")
        print(f"  Signature:   {resp.get('signature', '?')[:24]}...")
    else:
        print(f"Failed: {json.dumps(resp, indent=2)}")
        sys.exit(1)

    ws.close()


if __name__ == "__main__":
    main()
