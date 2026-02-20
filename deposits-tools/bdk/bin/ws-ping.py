#!/usr/bin/env python3
"""
Raw WebSocket Nostr ping test.
Measures actual relay latency without nostr-sdk overhead.
"""

import asyncio
import json
import time
import hashlib
import secrets
from typing import Optional

try:
    import websockets
    from secp256k1 import PrivateKey
except ImportError:
    print("Installing dependencies...")
    import subprocess
    subprocess.check_call(['pip3', 'install', 'websockets', 'secp256k1'])
    import websockets
    from secp256k1 import PrivateKey

RELAY_URL = "ws://localhost:7778"
KIND_PING = 29999

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def create_event(privkey: PrivateKey, kind: int, content: str, tags: list = None) -> dict:
    """Create and sign a Nostr event."""
    pubkey = privkey.pubkey.serialize()[1:].hex()  # x-only pubkey
    created_at = int(time.time())
    tags = tags or []

    # Create event ID (sha256 of serialized event)
    serialized = json.dumps([0, pubkey, created_at, kind, tags, content], separators=(',', ':'))
    event_id = sha256(serialized.encode()).hex()

    # Sign the event ID
    sig = privkey.schnorr_sign(bytes.fromhex(event_id), None, raw=True).hex()

    return {
        "id": event_id,
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig
    }

async def run_ping_test(count: int = 50, interval_ms: int = 50):
    """Run ping-pong test with raw WebSocket."""

    # Generate two keypairs
    sender_key = PrivateKey(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002"))
    receiver_key = PrivateKey(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001"))

    sender_pubkey = sender_key.pubkey.serialize()[1:].hex()
    receiver_pubkey = receiver_key.pubkey.serialize()[1:].hex()

    print(f"Sender:   {sender_pubkey[:16]}...")
    print(f"Receiver: {receiver_pubkey[:16]}...")
    print(f"Relay:    {RELAY_URL}")
    print(f"Count:    {count}, Interval: {interval_ms}ms")
    print()

    # Track latencies
    pending = {}
    latencies = []

    async def responder():
        """Receive pings and send pongs."""
        async with websockets.connect(RELAY_URL) as ws:
            # Subscribe to pings
            sub = ["REQ", "pings", {"kinds": [KIND_PING], "#p": [receiver_pubkey]}]
            await ws.send(json.dumps(sub))

            pong_count = 0
            while True:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=10)
                    data = json.loads(msg)

                    if data[0] == "EVENT" and data[1] == "pings":
                        event = data[2]
                        content = json.loads(event["content"])
                        if content.get("type") == "ping":
                            # Send pong
                            pong = create_event(
                                receiver_key, KIND_PING,
                                json.dumps({"type": "pong", "seq": content["seq"]}),
                                [["p", sender_pubkey], ["e", event["id"]]]
                            )
                            await ws.send(json.dumps(["EVENT", pong]))
                            pong_count += 1
                except asyncio.TimeoutError:
                    break

    async def requester():
        """Send pings and measure responses."""
        async with websockets.connect(RELAY_URL) as ws:
            # Subscribe to pongs
            sub = ["REQ", "pongs", {"kinds": [KIND_PING], "#p": [sender_pubkey]}]
            await ws.send(json.dumps(sub))

            # Wait for EOSE
            while True:
                msg = await ws.recv()
                data = json.loads(msg)
                if data[0] == "EOSE":
                    break

            # Spawn receiver task
            async def receive_pongs():
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=5)
                        recv_time = time.time()
                        data = json.loads(msg)

                        if data[0] == "EVENT":
                            event = data[2]
                            try:
                                content = json.loads(event["content"])
                                if content.get("type") == "pong":
                                    seq = content["seq"]
                                    if seq in pending:
                                        latency_ms = (recv_time - pending[seq]) * 1000
                                        latencies.append(latency_ms)
                                        del pending[seq]
                                        print(f"  PONG {seq:3d}: {latency_ms:.2f}ms")
                            except:
                                pass
                    except asyncio.TimeoutError:
                        break

            recv_task = asyncio.create_task(receive_pongs())

            # Send pings
            print("Sending pings...")
            for i in range(count):
                ping = create_event(
                    sender_key, KIND_PING,
                    json.dumps({"type": "ping", "seq": i}),
                    [["p", receiver_pubkey]]
                )
                pending[i] = time.time()
                await ws.send(json.dumps(["EVENT", ping]))
                print(f"PING {i:3d}", end=" ", flush=True)

                if i < count - 1:
                    await asyncio.sleep(interval_ms / 1000)

            print()
            print("Waiting for responses...")
            await recv_task

    # Run both in parallel
    await asyncio.gather(
        responder(),
        requester()
    )

    # Print stats
    print()
    print("=== Results (Raw WebSocket) ===")
    print(f"Sent:     {count}")
    print(f"Received: {len(latencies)} ({100*len(latencies)/count:.1f}%)")
    if latencies:
        print()
        print("Round-trip latency:")
        print(f"  Min:  {min(latencies):.2f}ms")
        print(f"  Max:  {max(latencies):.2f}ms")
        print(f"  Avg:  {sum(latencies)/len(latencies):.2f}ms")
        sorted_lat = sorted(latencies)
        print(f"  P50:  {sorted_lat[len(sorted_lat)//2]:.2f}ms")
        print(f"  P95:  {sorted_lat[int(len(sorted_lat)*0.95)]:.2f}ms")
        print()
        print(f"Effective TPS: {1000/(sum(latencies)/len(latencies)):.1f}")

if __name__ == "__main__":
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    asyncio.run(run_ping_test(count, interval))
