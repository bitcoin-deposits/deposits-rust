#!/usr/bin/env python3
"""
Test deposit operations via NWC over Nostr
"""
import asyncio
import json
import websockets
import time
import hashlib
import secrets

class SimpleNWCTester:
    def __init__(self):
        # Generate a simple test client keypair
        self.client_privkey = secrets.randbits(256)
        self.client_privkey_hex = format(self.client_privkey, '064x')
        
        # For simplicity, just use the privkey as pubkey (not cryptographically correct but ok for testing)
        self.client_pubkey_hex = format(self.client_privkey % (2**256), '064x')
        
        # Alice NWC service pubkey (from server logs)
        self.server_pubkey = "879947b22512a75ff743159fa334086a58df320b947d22ba6eb667a687997599"
        
        self.relay_url = "ws://localhost:7777"
        self.websocket = None
        
    async def connect(self):
        """Connect to the Nostr relay"""
        print(f"🔗 Connecting to relay: {self.relay_url}")
        print(f"🔑 Client pubkey: {self.client_pubkey_hex}")
        print(f"🎯 Server pubkey: {self.server_pubkey}")
        
        self.websocket = await websockets.connect(self.relay_url)
        
        # Subscribe to NWC responses
        sub_request = json.dumps([
            "REQ", 
            "nwc_deposit_test",
            {
                "kinds": [23195],  # NIP-47 response
                "authors": [self.server_pubkey],
                "#p": [self.client_pubkey_hex]
            }
        ])
        
        await self.websocket.send(sub_request)
        print("✅ Subscribed to NWC responses")
        return True
        
    async def send_nwc_request(self, method, params):
        """Send a NIP-47 request (simplified version)"""
        created_at = int(time.time())
        
        request_data = {
            "method": method,
            "params": params
        }
        
        # Create simplified event (not properly signed for this test)
        event = {
            "id": format(secrets.randbits(256), '064x'),  # Random ID for testing
            "pubkey": self.client_pubkey_hex,
            "created_at": created_at,
            "kind": 23194,  # NIP-47 request
            "tags": [["p", self.server_pubkey]],
            "content": json.dumps(request_data),
            "sig": format(secrets.randbits(256), '064x')  # Random sig for testing
        }
        
        print(f"📤 Sending {method} request...")
        await self.websocket.send(json.dumps(["EVENT", event]))
        
        # Wait for response
        try:
            response = await asyncio.wait_for(self.websocket.recv(), timeout=15)
            return response
        except asyncio.TimeoutError:
            return f"⏰ {method} request timed out"
        
    async def test_deposit_nwc_operations(self):
        """Test the deposit-specific NWC methods"""
        print("\n🏦 Testing Deposit NWC Operations...")
        
        deposit_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"  # From our created deposit
        
        # Test 1: list_deposits
        print("\n1️⃣  Testing list_deposits via NWC...")
        response = await self.send_nwc_request("list_deposits", {})
        print(f"📋 Response: {response[:300]}...")
        
        # Test 2: get_deposit_balance
        print(f"\n2️⃣  Testing get_deposit_balance for {deposit_pubkey[:16]}...")
        response = await self.send_nwc_request("get_deposit_balance", {
            "deposit_pubkey": deposit_pubkey
        })
        print(f"💰 Response: {response[:300]}...")
        
        # Test 3: make_deposit_invoice 
        print(f"\n3️⃣  Testing make_deposit_invoice for {deposit_pubkey[:16]}...")
        response = await self.send_nwc_request("make_deposit_invoice", {
            "amount": 10000,
            "description": "Test deposit invoice via NWC",
            "deposit_pubkey": deposit_pubkey
        })
        print(f"🧾 Response: {response[:300]}...")

async def main():
    tester = SimpleNWCTester()
    
    try:
        await tester.connect()
        await tester.test_deposit_nwc_operations()
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        if tester.websocket:
            await tester.websocket.close()

if __name__ == "__main__":
    asyncio.run(main())