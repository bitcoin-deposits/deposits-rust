#!/usr/bin/env python3
"""
Simple test script to verify deposit/NWC connection
"""
import asyncio
import json
import websockets
import time
import hashlib
import secp256k1
import secrets

class NWCDepositTester:
    def __init__(self):
        # Generate a test client keypair
        self.client_privkey = secrets.randbits(256).to_bytes(32, 'big')
        self.client_pubkey = secp256k1.PublicKey.from_secret(self.client_privkey).serialize(compressed=False)[1:]  # x-only
        self.client_pubkey_hex = self.client_pubkey.hex()
        
        # Alice NWC service pubkey (derived from Lightning node)
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
            "nwc_test",
            {
                "kinds": [23195],  # NIP-47 response
                "authors": [self.server_pubkey],
                "#p": [self.client_pubkey_hex]
            }
        ])
        
        await self.websocket.send(sub_request)
        print("✅ Subscribed to NWC responses")
        return True
        
    def create_nwc_request(self, method, params):
        """Create a NIP-47 request"""
        created_at = int(time.time())
        
        request_data = {
            "method": method,
            "params": params
        }
        
        # Create event
        event = {
            "id": "",
            "pubkey": self.client_pubkey_hex,
            "created_at": created_at,
            "kind": 23194,  # NIP-47 request
            "tags": [["p", self.server_pubkey]],
            "content": json.dumps(request_data),
            "sig": ""
        }
        
        # Calculate event ID (this is simplified - real implementation needs proper serialization)
        event_json = json.dumps([
            0,
            self.client_pubkey_hex,
            created_at,
            23194,
            [["p", self.server_pubkey]],
            json.dumps(request_data)
        ], separators=(',', ':'))
        
        event_id = hashlib.sha256(event_json.encode()).hexdigest()
        event["id"] = event_id
        
        # Sign event (simplified)
        msg_hash = bytes.fromhex(event_id)
        privkey_obj = secp256k1.PrivateKey(self.client_privkey)
        signature = privkey_obj.schnorr_sign(msg_hash, None, raw=True)
        event["sig"] = signature.hex()
        
        return event
        
    async def test_deposit_operations(self):
        """Test the deposit-specific NWC methods"""
        print("\n🏦 Testing deposit-specific NWC operations...")
        
        # Test 1: list_deposits
        print("1️⃣  Testing list_deposits...")
        event = self.create_nwc_request("list_deposits", {})
        
        await self.websocket.send(json.dumps(["EVENT", event]))
        
        # Wait for response with timeout
        try:
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10)
            print(f"📋 list_deposits response: {response[:200]}...")
            
        except asyncio.TimeoutError:
            print("⏰ list_deposits timed out")
            
        # Test 2: get_deposit_balance
        print("\n2️⃣  Testing get_deposit_balance...")
        test_deposit_pubkey = "025b7bc863456118a016f6413db5cc877dffcdc8dafcfe21f8c74f795d8f4f2220"  # Alice's node pubkey as test
        event = self.create_nwc_request("get_deposit_balance", {"deposit_pubkey": test_deposit_pubkey})
        
        await self.websocket.send(json.dumps(["EVENT", event]))
        
        try:
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10)
            print(f"💰 get_deposit_balance response: {response[:200]}...")
            
        except asyncio.TimeoutError:
            print("⏰ get_deposit_balance timed out")

async def main():
    tester = NWCDepositTester()
    
    try:
        await tester.connect()
        await tester.test_deposit_operations()
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        if tester.websocket:
            await tester.websocket.close()

if __name__ == "__main__":
    asyncio.run(main())