#!/usr/bin/env python3
"""
Test deposit creation via plain Nostr DM (not NWC)
"""
import asyncio
import json
import websockets
import time
import hashlib
import secrets

class DepositDMTester:
    def __init__(self):
        # Generate a test client keypair
        self.client_privkey = secrets.randbits(256)
        self.client_privkey_hex = format(self.client_privkey, '064x')
        
        # For simplicity, derive pubkey from privkey (not cryptographically correct but ok for testing)
        self.client_pubkey_hex = format(self.client_privkey % (2**256), '064x')
        
        # Alice NWC service pubkey (from corrected server logs)
        self.alice_pubkey = "c36e115e99451a6c97f49c4789957f9e7a838450f2c83bbb44744b8609d814fc"
        
        self.relay_url = "ws://localhost:7777"
        self.websocket = None
        
    async def connect(self):
        """Connect to the Nostr relay"""
        print(f"🔗 Connecting to relay: {self.relay_url}")
        print(f"🔑 Client pubkey: {self.client_pubkey_hex}")
        print(f"🎯 Alice pubkey: {self.alice_pubkey}")
        
        self.websocket = await websockets.connect(self.relay_url)
        
        # Subscribe to DMs from Alice
        sub_request = json.dumps([
            "REQ", 
            "dm_deposit_test",
            {
                "kinds": [4],  # DMs
                "authors": [self.alice_pubkey],
                "#p": [self.client_pubkey_hex]
            }
        ])
        
        await self.websocket.send(sub_request)
        print("✅ Subscribed to DM responses from Alice")
        return True
        
    async def send_dm(self, content):
        """Send a DM to Alice (simplified version without proper signing)"""
        created_at = int(time.time())
        
        # Create simplified DM event (not properly signed for this test)
        event = {
            "id": format(secrets.randbits(256), '064x'),  # Random ID for testing
            "pubkey": self.client_pubkey_hex,
            "created_at": created_at,
            "kind": 4,  # DM
            "tags": [["p", self.alice_pubkey]],
            "content": content,
            "sig": format(secrets.randbits(256), '064x')  # Random sig for testing
        }
        
        print(f"📤 Sending DM: {content}")
        await self.websocket.send(json.dumps(["EVENT", event]))
        
        # Wait for response
        try:
            for _ in range(10):  # Try up to 10 messages
                response = await asyncio.wait_for(self.websocket.recv(), timeout=5)
                response_data = json.loads(response)
                
                if (response_data[0] == "EVENT" and 
                    len(response_data) > 2 and 
                    response_data[2].get("kind") == 4):
                    
                    dm_content = response_data[2].get("content", "")
                    print(f"📥 Alice responded: {dm_content}")
                    return dm_content
                    
        except asyncio.TimeoutError:
            return f"⏰ No response received"
        
        return "🤷 No DM response found"
        
    async def test_deposit_creation(self):
        """Test creating a deposit via DM"""
        print("\n🏦 Testing Deposit Creation via Nostr DM...")
        
        # Get Alice's channel info first (we know from earlier)
        channel_id = "d064b35f854415908f166b7d680807f8d607c6183a8f06f7ab2a62b0522a6021"
        amount_sat = 50000
        
        # Test 1: Help command
        print("\n1️⃣  Testing /help command...")
        response = await self.send_dm("/help")
        print(f"📋 Help response: {response[:200]}...")
        
        # Test 2: Create deposit (zero balance)
        print(f"\n2️⃣  Testing /create_deposit {channel_id[:16]}... (zero balance)")
        deposit_command = f"/create_deposit {channel_id}"
        response = await self.send_dm(deposit_command)
        print(f"🏦 Deposit creation response: {response[:300]}...")
        
        # Test 3: Invalid command
        print("\n3️⃣  Testing invalid command...")
        response = await self.send_dm("hello alice!")
        print(f"👋 General response: {response[:200]}...")

async def main():
    tester = DepositDMTester()
    
    try:
        await tester.connect()
        await tester.test_deposit_creation()
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        if tester.websocket:
            await tester.websocket.close()

if __name__ == "__main__":
    asyncio.run(main())