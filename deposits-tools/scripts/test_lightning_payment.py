#!/usr/bin/env python3
"""
Test Lightning invoice creation and payment between nodes
"""
import requests
import json
import time

# Node configurations
ALICE_PORT = 3011
BOB_PORT = 3012

def test_node_info(node_name, port):
    """Test node info endpoint"""
    try:
        response = requests.get(f"http://localhost:{port}/info")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ {node_name} Info: Node ID: {data['data']['node_id'][:16]}...")
            return True
        else:
            print(f"❌ {node_name} Info failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ {node_name} connection failed: {e}")
        return False

def create_invoice(node_name, port, amount_msat, description):
    """Create a Lightning invoice"""
    try:
        payload = {
            "amount_msat": amount_msat,
            "description": description
        }
        response = requests.post(f"http://localhost:{port}/invoice", json=payload)
        if response.status_code == 200:
            data = response.json()
            invoice = data['data']['bolt11_invoice']
            payment_hash = data['data']['payment_hash']
            print(f"✅ {node_name} created invoice for {amount_msat//1000} sat")
            print(f"   Payment hash: {payment_hash}")
            print(f"   Invoice: {invoice[:50]}...")
            return invoice
        else:
            print(f"❌ {node_name} invoice creation failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ {node_name} invoice creation error: {e}")
        return None

def pay_invoice(node_name, port, invoice):
    """Pay a Lightning invoice"""
    try:
        payload = {"invoice": invoice}
        response = requests.post(f"http://localhost:{port}/pay", json=payload)
        if response.status_code == 200:
            data = response.json()
            payment_hash = data['data']['payment_hash']
            print(f"✅ {node_name} paid invoice successfully")
            print(f"   Payment hash: {payment_hash}")
            return True
        else:
            print(f"❌ {node_name} payment failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ {node_name} payment error: {e}")
        return False

def main():
    print("🚀 Testing Lightning Invoice Creation and Payment")
    print("=" * 60)
    
    # Test 1: Check if both nodes are running
    print("\n📡 Step 1: Testing node connectivity")
    alice_ok = test_node_info("Alice", ALICE_PORT)
    bob_ok = test_node_info("Bob", BOB_PORT)
    
    if not (alice_ok and bob_ok):
        print("\n❌ Cannot proceed - nodes not accessible")
        print("💡 Make sure Docker containers are running:")
        print("   docker-compose -f docker-compose-deposits.yml up -d")
        return
    
    # Test 2: Alice creates an invoice
    print("\n🧾 Step 2: Alice creates an invoice")
    invoice = create_invoice("Alice", ALICE_PORT, 100000, "Test Lightning payment from Bob to Alice")
    
    if not invoice:
        print("\n❌ Cannot proceed - invoice creation failed")
        return
    
    # Test 3: Bob pays the invoice
    print("\n💸 Step 3: Bob pays Alice's invoice")
    payment_success = pay_invoice("Bob", BOB_PORT, invoice)
    
    if payment_success:
        print("\n🎉 Lightning payment test completed successfully!")
        print("✅ Alice created invoice ✅ Bob paid invoice")
    else:
        print("\n❌ Lightning payment test failed")
        print("💡 This could be due to:")
        print("   - Nodes not connected as peers")
        print("   - No Lightning channel between Alice and Bob")
        print("   - Insufficient channel capacity")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()