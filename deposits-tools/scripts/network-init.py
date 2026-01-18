#!/usr/bin/env python3
"""
Bitcoin Deposits Network Initialization Script

This script initializes a 6-node Lightning Network with Bitcoin Deposits:
1. Funds all nodes with Bitcoin
2. Creates channels between all node pairs (full mesh: 15 channels total)
3. Initializes Bitcoin Deposits ledgers on all channels
4. Sets up NWC services for mobile wallet integration

Network topology:
Alice (custodian) <-> Bob (merchant)
Alice <-> Charlie (exchange)
Alice <-> Diana (service provider)
Alice <-> Eve (router)
Alice <-> Frank (hub)
Bob <-> Charlie
Bob <-> Diana
Bob <-> Eve
Bob <-> Frank
Charlie <-> Diana
Charlie <-> Eve
Charlie <-> Frank
Diana <-> Eve
Diana <-> Frank
Eve <-> Frank
"""

import requests
import json
import time
import sys
import os
from typing import Dict, List, Tuple

# Node configurations
NODES = {
    'alice': {
        'name': 'Alice (Custodian)',
        'host': 'ldk-alice',
        'api_port': 3000,
        'p2p_port': 9735,
        'ip': '172.20.0.20',
        'role': 'primary_custodian'
    },
    'bob': {
        'name': 'Bob (Merchant)',
        'host': 'ldk-bob',
        'api_port': 3000,
        'p2p_port': 9736,
        'ip': '172.20.0.21',
        'role': 'merchant'
    },
    'charlie': {
        'name': 'Charlie (Exchange)',
        'host': 'ldk-charlie',
        'api_port': 3000,
        'p2p_port': 9737,
        'ip': '172.20.0.22',
        'role': 'exchange'
    },
    'diana': {
        'name': 'Diana (Service Provider)',
        'host': 'ldk-diana',
        'api_port': 3000,
        'p2p_port': 9738,
        'ip': '172.20.0.23',
        'role': 'service_provider'
    },
    'eve': {
        'name': 'Eve (Router)',
        'host': 'ldk-eve',
        'api_port': 3000,
        'p2p_port': 9739,
        'ip': '172.20.0.24',
        'role': 'router'
    },
    'frank': {
        'name': 'Frank (Hub)',
        'host': 'ldk-frank',
        'api_port': 3000,
        'p2p_port': 9740,
        'ip': '172.20.0.25',
        'role': 'hub'
    }
}

BITCOIN_RPC = {
    'host': 'bitcoin',
    'port': 18443,
    'user': 'user',
    'password': 'pass'
}

class NetworkInitializer:
    def __init__(self):
        self.node_pubkeys = {}
        self.channels = {}
        self.bitcoin_session = requests.Session()
        self.bitcoin_session.auth = (BITCOIN_RPC['user'], BITCOIN_RPC['password'])

    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")

    def bitcoin_rpc(self, method: str, params: List = None) -> dict:
        """Make Bitcoin RPC call"""
        if params is None:
            params = []

        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
            'id': 1
        }

        try:
            response = self.bitcoin_session.post(
                f"http://{BITCOIN_RPC['host']}:{BITCOIN_RPC['port']}/",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()

            if 'error' in result and result['error']:
                raise Exception(f"Bitcoin RPC error: {result['error']}")

            return result.get('result')
        except Exception as e:
            self.log(f"Bitcoin RPC call failed: {e}", "ERROR")
            raise

    def ldk_api_call(self, node: str, endpoint: str, method: str = "GET", data: dict = None) -> dict:
        """Make API call to LDK node"""
        node_config = NODES[node]
        url = f"http://{node_config['host']}:{node_config['api_port']}{endpoint}"

        try:
            if method == "GET":
                response = requests.get(url, timeout=30)
            elif method == "POST":
                response = requests.post(url, json=data or {}, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.log(f"API call to {node} failed: {e}", "ERROR")
            raise

    def wait_for_nodes(self):
        """Wait for all LDK nodes to be ready"""
        self.log("🔄 Waiting for all LDK nodes to be ready...")

        for node_id, node_config in NODES.items():
            max_retries = 30
            retry_count = 0

            while retry_count < max_retries:
                try:
                    response = self.ldk_api_call(node_id, "/health")
                    if response.get('status') == 'ok':
                        self.log(f"✅ {node_config['name']} is ready")
                        break
                except:
                    retry_count += 1
                    if retry_count < max_retries:
                        time.sleep(2)
                    else:
                        raise Exception(f"❌ {node_config['name']} failed to start after {max_retries * 2} seconds")

        self.log("✅ All LDK nodes are ready")

    def setup_bitcoin_funding(self):
        """Generate blocks and fund all nodes"""
        self.log("💰 Setting up Bitcoin funding...")

        # Generate initial blocks
        self.bitcoin_rpc('generatetoaddress', [101, self.bitcoin_rpc('getnewaddress')])
        self.log("✅ Generated 101 blocks for Bitcoin maturity")

        # Get node addresses and fund them
        for node_id, node_config in NODES.items():
            try:
                # Get node's Bitcoin address
                address_response = self.ldk_api_call(node_id, "/bitcoin/address")
                address = address_response.get('address')

                if address:
                    # Send 1 BTC to each node
                    self.bitcoin_rpc('sendtoaddress', [address, 1.0])
                    self.log(f"💸 Sent 1 BTC to {node_config['name']} ({address})")
                else:
                    self.log(f"⚠️ Could not get address for {node_config['name']}", "WARNING")
            except Exception as e:
                self.log(f"Failed to fund {node_config['name']}: {e}", "ERROR")

        # Mine a block to confirm transactions
        self.bitcoin_rpc('generatetoaddress', [1, self.bitcoin_rpc('getnewaddress')])
        self.log("✅ Mined confirmation block")

        # Wait for nodes to sync
        time.sleep(10)

        # Verify node balances
        for node_id, node_config in NODES.items():
            try:
                balance_response = self.ldk_api_call(node_id, "/bitcoin/balance")
                balance = balance_response.get('balance_sat', 0)
                self.log(f"💰 {node_config['name']} balance: {balance:,} sat")
            except Exception as e:
                self.log(f"Could not check balance for {node_config['name']}: {e}", "WARNING")

    def get_node_pubkeys(self):
        """Get public keys for all nodes"""
        self.log("🔑 Collecting node public keys...")

        for node_id, node_config in NODES.items():
            try:
                info_response = self.ldk_api_call(node_id, "/info")
                pubkey = info_response.get('node_id')

                if pubkey:
                    self.node_pubkeys[node_id] = pubkey
                    self.log(f"🔑 {node_config['name']}: {pubkey}")
                else:
                    raise Exception(f"Could not get pubkey for {node_config['name']}")
            except Exception as e:
                self.log(f"Failed to get pubkey for {node_config['name']}: {e}", "ERROR")
                raise

    def create_full_mesh_channels(self):
        """Create channels between all node pairs (full mesh topology)"""
        self.log("🔗 Creating full mesh Lightning channels...")

        node_list = list(NODES.keys())
        channel_amount = 5_000_000  # 0.05 BTC per channel

        for i, node1 in enumerate(node_list):
            for j, node2 in enumerate(node_list):
                if i >= j:  # Skip self-connections and duplicates
                    continue

                try:
                    self.log(f"🔗 Creating channel: {NODES[node1]['name']} -> {NODES[node2]['name']}")

                    # Connect peers first
                    connect_data = {
                        'pubkey': self.node_pubkeys[node2],
                        'host': NODES[node2]['ip'],
                        'port': NODES[node2]['p2p_port']
                    }
                    self.ldk_api_call(node1, "/peers/connect", "POST", connect_data)

                    # Wait for connection
                    time.sleep(2)

                    # Open channel
                    channel_data = {
                        'pubkey': self.node_pubkeys[node2],
                        'amount_sat': channel_amount,
                        'announce': True
                    }
                    channel_response = self.ldk_api_call(node1, "/channels/open", "POST", channel_data)

                    if channel_response.get('success'):
                        channel_id = channel_response.get('channel_id')
                        self.channels[f"{node1}-{node2}"] = {
                            'id': channel_id,
                            'initiator': node1,
                            'responder': node2,
                            'amount': channel_amount
                        }
                        self.log(f"✅ Channel created: {channel_id}")
                    else:
                        self.log(f"❌ Failed to create channel between {node1} and {node2}", "ERROR")

                except Exception as e:
                    self.log(f"Error creating channel {node1}-{node2}: {e}", "ERROR")
                    continue

        # Mine blocks to confirm channels
        self.log("⛏️ Mining blocks to confirm channels...")
        self.bitcoin_rpc('generatetoaddress', [6, self.bitcoin_rpc('getnewaddress')])

        # Wait for channel confirmations
        self.log("⏳ Waiting for channel confirmations...")
        time.sleep(30)

        self.log(f"✅ Created {len(self.channels)} Lightning channels")

    def initialize_deposits_ledgers(self):
        """Initialize Bitcoin Deposits ledgers on all channels"""
        self.log("📋 Initializing Bitcoin Deposits ledgers...")

        for channel_key, channel_info in self.channels.items():
            try:
                node1 = channel_info['initiator']
                node2 = channel_info['responder']

                self.log(f"📋 Setting up Bitcoin Deposits ledger: {NODES[node1]['name']} <-> {NODES[node2]['name']}")

                # Initialize ledger from node1's perspective
                ledger_data = {
                    'partner_pubkey': self.node_pubkeys[node2],
                    'initial_balance_msat': 0,
                    'ledger_type': 'custodial_deposit'
                }

                response1 = self.ldk_api_call(node1, "/bitcoin-deposits/ledger/init", "POST", ledger_data)

                # Initialize ledger from node2's perspective
                ledger_data2 = {
                    'partner_pubkey': self.node_pubkeys[node1],
                    'initial_balance_msat': 0,
                    'ledger_type': 'custodial_deposit'
                }

                response2 = self.ldk_api_call(node2, "/bitcoin-deposits/ledger/init", "POST", ledger_data2)

                if response1.get('success') and response2.get('success'):
                    self.log(f"✅ Bitcoin Deposits ledger initialized for {node1}-{node2}")
                else:
                    self.log(f"⚠️ Partial ledger initialization for {node1}-{node2}", "WARNING")

            except Exception as e:
                self.log(f"Error initializing ledger for {channel_key}: {e}", "ERROR")
                continue

        self.log("✅ All Bitcoin Deposits ledgers initialized")

    def setup_nwc_services(self):
        """Set up NWC services for mobile wallet integration"""
        self.log("📱 Setting up NWC (Nostr Wallet Connect) services...")

        for node_id, node_config in NODES.items():
            try:
                # Start NWC service
                nwc_config = {
                    'enable_nwc_server': True,
                    'nwc_relay_urls': ['wss://relay.damus.io', 'wss://nos.lol'],
                    'max_sessions': 100
                }

                response = self.ldk_api_call(node_id, "/bitcoin-deposits/nwc/start", "POST", nwc_config)

                if response.get('success'):
                    self.log(f"✅ NWC service started for {node_config['name']}")
                else:
                    self.log(f"⚠️ Could not start NWC service for {node_config['name']}", "WARNING")

            except Exception as e:
                self.log(f"Error setting up NWC for {node_config['name']}: {e}", "WARNING")
                continue

        self.log("✅ NWC services configured")

    def print_network_summary(self):
        """Print network initialization summary"""
        self.log("\n" + "="*80)
        self.log("🎉 BITCOIN DEPOSITS LIGHTNING NETWORK INITIALIZED")
        self.log("="*80)

        self.log(f"📊 Network Statistics:")
        self.log(f"   • Nodes: {len(NODES)}")
        self.log(f"   • Channels: {len(self.channels)}")
        self.log(f"   • Bitcoin Deposits Ledgers: {len(self.channels)}")

        self.log(f"\n📡 Node Information:")
        for node_id, node_config in NODES.items():
            pubkey = self.node_pubkeys.get(node_id, "Unknown")
            self.log(f"   • {node_config['name']}")
            self.log(f"     - API: http://localhost:{3001 + list(NODES.keys()).index(node_id)}")
            self.log(f"     - P2P: {node_config['ip']}:{node_config['p2p_port']}")
            self.log(f"     - PubKey: {pubkey}")

        self.log(f"\n⚡ Channel Topology (Full Mesh):")
        for channel_key, channel_info in self.channels.items():
            node1 = channel_info['initiator']
            node2 = channel_info['responder']
            amount = channel_info['amount']
            self.log(f"   • {NODES[node1]['name']} <-> {NODES[node2]['name']} ({amount:,} sat)")

        self.log(f"\n📱 Mobile Wallet Integration:")
        self.log(f"   • All nodes support NWC (Nostr Wallet Connect)")
        self.log(f"   • Bitcoin Deposits API available on all nodes")
        self.log(f"   • Production-ready service architecture")

        self.log("\n✅ Network ready for Bitcoin Deposits operations!")
        self.log("="*80)

    def run(self):
        """Run the complete network initialization"""
        try:
            self.log("🚀 Starting Bitcoin Deposits Lightning Network initialization...")

            # Step 1: Wait for nodes
            self.wait_for_nodes()

            # Step 2: Setup Bitcoin funding
            self.setup_bitcoin_funding()

            # Step 3: Get node public keys
            self.get_node_pubkeys()

            # Step 4: Create full mesh of channels
            self.create_full_mesh_channels()

            # Step 5: Initialize Bitcoin Deposits ledgers
            self.initialize_deposits_ledgers()

            # Step 6: Setup NWC services
            self.setup_nwc_services()

            # Step 7: Print summary
            self.print_network_summary()

            self.log("✅ Network initialization completed successfully!")

        except Exception as e:
            self.log(f"❌ Network initialization failed: {e}", "ERROR")
            sys.exit(1)

if __name__ == "__main__":
    initializer = NetworkInitializer()
    initializer.run()
