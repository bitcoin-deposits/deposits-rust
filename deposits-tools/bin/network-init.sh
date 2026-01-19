#!/bin/bash

# Bitcoin Deposits Network Initialization Script
#
# This script initializes a 6-node Lightning Network with Bitcoin Deposits:
# 1. Funds all nodes with Bitcoin
# 2. Creates channels between all node pairs (full mesh: 15 channels total)
# 3. Initializes Bitcoin Deposits ledgers on all channels
# 4. Sets up NWC services for mobile wallet integration

cd "$(dirname "$0")/.."
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Node configurations
NODES="alice:3001 bob:3003 charlie:3004 diana:3005 eve:3006 frank:3007"
NODE_NAMES="alice:Alice(Custodian) bob:Bob(Merchant) charlie:Charlie(Exchange) diana:Diana(ServiceProvider) eve:Eve(Router) frank:Frank(Hub)"

# Helper functions
get_node_port() {
    local node="$1"
    echo "$NODES" | tr ' ' '\n' | grep "^$node:" | cut -d: -f2
}

get_node_name() {
    local node="$1"
    echo "$NODE_NAMES" | tr ' ' '\n' | grep "^$node:" | cut -d: -f2 | tr '()' ' ()'
}

get_all_nodes() {
    echo "$NODES" | tr ' ' '\n' | cut -d: -f1
}

# Bitcoin RPC configuration
BITCOIN_RPC_HOST="localhost"
BITCOIN_RPC_PORT="18443"
BITCOIN_RPC_USER="user"
BITCOIN_RPC_PASSWORD="pass"

# Global variables (using temp files for associative data)
NODE_PUBKEYS_FILE="/tmp/node_pubkeys.txt"
CHANNELS_FILE="/tmp/channels.txt"

# Initialize temp files
> "$NODE_PUBKEYS_FILE"
> "$CHANNELS_FILE"

# Helper functions for associative data
set_node_pubkey() {
    local node="$1"
    local pubkey="$2"
    echo "$node:$pubkey" >> "$NODE_PUBKEYS_FILE"
}

get_node_pubkey() {
    local node="$1"
    grep "^$node:" "$NODE_PUBKEYS_FILE" | cut -d: -f2 | head -1
}

set_channel() {
    local key="$1"
    local value="$2"
    echo "$key:$value" >> "$CHANNELS_FILE"
}

get_all_channels() {
    cat "$CHANNELS_FILE" 2>/dev/null || true
}

# Bitcoin RPC call function
bitcoin_rpc() {
    local method="$1"
    shift
    local params=""
    if [ $# -gt 0 ]; then
        params="$(printf '"%s",' "$@")"
        params="[${params%,}]"
    else
        params="[]"
    fi

    curl -s -u "$BITCOIN_RPC_USER:$BITCOIN_RPC_PASSWORD" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "http://$BITCOIN_RPC_HOST:$BITCOIN_RPC_PORT/" | jq -r '.result'
}

# LDK API call function
ldk_api_call() {
    local node="$1"
    local endpoint="$2"
    local method="${3:-GET}"
    local data="${4:-}"

    local port=$(get_node_port "$node")
    local url="http://localhost:$port$endpoint"

    if [ "$method" = "GET" ]; then
        curl -s "$url"
    else
        curl -s -X "$method" -H "Content-Type: application/json" -d "$data" "$url"
    fi
}

# Wait for all nodes to be ready
wait_for_nodes() {
    log "🔄 Waiting for all LDK nodes to be ready..."

    for node in $(get_all_nodes); do
        local port=$(get_node_port "$node")
        local name=$(get_node_name "$node")
        local max_retries=30
        local retry_count=0

        while [ $retry_count -lt $max_retries ]; do
            if curl -s -f "http://localhost:$port/health" > /dev/null 2>&1; then
                log "✅ $name is ready"
                break
            fi

            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                sleep 2
            else
                error "❌ $name failed to start after $((max_retries * 2)) seconds"
                exit 1
            fi
        done
    done

    log "✅ All LDK nodes are ready"
}

# Setup Bitcoin funding
setup_bitcoin_funding() {
    log "💰 Setting up Bitcoin funding..."

    # Generate initial blocks
    local new_address=$(bitcoin_rpc "getnewaddress")
    bitcoin_rpc "generatetoaddress" "101" "$new_address" > /dev/null
    log "✅ Generated 101 blocks for Bitcoin maturity"

    # Get node addresses and fund them
    for node in $(get_all_nodes); do
        local name=$(get_node_name "$node")
        local response=$(ldk_api_call "$node" "/bitcoin/address")
        local address=$(echo "$response" | jq -r '.data.address // empty')

        if [ -n "$address" ]; then
            bitcoin_rpc "sendtoaddress" "$address" "1.0" > /dev/null
            log "💸 Sent 1 BTC to $name ($address)"
        else
            warn "⚠️ Could not get address for $name"
        fi
    done

    # Mine a block to confirm transactions
    bitcoin_rpc "generatetoaddress" "1" "$new_address" > /dev/null
    log "✅ Mined confirmation block"

    # Wait for nodes to sync
    sleep 10

    # Verify node balances
    for node in $(get_all_nodes); do
        local name=$(get_node_name "$node")
        local response=$(ldk_api_call "$node" "/bitcoin/balance")
        local balance=$(echo "$response" | jq -r '.data.balance_sat // 0')
        log "💰 $name balance: $(printf "%'d" $balance) sat"
    done
}

# Get node public keys
get_node_pubkeys() {
    log "🔑 Collecting node public keys..."

    for node in $(get_all_nodes); do
        local name=$(get_node_name "$node")
        local response=$(ldk_api_call "$node" "/info")
        local pubkey=$(echo "$response" | jq -r '.data.node_id // empty')

        if [ -n "$pubkey" ]; then
            set_node_pubkey "$node" "$pubkey"
            log "🔑 $name: $pubkey"
        else
            error "Could not get pubkey for $name"
            exit 1
        fi
    done
}

# Create full mesh channels
create_full_mesh_channels() {
    log "🔗 Creating full mesh Lightning channels..."

    local nodes=($(get_all_nodes | sort))
    local channel_amount=5000000  # 0.05 BTC per channel
    local channel_count=0

    for ((i=0; i<${#nodes[@]}; i++)); do
        for ((j=i+1; j<${#nodes[@]}; j++)); do
            local node1="${nodes[i]}"
            local node2="${nodes[j]}"
            local name1=$(get_node_name "$node1")
            local name2=$(get_node_name "$node2")
            local pubkey2=$(get_node_pubkey "$node2")

            log "🔗 Creating channel: $name1 -> $name2"

            # Connect peers first
            local connect_data="{\"pubkey\":\"$pubkey2\",\"host\":\"172.20.0.$((22+j))\",\"port\":$((9735+j))}"
            ldk_api_call "$node1" "/peers/connect" "POST" "$connect_data" > /dev/null 2>&1 || true

            # Wait for connection
            sleep 2

            # Open channel
            local channel_data="{\"pubkey\":\"$pubkey2\",\"amount_sat\":$channel_amount,\"announce\":true}"
            local response=$(ldk_api_call "$node1" "/channels/open" "POST" "$channel_data")
            local success=$(echo "$response" | jq -r '.success // false')

            if [ "$success" = "true" ]; then
                local channel_id=$(echo "$response" | jq -r '.data.channel_id // ""')
                set_channel "$node1-$node2" "$channel_id"
                channel_count=$((channel_count + 1))
                log "✅ Channel created: $channel_id"
            else
                error "❌ Failed to create channel between $node1 and $node2"
            fi
        done
    done

    # Mine blocks to confirm channels
    log "⛏️ Mining blocks to confirm channels..."
    local new_address=$(bitcoin_rpc "getnewaddress")
    bitcoin_rpc "generatetoaddress" "6" "$new_address" > /dev/null

    # Wait for channel confirmations
    log "⏳ Waiting for channel confirmations..."
    sleep 30

    log "✅ Created $channel_count Lightning channels"
}

# Initialize Bitcoin Deposits ledgers
initialize_deposits_ledgers() {
    log "📋 Initializing Bitcoin Deposits ledgers..."

    local ledger_count=0
    for channel_key in "${!CHANNELS[@]}"; do
        IFS='-' read -r node1 node2 <<< "$channel_key"
        local name1="${NODE_NAMES[$node1]}"
        local name2="${NODE_NAMES[$node2]}"

        log "📋 Setting up Bitcoin Deposits ledger: $name1 <-> $name2"

        # Initialize ledger from node1's perspective
        local ledger_data1="{\"partner_pubkey\":\"${NODE_PUBKEYS[$node2]}\",\"initial_balance_msat\":0,\"ledger_type\":\"custodial_deposit\"}"
        local response1=$(ldk_api_call "$node1" "/bitcoin-deposits/ledger/init" "POST" "$ledger_data1")
        local success1=$(echo "$response1" | jq -r '.success // false')

        # Initialize ledger from node2's perspective
        local ledger_data2="{\"partner_pubkey\":\"${NODE_PUBKEYS[$node1]}\",\"initial_balance_msat\":0,\"ledger_type\":\"custodial_deposit\"}"
        local response2=$(ldk_api_call "$node2" "/bitcoin-deposits/ledger/init" "POST" "$ledger_data2")
        local success2=$(echo "$response2" | jq -r '.success // false')

        if [ "$success1" = "true" ] && [ "$success2" = "true" ]; then
            ledger_count=$((ledger_count + 1))
            log "✅ Bitcoin Deposits ledger initialized for $node1-$node2"
        else
            warn "⚠️ Partial ledger initialization for $node1-$node2"
        fi
    done

    log "✅ Initialized $ledger_count Bitcoin Deposits ledgers"
}

# Setup NWC services
setup_nwc_services() {
    log "📱 Setting up NWC (Nostr Wallet Connect) services..."

    for node in "${!NODES[@]}"; do
        local name="${NODE_NAMES[$node]}"
        local nwc_config='{"enable_nwc_server":true,"nwc_relay_urls":["wss://relay.damus.io","wss://nos.lol"],"max_sessions":100}'
        local response=$(ldk_api_call "$node" "/bitcoin-deposits/nwc/start" "POST" "$nwc_config")
        local success=$(echo "$response" | jq -r '.success // false')

        if [ "$success" = "true" ]; then
            log "✅ NWC service started for $name"
        else
            warn "⚠️ Could not start NWC service for $name"
        fi
    done

    log "✅ NWC services configured"
}

# Print network summary
print_network_summary() {
    echo ""
    echo "================================================================================"
    log "🎉 BITCOIN DEPOSITS LIGHTNING NETWORK INITIALIZED"
    echo "================================================================================"

    log "📊 Network Statistics:"
    log "   • Nodes: ${#NODES[@]}"
    log "   • Channels: ${#CHANNELS[@]}"
    log "   • Bitcoin Deposits Ledgers: ${#CHANNELS[@]}"

    echo ""
    log "📡 Node Information:"
    for node in "${!NODES[@]}"; do
        local name="${NODE_NAMES[$node]}"
        local port="${NODES[$node]}"
        local pubkey="${NODE_PUBKEYS[$node]}"
        log "   • $name"
        log "     - API: http://localhost:$port"
        log "     - PubKey: $pubkey"
    done

    echo ""
    log "⚡ Channel Topology (Full Mesh):"
    for channel_key in "${!CHANNELS[@]}"; do
        IFS='-' read -r node1 node2 <<< "$channel_key"
        local name1="${NODE_NAMES[$node1]}"
        local name2="${NODE_NAMES[$node2]}"
        log "   • $name1 <-> $name2 (5,000,000 sat)"
    done

    echo ""
    log "📱 Mobile Wallet Integration:"
    log "   • All nodes support NWC (Nostr Wallet Connect)"
    log "   • Bitcoin Deposits API available on all nodes"
    log "   • Production-ready service architecture"

    echo ""
    log "✅ Network ready for Bitcoin Deposits operations!"
    echo "================================================================================"
}

# Main execution
main() {
    log "🚀 Starting Bitcoin Deposits Lightning Network initialization..."

    # Check dependencies
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed"
        exit 1
    fi

    # Step 1: Wait for nodes
    wait_for_nodes

    # Step 2: Setup Bitcoin funding
    setup_bitcoin_funding

    # Step 3: Get node public keys
    get_node_pubkeys

    # Step 4: Create full mesh of channels
    create_full_mesh_channels

    # Step 5: Initialize Bitcoin Deposits ledgers
    initialize_deposits_ledgers

    # Step 6: Setup NWC services
    setup_nwc_services

    # Step 7: Print summary
    print_network_summary

    log "✅ Network initialization completed successfully!"
}

# Run main function
main "$@"
