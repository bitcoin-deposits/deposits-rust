#!/bin/bash

# Turnkey Docker Environment Setup Script
# This script provides a reliable way to recreate the entire Bitcoin Deposits environment

cd "$(dirname "$0")/.."
set -e  # Exit on any error
. ./bin/_common.sh

echo "🚀 Starting turnkey Docker environment setup..."
echo "============================================================"

# Configuration
COMPOSE_FILE="docker-compose-deposits.yml"
mkdir -p log
LOG_FILE="log/setup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}✅ $1${NC}" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}❌ $1${NC}" | tee -a "$LOG_FILE"
}

# Function to wait for service health
wait_for_service() {
    local service=$1
    local max_attempts=${2:-30}
    local attempt=1
    
    log "Waiting for $service to be healthy..."
    while [ $attempt -le $max_attempts ]; do
        if docker-compose -f "$COMPOSE_FILE" ps "$service" | grep -q "healthy\|Up"; then
            success "$service is ready"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    error "$service failed to start within $((max_attempts * 2)) seconds"
    return 1
}

# Function to check API endpoint using authenticated HTTPS
check_api() {
    local name=$1
    local port=$2
    local endpoint=${3:-"/node/info"}

    log "Checking $name API at port $port..."
    if ldk_curl "$port" GET "$endpoint" > /dev/null 2>&1; then
        success "$name API is responding"
        return 0
    else
        error "$name API is not responding at port $port"
        return 1
    fi
}

# Step 1: Clean up existing environment
log "Step 1: Cleaning up existing environment..."
docker-compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
docker system prune -f > /dev/null 2>&1 || true
success "Environment cleaned up"

# Step 2: Build images from scratch
log "Step 2: Building fresh Docker images..."
docker-compose -f "$COMPOSE_FILE" build --no-cache --pull ldk-alice ldk-bob ldk-charlie ldk-diana ldk-eve ldk-frank
success "Docker images built successfully"

# Step 3: Start infrastructure services first
log "Step 3: Starting infrastructure services..."
docker-compose -f "$COMPOSE_FILE" up -d bitcoin electrs nostr-relay

# Wait for Bitcoin Core
if wait_for_service "bitcoin" 60; then
    success "Bitcoin Core is ready"
else
    error "Bitcoin Core failed to start"
    exit 1
fi

# Wait for Electrs
if wait_for_service "electrs" 30; then
    success "Electrs is ready"
else
    error "Electrs failed to start"
    exit 1
fi

# Step 4: Start LDK nodes
log "Step 4: Starting LDK nodes..."
docker-compose -f "$COMPOSE_FILE" up -d ldk-alice ldk-bob ldk-charlie ldk-diana ldk-eve ldk-frank

# Give nodes time to start
log "Waiting for LDK nodes to initialize..."
sleep 15

# Step 5: Check node APIs
log "Step 5: Verifying node APIs..."
nodes=("alice:3011" "bob:3012" "charlie:3013" "diana:3014" "eve:3015" "frank:3016")
all_nodes_ready=true

for node_info in "${nodes[@]}"; do
    IFS=':' read -r name port <<< "$node_info"
    if ! check_api "$name" "$port"; then
        all_nodes_ready=false
    fi
done

if [ "$all_nodes_ready" = true ]; then
    success "All node APIs are responding"
else
    warning "Some node APIs are not ready yet, but continuing..."
fi

# Step 6: Test Lightning endpoints
log "Step 6: Testing Lightning invoice creation..."
alice_response=$(ldk_curl 3011 POST /bolt11/receive '{"amount_msat": 50000, "description": "Test setup invoice"}' 2>/dev/null || echo "")

if echo "$alice_response" | grep -q "invoice"; then
    success "Lightning invoice creation working"
    invoice=$(echo "$alice_response" | jq -r '.invoice // empty')
    log "Created test invoice: ${invoice:0:50}..."
else
    warning "Lightning invoice creation may need time to initialize"
fi

# Step 7: Summary and instructions
echo ""
echo "============================================================"
success "🎉 Environment setup complete!"
echo ""
log "📋 Environment Status:"
echo "  • Bitcoin Core: http://localhost:18443 (RPC: user/pass)"
echo "  • Electrs: http://localhost:3002"
echo "  • Nostr Relay: ws://localhost:7777"
echo ""
log "⚡ Lightning Nodes (HTTPS with HMAC auth required):"
echo "  • Alice: https://localhost:3011 (Lightning: 9735)"
echo "  • Bob: https://localhost:3012 (Lightning: 9736)"
echo "  • Charlie: https://localhost:3013 (Lightning: 9737)"
echo "  • Diana: https://localhost:3014 (Lightning: 9738)"
echo "  • Eve: https://localhost:3015 (Lightning: 9739)"
echo "  • Frank: https://localhost:3016 (Lightning: 9740)"
echo ""
log "🧪 Quick Tests (use ldk_curl from _common.sh):"
echo "  • Source helpers: . ./bin/_common.sh"
echo "  • Node info: ldk_curl 3011 GET /node/info"
echo "  • Balance: ldk_curl 3011 GET /onchain/balance"
echo "  • Create invoice: ldk_curl 3011 POST /bolt11/receive '{\"amount_msat\": 100000, \"description\": \"test\"}'"
echo "  • NWC client: cargo run --bin nwc-client alice"
echo "  • Status tool: cargo run --bin status node alice"
echo ""
log "📁 Logs saved to: $LOG_FILE"
echo ""
success "Environment is ready for Bitcoin Deposits testing!"
echo "============================================================"