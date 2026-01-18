#!/bin/bash

# Script to run Alice standalone but connected to Docker infrastructure

set -e

echo "🔧 Setting up Alice connected debug environment..."

# Ensure Docker infrastructure is running (including Alice to copy data)
echo "🚀 Starting Docker infrastructure..."
docker-compose -f docker-compose-deposits.yml up -d bitcoin nostr-relay electrs ldk-alice

# Wait for Alice to initialize
echo "⏳ Waiting for Alice to initialize..."
sleep 10

# Create data directory and copy Docker data
ALICE_DATA_DIR="/tmp/ldk-alice-connected"
echo "📂 Setting up data directory: $ALICE_DATA_DIR"

rm -rf "$ALICE_DATA_DIR" 2>/dev/null || true
mkdir -p "$ALICE_DATA_DIR"

# Copy data from Docker container if available
echo "📋 Copying Docker data from container..."
if docker exec ldk-alice test -d /ldk 2>/dev/null; then
    docker cp ldk-alice:/ldk/. "$ALICE_DATA_DIR/"
    echo "✅ Copied Docker data from container"
else
    echo "⚠️  Docker container not running or no data found, starting fresh"
fi

# Now stop Docker Alice to avoid port conflicts
echo "🛑 Stopping Docker Alice..."
docker-compose -f docker-compose-deposits.yml stop ldk-alice

# Environment variables for connected Alice
export NODE_NAME="alice"
export LDK_DATA_DIR="$ALICE_DATA_DIR"
export LISTEN_PORT="9735"
export API_PORT="3011"
export ENABLE_DEPOSITS="true"
export NOSTR_RELAY_URL="ws://localhost:7777"
export RUST_LOG="debug,ldk_node=trace"

# Set Bitcoin and Electrum to use Docker services
export BITCOIN_RPC_HOST="127.0.0.1"
export BITCOIN_RPC_PORT="18443"
export BITCOIN_RPC_USER="user"
export BITCOIN_RPC_PASSWORD="password"
export ELECTRUM_SERVER_URL="127.0.0.1:50001"

echo "🚀 Starting connected Alice LDK server..."
echo "   Data directory: $ALICE_DATA_DIR (copied from Docker)"
echo "   Listen port: $LISTEN_PORT"
echo "   API will be on: http://localhost:3011"
echo "   Log level: $RUST_LOG"
echo "   Connected to Docker: Bitcoin, Electrum, Nostr"
echo ""
echo "📋 To debug protocol flow:"
echo "   1. Set breakpoints in deposits code"
echo "   2. Run: ./run-alice-connected.sh"
echo "   3. In another terminal: ./test-alice-connected.sh"
echo ""
echo "🔧 Environment variables set:"
echo "   NODE_NAME=$NODE_NAME"
echo "   LDK_DATA_DIR=$LDK_DATA_DIR"
echo "   LISTEN_PORT=$LISTEN_PORT"
echo "   API_PORT=$API_PORT"
echo "   ENABLE_DEPOSITS=$ENABLE_DEPOSITS"
echo "   NOSTR_RELAY_URL=$NOSTR_RELAY_URL"
echo "   RUST_LOG=$RUST_LOG"
echo ""

# Build and run
cargo build --bin ldk-server --features bitcoin-deposits,testing

echo "🎯 Ready to debug! Starting connected Alice..."
cargo run --bin ldk-server --features bitcoin-deposits,testing