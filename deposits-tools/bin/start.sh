#!/bin/bash

# Simple turnkey start script
# Build images once, then just use docker-compose up -d

cd "$(dirname "$0")/.."
. ./bin/_common.sh

echo "🚀 Starting Bitcoin Deposits Environment..."

# Check if images exist, build if needed
if ! docker images | grep -q ldk-node-ldk-alice; then
    echo "📦 Building Docker images (one-time setup)..."
    docker-compose -f docker-compose-deposits.yml build
    echo "✅ Images built successfully"
fi

# Start the environment
echo "🔄 Starting all services..."
docker-compose -f docker-compose-deposits.yml up -d

echo "⏳ Waiting for services to initialize..."
sleep 15

echo "🔍 Network status check:"
cargo_quiet run --bin status network

echo ""
echo "🎉 Environment is ready!"
echo "📝 Test commands (HTTPS with HMAC auth required):"
echo "   . ./bin/_common.sh && ldk_curl 3011 GET /node/info"
echo "   cargo run --bin nwc-client alice"
echo "   cargo run --bin status network"
echo ""
echo "📋 To rebuild: docker-compose -f docker-compose-deposits.yml build"
echo "🔄 To restart: docker-compose -f docker-compose-deposits.yml restart"
echo "🛑 To stop: docker-compose -f docker-compose-deposits.yml down"