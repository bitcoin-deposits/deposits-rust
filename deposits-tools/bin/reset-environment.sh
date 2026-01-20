#!/bin/bash

# Quick Reset Script for Docker Environment
# Use this when you need to quickly restart without rebuilding images

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

echo "🔄 Quick environment reset..."

# Stop and clean volumes but keep images
docker-compose -f docker-compose-deposits.yml down --volumes

# Start everything back up
docker-compose -f docker-compose-deposits.yml up -d

echo "⏳ Waiting for services to be ready..."
sleep 20

# Quick health check using authenticated HTTPS
echo "🔍 Quick health check:"
if ldk_curl 3011 GET /node/info > /dev/null 2>&1; then
    echo "✅ Alice is ready"
else
    echo "⚠️  Alice not ready yet (may need more time)"
fi

if ldk_curl 3012 GET /node/info > /dev/null 2>&1; then
    echo "✅ Bob is ready"
else
    echo "⚠️  Bob not ready yet (may need more time)"
fi

echo "🎉 Quick reset complete! Use setup-environment.sh for full rebuild."