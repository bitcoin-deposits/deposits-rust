#!/bin/bash

# Quick Reset Script for Docker Environment
# Use this when you need to quickly restart without rebuilding images

set -e

echo "🔄 Quick environment reset..."

# Stop and clean volumes but keep images
docker-compose -f docker-compose-deposits.yml down --volumes

# Start everything back up
docker-compose -f docker-compose-deposits.yml up -d

echo "⏳ Waiting for services to be ready..."
sleep 20

# Quick health check
echo "🔍 Quick health check:"
if curl -s http://localhost:3011/info > /dev/null 2>&1; then
    echo "✅ Alice is ready"
else
    echo "⚠️  Alice not ready yet (may need more time)"
fi

if curl -s http://localhost:3012/info > /dev/null 2>&1; then
    echo "✅ Bob is ready" 
else
    echo "⚠️  Bob not ready yet (may need more time)"
fi

echo "🎉 Quick reset complete! Use setup-environment.sh for full rebuild."