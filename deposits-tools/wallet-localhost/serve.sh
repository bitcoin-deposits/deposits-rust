#!/bin/bash
# Serve the wallet on localhost:8888
# Required because ES modules don't work over file:// (CORS)
cd "$(dirname "$0")"
echo "Wallet: http://localhost:8888"
python3 -m http.server 8888
