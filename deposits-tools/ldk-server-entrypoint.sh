#!/bin/bash
# Entrypoint script for ldk-server
# Generates TOML config from environment variables and runs ldk-server

set -e

CONFIG_FILE="/ldk/config.toml"

# Get listen port, default to 9735
LISTEN_PORT="${LISTEN_PORT:-9735}"

# Generate TOML config from environment variables
cat > "$CONFIG_FILE" << EOF
[node]
network = "regtest"
listening_address = "0.0.0.0:${LISTEN_PORT}"
rest_service_address = "0.0.0.0:3000"
alias = "${NODE_NAME:-ldk-node}"
api_key = "test_api_key"

[storage.disk]
dir_path = "${LDK_DATA_DIR:-/ldk}"

[esplora]
server_url = "http://${ELECTRUM_HOST:-electrs}:${ELECTRUM_PORT:-3002}"

[log]
level = "Debug"
EOF

echo "Generated config at $CONFIG_FILE:"
cat "$CONFIG_FILE"
echo ""
echo "Starting ldk-server..."

exec ldk-server "$CONFIG_FILE"
