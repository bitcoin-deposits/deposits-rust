#!/bin/bash
# Entrypoint for ldk-server container
# Generates TOML config from environment variables and starts ldk-server.

set -e

DATA_DIR="${LDK_DATA_DIR:-/ldk}"
LISTEN_ADDR="${TLS_HOSTNAME:-0.0.0.0}:${LISTEN_PORT:-9735}"
REST_ADDR="0.0.0.0:${API_PORT:-3000}"
NETWORK="${NETWORK:-regtest}"
API_KEY="${LDK_API_KEY:-test_api_key}"
ALIAS="${NODE_NAME:-ldk-node}"

mkdir -p "$DATA_DIR"

# Copy CLI binary to shared volume (if mounted at /ldk-cli)
if [ -d "/ldk-cli" ]; then
    cp /usr/local/bin/ldk-server-cli /ldk-cli/ldk-server-cli 2>/dev/null || true
fi

# Generate TOML config
cat > "$DATA_DIR/config.toml" <<EOF
[node]
network = "${NETWORK}"
listening_address = "${LISTEN_ADDR}"
rest_service_address = "${REST_ADDR}"
alias = "${ALIAS}"
api_key = "${API_KEY}"

[storage.disk]
dir_path = "${DATA_DIR}"

[esplora]
server_url = "http://${ELECTRUM_HOST:-electrs}:${ELECTRUM_PORT:-3002}"

[tls]
hosts = ["${TLS_HOSTNAME:-localhost}", "0.0.0.0", "127.0.0.1"]

[log]
level = "${LOG_LEVEL:-info}"
EOF

echo "Starting ldk-server with config:"
cat "$DATA_DIR/config.toml"
echo ""

exec ldk-server "$DATA_DIR/config.toml"
