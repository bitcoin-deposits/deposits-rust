#!/bin/bash
#
# Full reinitialization of the test environment
# Tears down containers, rebuilds, and recreates everything
#
# Usage: ./reinit.sh <network>

cd "$(dirname "$0")"
set -e

SCRIPT_DIR="$(pwd)"
PROJECT_DIR="$(cd ".." && pwd)"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network>"
    echo "  network: regtest or mutinynet"
    exit 1
fi

NETWORK=$1

# Select docker-compose file based on network
if [ "$NETWORK" = "regtest" ]; then
    COMPOSE_FILE="$PROJECT_DIR/docker-compose-deposits.yml"
elif [ "$NETWORK" = "mutinynet" ]; then
    COMPOSE_FILE="$PROJECT_DIR/docker-compose-mutinynet.yml"
else
    echo "ERROR: Unknown network '$NETWORK'. Valid networks: regtest, mutinynet"
    exit 1
fi

rm -f "$PROJECT_DIR/wallet"/*.json

touch "$PROJECT_DIR/RE-INIT.at"

if [ "$NETWORK" = "regtest" ]; then
    # Regtest: wipe volumes since we can mine new funds
    docker compose -f "$COMPOSE_FILE" down -v
else
    # Mutinynet: preserve volumes to keep funds (can't mine, need faucet)
    docker compose -f "$COMPOSE_FILE" down
fi

docker compose -f "$COMPOSE_FILE" up --build -d
cd "$PROJECT_DIR" && cargo run --features bitcoin-deposits --bin network-init -- --network "$NETWORK" 2> /dev/null

# Wait for peer connections to stabilize after network init
# LDK peers may disconnect/reconnect during channel reestablishment
echo "⏳ Waiting for peer connections to stabilize (60 seconds)..."
sleep 60

"$SCRIPT_DIR/drop-ledgers.sh" "$NETWORK"

# Create wallets for alice and bob
echo "🔑 Creating wallet for alice..."
"$SCRIPT_DIR/make-a-wallet.sh" "$NETWORK" alice charlie bob amber

echo "🔑 Creating wallet for bob..."
"$SCRIPT_DIR/make-a-wallet.sh" "$NETWORK" bob charlie alice blue

# Backup seeds for mutinynet so we can recover funds if volumes are wiped
if [ "$NETWORK" = "mutinynet" ]; then
    echo ""
    echo "💾 Backing up node wallet seeds..."
    "$SCRIPT_DIR/mutinynet-treasury.sh" backup-seeds
fi

echo "✅ Reinit complete!"
