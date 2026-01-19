#!/bin/bash
#
# Full reinitialization of the test environment
# Tears down containers, rebuilds, and recreates everything
#
# Usage: ./bin/reinit.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1
COMPOSE_FILE=$(get_compose_file "$NETWORK")

rm -f wallet/*.json

touch log/reinit-time

if [ "$NETWORK" = "regtest" ]; then
    # Regtest: wipe volumes since we can mine new funds
    docker compose -f "$COMPOSE_FILE" down -v
else
    # Mutinynet: preserve volumes to keep funds (can't mine, need faucet)
    docker compose -f "$COMPOSE_FILE" down
fi

docker compose -f "$COMPOSE_FILE" up --build -d
cargo run --manifest-path ../Cargo.toml --features bitcoin-deposits --bin network-init -- --network "$NETWORK" 2> /dev/null

# Wait for peer connections to stabilize after network init
# LDK peers may disconnect/reconnect during channel reestablishment
echo "⏳ Waiting for peer connections to stabilize (60 seconds)..."
sleep 60

./bin/drop-ledgers.sh

# Create wallets for alice and bob
echo "🔑 Creating wallet for alice..."
./bin/make-a-wallet.sh alice charlie bob amber

echo "🔑 Creating wallet for bob..."
./bin/make-a-wallet.sh bob charlie alice blue

# Copy TLS certificates for CLI access
echo ""
echo "🔐 Copying TLS certificates..."
copy_tls_certs alice bob charlie

# Backup seeds for mutinynet so we can recover funds if volumes are wiped
if [ "$NETWORK" = "mutinynet" ]; then
    echo ""
    echo "💾 Backing up node wallet seeds..."
    ./bin/mutinynet-treasury.sh backup-seeds
fi

echo "✅ Reinit complete!"
