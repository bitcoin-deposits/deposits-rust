#!/bin/bash
#
# Mutinynet Treasury & Wallet Backup Manager
#
# This script manages:
# 1. A host-side treasury wallet (outside docker) for funding nodes
# 2. Backup/restore of node wallet secrets (keys_seed) to preserve funds across reinits
#
# The treasury wallet is stored on the host and survives any docker operations.
# Fund it once from the faucet, then use it to fund nodes whenever needed.
#
# Usage:
#   ./mutinynet-treasury.sh init           # Initialize treasury wallet (once)
#   ./mutinynet-treasury.sh address        # Show treasury address (for faucet funding)
#   ./mutinynet-treasury.sh balance        # Check treasury and node balances
#   ./mutinynet-treasury.sh fund-nodes     # Fund nodes from treasury
#   ./mutinynet-treasury.sh backup-seeds   # Backup node seeds to host

cd "$(dirname "$0")/.."
set -e

TREASURY_DIR="treasury"
SEEDS_DIR="$TREASURY_DIR/seeds"
TREASURY_SEED="$TREASURY_DIR/treasury_seed"
SEEDS_LOG="$TREASURY_DIR/seeds.log"
COMPOSE_FILE="docker-compose-mutinynet.yml"

# Electrum server for mutinynet
ELECTRUM_URL="ssl://mutinynet.com:50002"
ESPLORA_URL="https://mutinynet.com/api"

# Ensure directories exist
mkdir -p "$TREASURY_DIR" "$SEEDS_DIR"

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Treasury Commands (host-side wallet, outside docker):"
    echo "  init            Initialize treasury wallet (run once)"
    echo "  address         Show treasury address (fund from faucet)"
    echo "  balance         Check treasury and node balances"
    echo "  fund-nodes      Send funds from treasury to nodes"
    echo "  reclaim         Sweep all node funds back to treasury"
    echo ""
    echo "Node Seed Backup Commands:"
    echo "  backup-seeds    Backup node wallet seeds to host"
    echo "  restore-seeds   Restore seeds from backup"
    echo "  show-seeds      Display backed up seeds"
    echo ""
    echo "First time setup:"
    echo "  1. ./mutinynet-treasury.sh init"
    echo "  2. ./mutinynet-treasury.sh address  # Fund this from faucet"
    echo "  3. ./mutinynet-treasury.sh fund-nodes"
    exit 1
}

log_timestamp() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$SEEDS_LOG"
}

# Treasury wallet management
cmd_init() {
    if [ -f "$TREASURY_SEED" ]; then
        echo "Treasury already initialized."
        echo "Seed file: $TREASURY_SEED"
        echo ""
        echo "To reinitialize, delete the file first (you'll lose access to funds!):"
        echo "  rm $TREASURY_SEED"
        exit 1
    fi

    echo "Initializing treasury wallet..."
    echo ""

    # Generate 32 bytes of entropy for the seed
    openssl rand -hex 32 > "$TREASURY_SEED"
    chmod 600 "$TREASURY_SEED"

    seed=$(cat "$TREASURY_SEED")
    echo "Treasury seed created: $TREASURY_SEED"
    echo ""

    # Build and show the treasury address
    echo "Building treasury-address tool..."
    if cargo build --bin treasury-address --quiet 2>/dev/null; then
        echo ""
        cargo run --bin treasury-address --quiet 2>/dev/null
    else
        echo "IMPORTANT: This seed controls your treasury funds!"
        echo "Seed (hex): $seed"
        echo ""
        echo "To get the address, import seed into Sparrow Wallet:"
        echo "  - Download Sparrow: https://sparrowwallet.com/"
        echo "  - File -> New Wallet -> 'treasury'"
        echo "  - Select 'New or Imported Software Wallet'"
        echo "  - Use 'Master Private Key (HEX)' and paste the seed above"
        echo "  - Set Script Type to 'Native Segwit (P2WPKH)'"
        echo "  - Connect to Mutinynet electrum: $ELECTRUM_URL"
    fi
}

cmd_treasury_address() {
    if [ ! -f "$TREASURY_SEED" ]; then
        echo "Treasury not initialized. Run: $0 init"
        exit 1
    fi

    # Use the treasury-address binary to derive the address
    if command -v cargo &> /dev/null; then
        cargo run --bin treasury-address --quiet 2>/dev/null || {
            echo "Treasury seed file: $TREASURY_SEED"
            echo "Seed (hex): $(cat $TREASURY_SEED)"
            echo ""
            echo "Could not derive address. Install Rust or use Sparrow Wallet."
        }
    else
        echo "Treasury seed file: $TREASURY_SEED"
        echo "Seed (hex): $(cat $TREASURY_SEED)"
        echo ""
        echo "To get the treasury address, import seed into Sparrow Wallet"
    fi
}

cmd_treasury_balance() {
    echo "Node balances:"
    echo ""
    local total=0
    for node in alice:3011 bob:3012 charlie:3013; do
        name=${node%:*}
        port=${node#*:}
        balance=$(curl -s http://localhost:${port}/bitcoin/balance 2>/dev/null | jq -r '.data.balance_sat // 0')
        pending=$(curl -s http://localhost:${port}/bitcoin/balance 2>/dev/null | jq -r '.data.pending_balance_sat // 0')
        total=$((total + balance + pending))
        printf "  %-8s %12s sat" "$name:" "$balance"
        if [ "$pending" != "0" ]; then
            echo " (+$pending pending)"
        else
            echo ""
        fi
    done
    echo ""
    echo "Total in nodes: $total sat"
    echo ""

    # Check treasury balance via esplora API
    if [ -f "$TREASURY_SEED" ]; then
        # Get treasury address from the binary
        treasury_address=$(cargo run --bin treasury-address --quiet 2>/dev/null | grep -E '^tb1' | head -1)
        if [ -n "$treasury_address" ]; then
            echo "Treasury address: $treasury_address"

            # Query esplora for address stats
            stats=$(curl -s "${ESPLORA_URL}/address/${treasury_address}" 2>/dev/null)
            if [ -n "$stats" ]; then
                # Parse chain_stats and mempool_stats
                chain_funded=$(echo "$stats" | jq -r '.chain_stats.funded_txo_sum // 0')
                chain_spent=$(echo "$stats" | jq -r '.chain_stats.spent_txo_sum // 0')
                mempool_funded=$(echo "$stats" | jq -r '.mempool_stats.funded_txo_sum // 0')
                mempool_spent=$(echo "$stats" | jq -r '.mempool_stats.spent_txo_sum // 0')

                confirmed_balance=$((chain_funded - chain_spent))
                pending_balance=$((mempool_funded - mempool_spent))

                echo "Treasury balance: $confirmed_balance sat"
                if [ "$pending_balance" != "0" ]; then
                    echo "Treasury pending: $pending_balance sat"
                fi
            else
                echo "Treasury balance: (could not query esplora)"
            fi
        else
            echo "Treasury balance: (could not derive address)"
        fi
    else
        echo "Treasury: not initialized (run: $0 init)"
    fi
}

cmd_backup_seeds() {
    echo "Backing up node wallet seeds..."
    echo ""

    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local seeds_log="$TREASURY_DIR/seeds.log"

    # Append header to log
    echo "" >> "$seeds_log"
    echo "=== Seed Backup: $timestamp ===" >> "$seeds_log"

    for node in alice bob charlie; do
        container="ldk-${node}-mutiny"

        # Check if container is running
        if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            echo "  $node: container not running, skipping"
            continue
        fi

        # Copy seed from container to temp file
        local temp_seed=$(mktemp)
        if docker cp "${container}:/ldk/keys_seed" "$temp_seed" 2>/dev/null; then
            # Get hex and address
            seed_hex=$(xxd -p "$temp_seed" | tr -d '\n')
            address=$(curl -s http://localhost:${node#alice}${node#bob}${node#charlie}/bitcoin/address 2>/dev/null | jq -r '.data.address // "unknown"')

            # Get port for address lookup
            case "$node" in
                alice)   port=3011 ;;
                bob)     port=3012 ;;
                charlie) port=3013 ;;
            esac
            address=$(curl -s http://localhost:${port}/bitcoin/address | jq -r '.data.address // "unknown"')
            balance=$(curl -s http://localhost:${port}/bitcoin/balance | jq -r '.data.balance_sat // 0')

            # Append to log (never overwrite!)
            echo "$node: seed=$seed_hex address=$address balance=${balance}sat" >> "$seeds_log"

            # Also write current seed to individual file for restore
            cp "$temp_seed" "$SEEDS_DIR/${node}_keys_seed"

            echo "  $node: ${seed_hex:0:32}..."
            echo "         address: $address (balance: $balance sat)"

            rm -f "$temp_seed"
        else
            echo "  $node: failed to backup (no keys_seed file?)"
        fi
    done

    echo ""
    echo "Seeds appended to $seeds_log"
    echo "All historical seeds are preserved."
}

cmd_restore_seeds() {
    echo "Restoring node wallet seeds from backup..."
    echo ""

    for node in alice bob charlie; do
        container="ldk-${node}-mutiny"
        seed_file="$SEEDS_DIR/${node}_keys_seed"

        if [ ! -f "$seed_file" ]; then
            echo "  $node: no backup found at $seed_file"
            continue
        fi

        # Check if container is running
        if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            echo "  $node: container not running, skipping"
            continue
        fi

        # Stop container, copy seed, start container
        echo "  $node: restoring seed..."
        docker cp "$seed_file" "${container}:/ldk/keys_seed"

        seed_hex=$(xxd -p "$seed_file" | tr -d '\n')
        log_timestamp "RESTORE $node: seed=$seed_hex"

        echo "         restored: ${seed_hex:0:32}..."
    done

    echo ""
    echo "Seeds restored. Restart containers to apply:"
    echo "  docker-compose -f $COMPOSE_FILE restart ldk-alice ldk-bob ldk-charlie"
}

cmd_show_seeds() {
    local seeds_log="$TREASURY_DIR/seeds.log"

    if [ ! -f "$seeds_log" ]; then
        echo "No seeds log found at $seeds_log"
        echo "Run './mutinynet-treasury.sh backup-seeds' first."
        exit 1
    fi

    echo "=== All backed up seeds (newest last) ==="
    echo ""
    cat "$seeds_log"
    echo ""
    echo "Log file: $seeds_log"
}

cmd_address() {
    cmd_treasury_address
}

cmd_balance() {
    cmd_treasury_balance
}

cmd_log_addresses() {
    echo "Logging current node addresses..."
    log_timestamp "=== Address snapshot ==="

    for node in alice:3011 bob:3012 charlie:3013; do
        name=${node%:*}
        port=${node#*:}
        address=$(curl -s http://localhost:${port}/bitcoin/address | jq -r '.data.address // "unavailable"')
        node_id=$(curl -s http://localhost:${port}/info | jq -r '.data.node_id // "unavailable"')
        balance=$(curl -s http://localhost:${port}/bitcoin/balance | jq -r '.data.balance_sat // 0')

        log_timestamp "$name: address=$address node_id=${node_id:0:16}... balance=$balance"
        echo "  $name: $address (balance: $balance sat)"
    done

    echo ""
    echo "Addresses logged to $ADDRESSES_LOG"
}

cmd_fund_nodes() {
    if [ ! -f "$TREASURY_SEED" ]; then
        echo "Treasury not initialized. Run: $0 init"
        exit 1
    fi

    # Always backup seeds before funding - ensures we can recover funds
    echo "=== Backing up node seeds before funding ==="
    cmd_backup_seeds
    echo ""

    # Build and run treasury-send
    echo "=== Funding nodes from treasury ==="
    if ! cargo build --bin treasury-send --quiet 2>/dev/null; then
        echo "Failed to build treasury-send. Falling back to manual instructions."
        cmd_fund_nodes_manual
        return
    fi

    ./target/debug/treasury-send --fund-nodes
}

cmd_sweep_nodes() {
    local treasury_address="${2:-}"

    if [ -z "$treasury_address" ]; then
        echo "Usage: $0 sweep-nodes <treasury-address>"
        echo ""
        echo "Get your treasury address from Sparrow Wallet and provide it."
        echo "This will sweep all node funds to your treasury."
        echo ""
        echo "Current node balances:"
        cmd_balance
        exit 1
    fi

    echo "Sweeping all node funds to treasury: $treasury_address"
    echo ""

    for node in alice:3011 bob:3012 charlie:3013; do
        name=${node%:*}
        port=${node#*:}

        balance=$(curl -s http://localhost:${port}/bitcoin/balance 2>/dev/null | jq -r '.data.balance_sat // 0')

        if [ "$balance" -gt 15000 ]; then
            # Leave some for fees
            sweep_amount=$((balance - 5000))
            echo "Sweeping $sweep_amount sats from $name..."
            result=$(curl -s -X POST http://localhost:${port}/bitcoin/send \
                -H "Content-Type: application/json" \
                -d "{\"address\":\"$treasury_address\",\"amount_sat\":$sweep_amount}")
            if echo "$result" | jq -e '.success' >/dev/null 2>&1; then
                echo "  sent!"
            else
                echo "  failed: $(echo "$result" | jq -r '.error // "unknown error"')"
            fi
        else
            echo "$name: balance too low ($balance sat)"
        fi
    done

    echo ""
    echo "Sweep complete! Wait for confirmations (~3 min)."
}

cmd_reclaim() {
    if [ ! -f "$TREASURY_SEED" ]; then
        echo "Treasury not initialized. Run: $0 init"
        exit 1
    fi

    # Get treasury address from the binary
    echo "Getting treasury address..."
    treasury_address=$(cargo run --bin treasury-address --quiet 2>/dev/null | grep -E '^tb1' | head -1)

    if [ -z "$treasury_address" ]; then
        echo "Failed to get treasury address. Make sure treasury-address is built."
        exit 1
    fi

    echo "=== Reclaiming funds to treasury: $treasury_address ==="
    echo ""

    # Part 1: Reclaim from running nodes via API
    echo "--- Running nodes ---"
    local total_from_nodes=0

    for node in alice:3011 bob:3012 charlie:3013; do
        name=${node%:*}
        port=${node#*:}

        balance=$(curl -s http://localhost:${port}/bitcoin/balance 2>/dev/null | jq -r '.data.balance_sat // 0')

        if [[ "$balance" -gt 1000 ]]; then
            echo "  $name: sweeping all (balance: $balance)..."
            # Omit amount_sat to sweep all funds
            result=$(curl -s -X POST http://localhost:${port}/bitcoin/send \
                -H "Content-Type: application/json" \
                -d "{\"address\":\"$treasury_address\"}")
            if echo "$result" | jq -e '.success' >/dev/null 2>&1; then
                txid=$(echo "$result" | jq -r '.data.txid // "unknown"')
                echo "         sent! txid: ${txid:0:16}..."
                total_from_nodes=$((total_from_nodes + balance))
            else
                echo "         failed: $(echo "$result" | jq -r '.error // "unknown error"')"
            fi
        else
            echo "  $name: balance too low ($balance sat), skipping"
        fi
    done

    echo ""
    echo "From running nodes: $total_from_nodes sat"
    echo ""

    # Part 2: Reclaim from historical seeds
    echo "--- Historical seed addresses ---"
    if [ -f "$SEEDS_LOG" ]; then
        # Build first silently, then run
        cargo build --bin treasury-send --quiet 2>/dev/null
        ./target/debug/treasury-send --reclaim-seeds 2>&1 | grep "^  "
    else
        echo "  No seeds.log found - skipping historical sweep"
    fi

    echo ""
    echo "=== Reclaim complete! ==="
    echo "  Treasury address: $treasury_address"
    echo ""
    echo "Wait for confirmations (~3 min on mutinynet)."
}

# Main
case "${1:-}" in
    init)           cmd_init ;;
    address)        cmd_address ;;
    balance)        cmd_balance ;;
    fund-nodes)     cmd_fund_nodes ;;
    reclaim)        cmd_reclaim ;;
    sweep-nodes)    cmd_sweep_nodes "$@" ;;
    backup-seeds)   cmd_backup_seeds ;;
    restore-seeds)  cmd_restore_seeds ;;
    show-seeds)     cmd_show_seeds ;;
    log-addresses)  cmd_log_addresses ;;
    *)              usage ;;
esac
