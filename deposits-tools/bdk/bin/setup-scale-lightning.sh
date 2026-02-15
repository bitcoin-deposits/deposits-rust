#!/bin/bash
# Scalable multi-operator setup with Lightning sidecars
#
# Spins up 12 operators with LDK Lightning nodes as sidecars.
# Opens Lightning channels in a ring topology to minimize channel count.
# Channel capacity matches reserves UTXO size.
#
# Ring topology: Node1 <-> Node2 <-> Node3 <-> ... <-> Node12 <-> Node1
#
# Usage:
#   ./bin/setup-scale-lightning.sh [--reserves N]
#
# Prerequisites:
#   - ldk-server built: cd ~/workspace/ldk-server && cargo build --release
#   - bdk-ldk-node image: docker compose -f docker-compose.lightning.yml build

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Configuration
TOTAL_NODES=12
RESERVES_AMOUNT=100000000  # 1 BTC - channel size will match this
ENFORCEMENT_DELAY=200
CHANNEL_AMOUNT=$RESERVES_AMOUNT  # Match reserves size

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --reserves)
            RESERVES_AMOUNT="$2"
            CHANNEL_AMOUNT="$2"
            shift 2
            ;;
        --nodes)
            TOTAL_NODES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--reserves N] [--nodes N]"
            exit 1
            ;;
    esac
done

# Temp directory for state
STATE_DIR=$(mktemp -d)
trap "rm -rf $STATE_DIR" EXIT

store_value() { echo "$2" > "$STATE_DIR/$1"; }
get_value() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }
append_value() { echo "$2" >> "$STATE_DIR/$1"; }
get_list() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"; }

# Container names (BDK nodes)
CORE_NAMES=("" "bdk-alice" "bdk-bob" "bdk-charlie" "bdk-diana")
CORE_SEEDS=(
    ""
    "416c696365000000000000000000000000000000000000000000000000000001"
    "426f620000000000000000000000000000000000000000000000000000000002"
    "436861726c696500000000000000000000000000000000000000000000000003"
    "4469616e61000000000000000000000000000000000000000000000000000004"
)

# LDK API port mapping (host ports)
# Alice=3111, Bob=3112, Charlie=3113, Diana=3114, Eve01=3115, etc.
ldk_host_port() {
    local n=$1
    echo $((3110 + n))
}

# LDK container internal port
ldk_internal_port() {
    local n=$1
    echo $((9734 + n))
}

generate_seed() {
    local n=$1
    if [ $n -le 4 ]; then
        echo "${CORE_SEEDS[$n]}"
    else
        printf "457665%02x0000000000000000000000000000000000000000000000000000%04x" $n $n
    fi
}

node_name() {
    local n=$1
    if [ $n -le 4 ]; then
        echo "${CORE_NAMES[$n]}"
    else
        printf "bdk-eve%02d" $((n - 4))
    fi
}

ln_node_name() {
    local n=$1
    echo "$(node_name $n)-ln"
}

run_node_cmd() {
    local n=$1
    shift
    local cmd=$1
    shift
    local name=$(node_name $n)
    local seed=$(generate_seed $n)
    docker exec -e RUST_LOG=error "$name" deposits-bdk "$cmd" "$@" \
        --seed "$seed" \
        --network regtest \
        --electrum http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data 2>&1
}

# LDK CLI helper
ldk_cli() {
    local n=$1
    shift
    local port=$(ldk_host_port $n)
    local name=$(node_name $n)
    local cert="$BDK_DIR/certs/${name}.crt"

    local cli="${LDK_SERVER_CLI:-$HOME/workspace/ldk-server/target/release/ldk-server-cli}"
    if [ ! -x "$cli" ]; then
        cli="$HOME/workspace/ldk-server/target/debug/ldk-server-cli"
    fi

    "$cli" -b "localhost:$port" -a test_api_key -t "$cert" "$@" 2>/dev/null
}

# ============================================================================
# Infrastructure setup
# ============================================================================

setup_infrastructure() {
    log_info "=== Setting up infrastructure ==="

    # Stop and remove existing eve nodes
    log_info "Cleaning up existing eve nodes..."
    for i in $(seq 1 99); do
        local name="bdk-eve$(printf '%02d' $i)"
        docker stop "$name" 2>/dev/null || true
        docker rm "$name" 2>/dev/null || true
        docker volume rm "bdk_${name}_data" 2>/dev/null || true
        # LN sidecar
        docker stop "${name}-ln" 2>/dev/null || true
        docker rm "${name}-ln" 2>/dev/null || true
        docker volume rm "ldk_${name}_data" 2>/dev/null || true
    done

    # Reset nostr relay and core containers
    log_info "Resetting Nostr relay and core containers..."
    $DC stop nostr-relay bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1 || true
    $DC rm -f nostr-relay bdk-alice bdk-bob bdk-charlie bdk-diana >/dev/null 2>&1 || true
    docker volume rm bdk_bdk_nostr_data 2>/dev/null || true
    docker volume rm bdk_bdk_alice_data bdk_bdk_bob_data bdk_bdk_charlie_data bdk_bdk_diana_data 2>/dev/null || true

    # Stop LDK sidecars for core nodes
    for node in alice bob charlie diana; do
        docker stop "bdk-${node}-ln" 2>/dev/null || true
        docker rm "bdk-${node}-ln" 2>/dev/null || true
        docker volume rm "ldk_${node}_data" 2>/dev/null || true
    done

    # Start core services
    log_info "Starting core services..."
    $DC up -d bitcoin electrs nostr-relay

    log_info "Waiting for services to be ready..."
    sleep 10

    # Create faucet wallet
    bitcoin_cli createwallet "faucet" 2>/dev/null || true
    bitcoin_cli -rpcwallet=faucet -generate 110 >/dev/null 2>&1

    # Create certs directory
    rm -rf "$BDK_DIR/certs"
    mkdir -p "$BDK_DIR/certs"

    log_success "Infrastructure ready"
}

# ============================================================================
# Node management
# ============================================================================

start_bdk_node() {
    local n=$1
    local name=$(node_name $n)
    local seed=$(generate_seed $n)

    if [ $n -le 4 ]; then
        log_info "Starting compose container $name..."
        $DC up -d "$name"
        sleep 2

        local address=$(run_node_cmd $n address 2>&1 | grep -E '^bcrt1' | head -1)
        if [ -n "$address" ]; then
            bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 5 >/dev/null 2>&1
            log_info "  Funded $name at ${address:0:20}..."
        fi
        return
    fi

    local ip="172.21.0.$((100 + n))"
    log_info "Starting $name (seed: ${seed:0:16}...)..."

    docker volume create "bdk_${name}_data" >/dev/null 2>&1 || true

    docker run -d \
        --name "$name" \
        --network bdk_bdk_network \
        --ip "$ip" \
        -v "bdk_${name}_data:/data" \
        -e RUST_LOG=warn,deposits_bdk=info \
        deposits-bdk:latest \
        run \
        --seed "$seed" \
        --network regtest \
        --electrum http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data \
        --metrics-port 9100 \
        >/dev/null 2>&1

    sleep 2

    local address=$(run_node_cmd $n address 2>&1 | grep -E '^bcrt1' | head -1)
    if [ -n "$address" ]; then
        bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 5 >/dev/null 2>&1
        log_info "  Funded $name at ${address:0:20}..."
    fi
}

start_ln_node() {
    local n=$1
    local bdk_name=$(node_name $n)
    local ln_name=$(ln_node_name $n)
    local ip="172.21.0.$((150 + n))"
    local internal_port=$(ldk_internal_port $n)
    local host_port=$(ldk_host_port $n)

    log_info "Starting $ln_name..."

    docker volume create "ldk_${bdk_name}_data" >/dev/null 2>&1 || true

    docker run -d \
        --name "$ln_name" \
        --network bdk_bdk_network \
        --ip "$ip" \
        -p "${host_port}:3000" \
        -v "ldk_${bdk_name}_data:/ldk" \
        -e NODE_NAME="$bdk_name" \
        -e LDK_DATA_DIR=/ldk \
        -e ELECTRUM_HOST=electrs \
        -e ELECTRUM_PORT=3002 \
        -e LISTEN_PORT=$internal_port \
        -e RUST_LOG=info,ldk_node=debug \
        -e LDK_ONCHAIN_WALLET_SYNC_INTERVAL_SECS=10 \
        -e LDK_LIGHTNING_WALLET_SYNC_INTERVAL_SECS=10 \
        bdk-ldk-node:latest \
        >/dev/null 2>&1

    sleep 3

    # Copy TLS cert
    for attempt in 1 2 3 4 5; do
        if docker cp "${ln_name}:/ldk/tls.crt" "$BDK_DIR/certs/${bdk_name}.crt" 2>/dev/null; then
            break
        fi
        sleep 2
    done
}

fund_ln_node() {
    local n=$1
    local amount_btc=${2:-2}
    local ln_name=$(ln_node_name $n)

    local address
    for i in 1 2 3 4 5; do
        local result=$(ldk_cli $n onchain-receive 2>/dev/null || echo "")
        address=$(echo "$result" | jq -r '.address // empty' 2>/dev/null || echo "")
        if [ -n "$address" ]; then
            break
        fi
        sleep 2
    done

    if [ -z "$address" ]; then
        log_warn "Could not get address for $ln_name"
        return 1
    fi

    bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" "$amount_btc" >/dev/null 2>&1
    log_info "  Funded $ln_name at ${address:0:20}..."
}

wait_for_ln_balance() {
    local n=$1
    local min_sats=${2:-100000000}
    local ln_name=$(ln_node_name $n)

    for i in $(seq 1 15); do
        local balance=$(ldk_cli $n get-balances 2>/dev/null | jq -r '.spendable_onchain_balance_sats // 0' 2>/dev/null || echo "0")
        if [ "$balance" -ge "$min_sats" ]; then
            return 0
        fi
        sleep 2
    done
    log_warn "$ln_name wallet sync timeout"
    return 1
}

get_ln_pubkey() {
    local n=$1
    ldk_cli $n get-node-info 2>/dev/null | jq -r '.node_id // empty' || echo ""
}

get_ln_address() {
    local n=$1
    local ln_name=$(ln_node_name $n)
    local port=$(ldk_internal_port $n)
    echo "${ln_name}:${port}"
}

# ============================================================================
# BDK setup (reserves, ledger, quorum)
# ============================================================================

setup_bdk_node() {
    local n=$1
    local name=$(node_name $n)

    log_info "Setting up $name..."

    local info=$(run_node_cmd $n info)
    local node_id=$(echo "$info" | grep "Node ID:" | awk '{print $3}')
    store_value "node_id_$n" "$node_id"

    local output=$(run_node_cmd $n reserves create $RESERVES_AMOUNT)
    local reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
    store_value "reserves_id_$n" "$reserves_id"

    local current_block=$(get_block_height)
    local enforcement_block=$((current_block + ENFORCEMENT_DELAY))

    output=$(run_node_cmd $n ledger open "$enforcement_block")
    local ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
    store_value "ledger_id_$n" "$ledger_id"

    local seed=$(generate_seed $n)
    docker exec -d "$name" deposits-bdk nostr watch "$ledger_id" \
        --seed "$seed" \
        --network regtest \
        --electrum http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data \
        >/dev/null 2>&1

    log_success "$name ready: ${node_id:0:12}... ledger: ${ledger_id:0:12}..."
}

# Add quorum members in ring topology: each node has prev and next as members
add_ring_quorum() {
    local n=$1
    local name=$(node_name $n)
    local node_id=$(get_value "node_id_$n")
    local reserves_id=$(get_value "reserves_id_$n")
    local ledger_id=$(get_value "ledger_id_$n")

    # Calculate prev and next in ring
    local prev=$((n - 1))
    local next=$((n + 1))
    if [ $prev -lt 1 ]; then prev=$TOTAL_NODES; fi
    if [ $next -gt $TOTAL_NODES ]; then next=1; fi

    local current_block=$(get_block_height)
    local membership_expires=$((current_block + 10000))

    log_info "  $name: adding ring neighbors ($(node_name $prev), $(node_name $next))..."

    for member_n in $prev $next; do
        local member_name=$(node_name $member_n)
        local member_node_id=$(get_value "node_id_$member_n")
        local member_ledger_id=$(get_value "ledger_id_$member_n")

        run_node_cmd $n partner add "$reserves_id" "$member_node_id" "$member_ledger_id" >/dev/null 2>&1 || true
        run_node_cmd $member_n partner join "$member_ledger_id" "$node_id" "$ledger_id" "$membership_expires" >/dev/null 2>&1 || true
    done
}

rotate_to_quorum() {
    local n=$1
    local reserves_id=$(get_value "reserves_id_$n")
    run_node_cmd $n reserves rotate "$reserves_id" >/dev/null 2>&1 || true
}

# ============================================================================
# Lightning channel setup (ring topology)
# ============================================================================

open_ring_channel() {
    local from=$1
    local to=$2
    local from_name=$(node_name $from)
    local to_name=$(node_name $to)

    log_info "  Opening channel: $from_name -> $to_name ($((CHANNEL_AMOUNT / 100000000)) BTC)..."

    local to_pubkey=$(get_value "ln_pubkey_$to")
    local to_addr=$(get_ln_address $to)

    if [ -z "$to_pubkey" ]; then
        log_warn "Could not get pubkey for $to_name"
        return 1
    fi

    # Check if channel already exists
    local existing=$(ldk_cli $from list-channels 2>/dev/null | jq -r ".channels[] | select(.counterparty_node_id == \"$to_pubkey\") | .channel_id" 2>/dev/null || echo "")
    if [ -n "$existing" ]; then
        log_info "    Channel already exists"
        return 0
    fi

    # Open channel with 50/50 balance
    local push_msat=$((CHANNEL_AMOUNT * 500))
    local result=$(ldk_cli $from open-channel \
        --node-pubkey "$to_pubkey" \
        --address "$to_addr" \
        --channel-amount-sats "$CHANNEL_AMOUNT" \
        --push-to-counterparty-msat "$push_msat" \
        --announce-channel 2>&1) || true

    local user_channel_id=$(echo "$result" | jq -r '.user_channel_id // empty' 2>/dev/null || echo "")
    if [ -n "$user_channel_id" ]; then
        log_info "    Channel pending: ${user_channel_id:0:16}..."
        return 0
    else
        log_warn "    Channel open failed: $(echo "$result" | head -1)"
        return 1
    fi
}

wait_for_channels() {
    log_info "Waiting for channels to confirm..."
    mine_blocks 6
    sleep 10

    local ready_count=0
    for n in $(seq 1 $TOTAL_NODES); do
        local channels=$(ldk_cli $n list-channels 2>/dev/null | jq -r '.channels | length' 2>/dev/null || echo "0")
        local ready=$(ldk_cli $n list-channels 2>/dev/null | jq -r '[.channels[] | select(.is_channel_ready == true)] | length' 2>/dev/null || echo "0")
        ready_count=$((ready_count + ready))
    done

    log_info "  $ready_count channel endpoints ready"
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "=========================================="
    log_info "  Lightning Scale Setup"
    log_info "=========================================="
    log_info "Total nodes: $TOTAL_NODES"
    log_info "Reserves/channel size: $((RESERVES_AMOUNT / 100000000)) BTC ($RESERVES_AMOUNT sats)"
    log_info "Topology: Ring (12 channels total)"
    echo ""

    setup_infrastructure

    # Start all BDK nodes
    log_info ""
    log_info "=== Starting BDK nodes ==="
    for n in $(seq 1 $TOTAL_NODES); do
        start_bdk_node $n
    done
    mine_blocks 1
    sleep 5

    # Setup BDK nodes (reserves, ledger)
    log_info ""
    log_info "=== Setting up BDK nodes ==="
    for n in $(seq 1 $TOTAL_NODES); do
        setup_bdk_node $n
    done
    mine_blocks 1

    # Add ring quorum
    log_info ""
    log_info "=== Adding ring quorum ==="
    for n in $(seq 1 $TOTAL_NODES); do
        add_ring_quorum $n
    done

    # Rotate to quorum
    log_info ""
    log_info "=== Rotating reserves to quorum ==="
    for n in $(seq 1 $TOTAL_NODES); do
        rotate_to_quorum $n
    done
    mine_blocks 1

    # Start all LN nodes
    log_info ""
    log_info "=== Starting Lightning sidecars ==="
    for n in $(seq 1 $TOTAL_NODES); do
        start_ln_node $n
    done
    sleep 5

    # Get LN pubkeys
    log_info ""
    log_info "=== Getting Lightning node info ==="
    for n in $(seq 1 $TOTAL_NODES); do
        local pubkey=$(get_ln_pubkey $n)
        store_value "ln_pubkey_$n" "$pubkey"
        log_info "  $(node_name $n): ${pubkey:0:20}..."
    done

    # Fund LN nodes
    log_info ""
    log_info "=== Funding Lightning nodes ==="
    for n in $(seq 1 $TOTAL_NODES); do
        fund_ln_node $n 2
    done
    mine_blocks 6

    # Wait for balances
    log_info ""
    log_info "=== Waiting for Lightning wallet sync ==="
    for n in $(seq 1 $TOTAL_NODES); do
        wait_for_ln_balance $n 100000000  # 1 BTC minimum
    done

    # Open ring channels
    log_info ""
    log_info "=== Opening ring channels ==="
    for n in $(seq 1 $TOTAL_NODES); do
        local next=$((n + 1))
        if [ $next -gt $TOTAL_NODES ]; then next=1; fi
        open_ring_channel $n $next
    done

    wait_for_channels

    # Print summary
    log_info ""
    log_info "=========================================="
    log_info "  Setup Complete!"
    log_info "=========================================="
    echo ""
    log_info "Nodes:"
    for n in $(seq 1 $TOTAL_NODES); do
        local name=$(node_name $n)
        local node_id=$(get_value "node_id_$n")
        local ledger_id=$(get_value "ledger_id_$n")
        local ln_pubkey=$(get_value "ln_pubkey_$n")
        echo "  $name:"
        echo "    BDK: ${node_id:0:16}... -> ${ledger_id:0:16}..."
        echo "    LN:  ${ln_pubkey:0:16}..."
    done
    echo ""
    log_info "Ring topology: Node1 <-> Node2 <-> ... <-> Node12 <-> Node1"
    log_info "Channel capacity: $((CHANNEL_AMOUNT / 100000000)) BTC each"
    log_info "Block height: $(get_block_height)"
    echo ""
    log_info "View ledgers: ./bin/nostr-updates.sh --color"
    log_info "LDK CLI:      ./bin/ldk-cli.sh <node> <command>"
    echo ""

    log_success "Done! $TOTAL_NODES operators with Lightning sidecars in ring topology."
}

main
