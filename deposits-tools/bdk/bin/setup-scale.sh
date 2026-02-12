#!/bin/bash
# Scalable multi-operator setup script
#
# Gradually spins up N operators (default 24) with semi-random quorum membership.
# Starts with 3 nodes, adds more in waves, each picking 3-5 quorum members.
#
# Usage:
#   ./bin/setup-scale.sh [--nodes N] [--wave-size N] [--quorum-min N] [--quorum-max N]
#
# Example:
#   ./bin/setup-scale.sh --nodes 12 --wave-size 3

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Configuration
TOTAL_NODES=24
WAVE_SIZE=3
QUORUM_MIN=3
QUORUM_MAX=5
RESERVES_AMOUNT=100000000  # 1 BTC
ENFORCEMENT_DELAY=200
WAVE_DELAY=5  # seconds between waves

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes)
            TOTAL_NODES="$2"
            shift 2
            ;;
        --wave-size)
            WAVE_SIZE="$2"
            shift 2
            ;;
        --quorum-min)
            QUORUM_MIN="$2"
            shift 2
            ;;
        --quorum-max)
            QUORUM_MAX="$2"
            shift 2
            ;;
        --reserves)
            RESERVES_AMOUNT="$2"
            shift 2
            ;;
        --enforcement-delay)
            ENFORCEMENT_DELAY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--nodes N] [--wave-size N] [--quorum-min N] [--quorum-max N]"
            exit 1
            ;;
    esac
done

# Temp directory for state
STATE_DIR=$(mktemp -d)
trap "rm -rf $STATE_DIR" EXIT

store_value() {
    echo "$2" > "$STATE_DIR/$1"
}

get_value() {
    [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"
}

append_value() {
    echo "$2" >> "$STATE_DIR/$1"
}

get_list() {
    [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1"
}

# Generate deterministic seed for node N (hex string, 64 chars)
generate_seed() {
    local n=$1
    printf "6e6f6465%02x00000000000000000000000000000000000000000000000000%04x" $n $n
}

# Generate container name for node N
node_name() {
    printf "bdk-node%02d" $1
}

# Run a CLI command on a node
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
        --esplora http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data 2>&1
}

# ============================================================================
# Infrastructure setup
# ============================================================================

setup_infrastructure() {
    log_info "=== Setting up infrastructure ==="

    # Stop and remove any existing scale nodes
    log_info "Cleaning up existing scale nodes..."
    for i in $(seq 1 99); do
        local name=$(node_name $i)
        docker stop "$name" 2>/dev/null || true
        docker rm "$name" 2>/dev/null || true
        docker volume rm "bdk_${name}_data" 2>/dev/null || true
    done

    # Reset nostr relay
    log_info "Resetting Nostr relay..."
    $DC stop nostr-relay >/dev/null 2>&1 || true
    $DC rm -f nostr-relay >/dev/null 2>&1 || true
    docker volume rm bdk_bdk_nostr_data 2>/dev/null || true

    # Start core services
    log_info "Starting core services..."
    $DC up -d bitcoin electrs nostr-relay

    # Wait for services
    log_info "Waiting for services to be ready..."
    sleep 10

    # Create faucet wallet
    bitcoin_cli createwallet "faucet" 2>/dev/null || true
    bitcoin_cli -rpcwallet=faucet -generate 110 >/dev/null 2>&1

    log_success "Infrastructure ready"
}

# ============================================================================
# Node management
# ============================================================================

start_node() {
    local n=$1
    local name=$(node_name $n)
    local seed=$(generate_seed $n)
    local ip="172.21.0.$((100 + n))"

    log_info "Starting $name (seed: ${seed:0:16}...)..."

    # Create volume
    docker volume create "bdk_${name}_data" >/dev/null 2>&1 || true

    # Start container
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
        >/dev/null 2>&1

    # Wait for it to be ready
    sleep 2

    # Get wallet address and fund the node
    local address=$(run_node_cmd $n address 2>&1 | grep -E '^bcrt1' | head -1)
    if [ -n "$address" ]; then
        bitcoin_cli -rpcwallet=faucet sendtoaddress "$address" 5 >/dev/null 2>&1
        log_info "  Funded $name at $address"
    else
        log_warn "  Could not get address for $name"
    fi
}

get_node_info() {
    local n=$1
    local name=$(node_name $n)

    local info=$(run_node_cmd $n info)
    local node_id=$(echo "$info" | grep "Node ID:" | awk '{print $3}')

    store_value "node_id_$n" "$node_id"
    echo "$node_id"
}

setup_node() {
    local n=$1
    local name=$(node_name $n)

    log_info "Setting up $name..."

    # Get node ID
    local node_id=$(get_node_info $n)
    if [ -z "$node_id" ]; then
        log_error "Could not get node ID for $name"
        return 1
    fi

    # Check wallet balance (info command syncs the wallet)
    local balance=$(run_node_cmd $n info 2>&1 | grep "Wallet balance:" | awk '{print $3}')
    if [ -z "$balance" ] || [ "$balance" -lt $RESERVES_AMOUNT ]; then
        log_warn "  $name has insufficient balance: $balance sats"
    fi

    # Create reserves
    local output=$(run_node_cmd $n reserves create $RESERVES_AMOUNT)
    local reserves_id=$(echo "$output" | grep "Address:" | awk '{print $2}')
    if [ -z "$reserves_id" ]; then
        log_error "  Failed to create reserves: $(echo "$output" | tail -1)"
        return 1
    fi
    store_value "reserves_id_$n" "$reserves_id"

    # Get enforcement block
    local current_block=$(get_block_height)
    local enforcement_block=$((current_block + ENFORCEMENT_DELAY))

    # Open ledger
    output=$(run_node_cmd $n ledger open "$enforcement_block")
    local ledger_id=$(echo "$output" | grep "Ledger ID:" | awk '{print $3}')
    store_value "ledger_id_$n" "$ledger_id"

    # Start nostr watcher in background
    local seed=$(generate_seed $n)
    docker exec -d "$name" deposits-bdk nostr watch "$ledger_id" \
        --seed "$seed" \
        --network regtest \
        --esplora http://electrs:3002 \
        --relay ws://nostr-relay:7777 \
        --data-dir /data \
        >/dev/null 2>&1

    # Track this node as ready
    append_value "ready_nodes" "$n"

    log_success "$name ready: ${node_id:0:12}... ledger: ${ledger_id:0:12}..."
}

# ============================================================================
# Quorum setup
# ============================================================================

# Pick N random items from a list (excluding self)
pick_random() {
    local exclude=$1
    local count=$2
    shift 2
    local items=("$@")

    # Remove excluded item
    local filtered=()
    for item in "${items[@]}"; do
        if [ "$item" != "$exclude" ]; then
            filtered+=("$item")
        fi
    done

    # Shuffle and pick
    printf '%s\n' "${filtered[@]}" | shuf | head -n "$count"
}

add_quorum_members() {
    local n=$1
    local name=$(node_name $n)
    local node_id=$(get_value "node_id_$n")
    local ledger_id=$(get_value "ledger_id_$n")

    # Get list of ready nodes
    local ready=($(get_list "ready_nodes"))
    local ready_count=${#ready[@]}

    # Pick random number of quorum members (between min and max)
    local num_members=$((RANDOM % (QUORUM_MAX - QUORUM_MIN + 1) + QUORUM_MIN))
    if [ $num_members -gt $((ready_count - 1)) ]; then
        num_members=$((ready_count - 1))
    fi

    if [ $num_members -lt 1 ]; then
        log_info "  $name: no other nodes available for quorum yet"
        return
    fi

    log_info "  $name: adding $num_members quorum members..."

    # Pick random members
    local members=($(pick_random "$n" "$num_members" "${ready[@]}"))

    for member_n in "${members[@]}"; do
        local member_name=$(node_name $member_n)
        local member_node_id=$(get_value "node_id_$member_n")
        local member_ledger_id=$(get_value "ledger_id_$member_n")

        # Add member to our quorum
        run_node_cmd $n partner add "$ledger_id" "$member_node_id" "$member_ledger_id" >/dev/null 2>&1 || true

        # Record join on member's side
        run_node_cmd $member_n partner join "$member_ledger_id" "$node_id" "$ledger_id" 1000000 >/dev/null 2>&1 || true

        log_info "    + ${member_name}"
    done
}

rotate_to_quorum() {
    local n=$1
    local reserves_id=$(get_value "reserves_id_$n")

    run_node_cmd $n reserves rotate "$reserves_id" >/dev/null 2>&1 || true
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "=========================================="
    log_info "  Scalable Multi-Operator Setup"
    log_info "=========================================="
    log_info "Total nodes: $TOTAL_NODES"
    log_info "Wave size: $WAVE_SIZE"
    log_info "Quorum members: $QUORUM_MIN - $QUORUM_MAX per node"
    log_info "Reserves: $RESERVES_AMOUNT sats each"
    echo ""

    setup_infrastructure

    # Process in waves
    local wave=1
    local started=0

    while [ $started -lt $TOTAL_NODES ]; do
        local wave_end=$((started + WAVE_SIZE))
        if [ $wave_end -gt $TOTAL_NODES ]; then
            wave_end=$TOTAL_NODES
        fi

        log_info ""
        log_info "=== Wave $wave: nodes $((started + 1)) to $wave_end ==="
        echo ""

        # Start nodes in this wave
        for n in $(seq $((started + 1)) $wave_end); do
            start_node $n
        done

        # Mine blocks to confirm funding and wait for wallet sync
        mine_blocks 1
        log_info "Waiting for wallet sync..."
        sleep 5

        # Setup nodes (reserves, ledger, watcher)
        for n in $(seq $((started + 1)) $wave_end); do
            setup_node $n || log_warn "Setup failed for node $n, continuing..."
        done

        # Mine to confirm reserves
        mine_blocks 1
        sleep 2

        # Add quorum members for new nodes
        log_info ""
        log_info "Adding quorum members..."
        for n in $(seq $((started + 1)) $wave_end); do
            add_quorum_members $n
        done

        # Also update quorum for existing nodes (they can now add new nodes)
        if [ $started -gt 0 ]; then
            log_info ""
            log_info "Updating existing nodes' quorums..."
            for n in $(seq 1 $started); do
                # 50% chance to add new members
                if [ $((RANDOM % 2)) -eq 0 ]; then
                    add_quorum_members $n
                fi
            done
        fi

        # Rotate all nodes to quorum-based taproot
        log_info ""
        log_info "Rotating reserves to quorum..."
        for n in $(seq 1 $wave_end); do
            rotate_to_quorum $n
        done

        mine_blocks 1

        started=$wave_end
        wave=$((wave + 1))

        if [ $started -lt $TOTAL_NODES ]; then
            log_info ""
            log_info "Waiting ${WAVE_DELAY}s before next wave..."
            sleep $WAVE_DELAY
        fi
    done

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
        echo "  $name: ${node_id:0:12}... -> ${ledger_id:0:12}..."
    done
    echo ""
    log_info "Block height: $(get_block_height)"
    echo ""
    log_info "View all ledgers: ./bin/nostr-updates.sh --color"
    log_info "Stop all: docker stop \$(docker ps -q --filter 'name=bdk-node')"
    echo ""

    log_success "Done! $TOTAL_NODES operators running with semi-random quorum membership."
}

main
