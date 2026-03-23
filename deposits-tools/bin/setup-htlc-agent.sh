#!/bin/bash
# Set up the HTLC agent: open deposits on every operator ledger, fund them, start the agent.
#
# Can be called standalone or from setup-4op-lightning.sh.
#
# Usage:
#   ./bin/setup-htlc-agent.sh                          # Fresh setup (wipes existing agent data)
#   ./bin/setup-htlc-agent.sh --keep-data              # Reuse existing deposits, just restart
#   ./bin/setup-htlc-agent.sh --deposit-sats 1000000   # Custom deposit size

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Defaults
HTLC_AGENT="${HTLC_AGENT:-$REPO_ROOT/target/release/htlc-agent}"
AGENT_DATA_DIR="$DATA_ROOT/htlc-agent"
AGENT_SEED="48544c43416765006e740000000000000000000000000000000000000000000a"
AGENT_DEPOSIT_SATS=500000  # 0.005 BTC per deposit
KEEP_DATA=false
OPERATORS="${OPERATORS:-alice bob charlie diana}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-data|-k)
            KEEP_DATA=true
            shift
            ;;
        --deposit-sats)
            AGENT_DEPOSIT_SATS="$2"
            shift 2
            ;;
        --seed)
            AGENT_SEED="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --keep-data, -k          Reuse existing agent data, just restart"
            echo "  --deposit-sats <sats>    Deposit size per ledger (default: 500000)"
            echo "  --seed <hex>             Agent seed (default: built-in)"
            echo "  --help, -h               Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info "=========================================="
log_info "  HTLC Agent Setup"
log_info "=========================================="
echo ""

# Stop any existing agent
if [ -f "$AGENT_DATA_DIR/agent.pid" ]; then
    old_pid=$(cat "$AGENT_DATA_DIR/agent.pid")
    if kill -0 "$old_pid" 2>/dev/null; then
        kill "$old_pid" 2>/dev/null || true
        sleep 1
        kill -0 "$old_pid" 2>/dev/null && kill -9 "$old_pid" 2>/dev/null || true
        log_info "Stopped old agent (pid $old_pid)"
    fi
fi
pkill -f "htlc-agent" 2>/dev/null || true

# ── If --keep-data and deposits exist, skip straight to starting the agent ──

if $KEEP_DATA && [ -f "$AGENT_DATA_DIR/deposits.json" ]; then
    existing=$(python3 -c "
import json
data = json.load(open('$AGENT_DATA_DIR/deposits.json'))
print(sum(1 for d in data if d.get('status') in ('completed', 'funded')))
" 2>/dev/null || echo "0")

    if [ "$existing" -gt 0 ]; then
        log_info "Reusing $existing existing deposits (--keep-data)"
        # Jump to start
        START_AGENT=true
    fi
fi

if [ "${START_AGENT:-}" != "true" ]; then

    # Fresh setup
    if ! $KEEP_DATA; then
        rm -rf "$AGENT_DATA_DIR"
    fi
    mkdir -p "$AGENT_DATA_DIR"
    echo "$AGENT_SEED" > "$AGENT_DATA_DIR/seed.hex"

    # ── Discover ledgers from relay advertisements ─────────────────────────

    log_info "=== Discovering operator ledgers from $RELAY_LEDGERS ==="

    LEDGER_IDS=()
    LEDGER_RELAYS=()

    # Fetch advertisements as JSON (one per line), pick one ledger per operator
    ads_json=$(RUST_LOG=error "$DEPOSITS_WALLET" discover --json \
        --seed "$AGENT_SEED" --network regtest \
        --relay "$RELAY_LEDGERS" 2>/dev/null || true)

    if [ -z "$ads_json" ]; then
        log_error "No advertisements found on $RELAY_LEDGERS — cannot set up agent"
        exit 1
    fi

    # One deposit per ledger (all advertised ledgers)
    seen_ledgers=""
    LEDGER_OPERATORS=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        parsed=$(echo "$line" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if d.get('type') == 'agent': sys.exit(0)  # skip agent ads in JSON output
print(d.get('operator_pubkey',''), d['ledger_id'], d.get('relay_url',''), d.get('operator_name','unknown'))
" 2>/dev/null || true)
        [ -z "$parsed" ] && continue

        read -r opkey lid relay name <<< "$parsed"

        # Skip if we already have this ledger
        if echo "$seen_ledgers" | grep -q "$lid"; then
            continue
        fi
        seen_ledgers="$seen_ledgers $lid"

        LEDGER_IDS+=("$lid")
        LEDGER_RELAYS+=("${relay:-$RELAY_ALICE}")
        LEDGER_OPERATORS+=("$(echo "$name" | tr '[:upper:]' '[:lower:]')")
        log_info "  $name: ledger ${lid:0:16}... relay ${relay:-$RELAY_ALICE}"
    done <<< "$ads_json"

    if [ ${#LEDGER_IDS[@]} -eq 0 ]; then
        log_error "No ledgers found in advertisements — cannot set up agent"
        exit 1
    fi

    log_success "Found ${#LEDGER_IDS[@]} ledger(s)"

    # ── Open deposits ────────────────────────────────────────────────────────

    log_info ""
    log_info "=== Opening agent deposits ($AGENT_DEPOSIT_SATS sats each) ==="

    AGENT_DEPOSIT_MSATS=$((AGENT_DEPOSIT_SATS * 1000))

    for i in "${!LEDGER_IDS[@]}"; do
        lid="${LEDGER_IDS[$i]}"
        relay="${LEDGER_RELAYS[$i]}"
        operator="${LEDGER_OPERATORS[$i]}"

        # Skip if deposit already exists for this ledger
        if [ -f "$AGENT_DATA_DIR/deposits.json" ]; then
            already=$(python3 -c "
import json, sys
data = json.load(open('$AGENT_DATA_DIR/deposits.json'))
lid = sys.argv[1]
print(sum(1 for d in data if d.get('ledger_id','').startswith(lid[:16])))
" "$lid" 2>/dev/null || echo "0")
            if [ "$already" -gt 0 ]; then
                log_info "  Deposit already exists on ${lid:0:16}..., skipping"
                continue
            fi
        fi

        log_info "  Opening deposit on $operator (${lid:0:16}...)..."
        open_output=$(RUST_LOG=error "$DEPOSITS_WALLET" open \
            "$lid" "$AGENT_DEPOSIT_SATS" \
            --alias "agent-${lid:0:8}" --skip-cosign-verify \
            --seed "$AGENT_SEED" --network regtest \
            --relay "$relay" \
            --data-dir "$AGENT_DATA_DIR" 2>&1 || true)

        if echo "$open_output" | grep -q "created\|Fund with"; then
            log_success "  Deposit opened on $operator"
        else
            log_warn "  Deposit open may have failed on $operator"
            echo "    $open_output" | head -3
        fi
    done

    # ── Credit deposits via operators ──────────────────────────────────────

    log_info ""
    log_info "=== Crediting agent deposits ($AGENT_DEPOSIT_SATS sats each) ==="

    credits_ok=0
    for i in "${!LEDGER_IDS[@]}"; do
        lid="${LEDGER_IDS[$i]}"
        operator="${LEDGER_OPERATORS[$i]}"

        # Get deposit_pubkey for this ledger from agent's deposits.json
        deposit_pubkey=$(python3 -c "
import json, sys
data = json.load(open('$AGENT_DATA_DIR/deposits.json'))
lid = sys.argv[1]
for d in data:
    if d.get('ledger_id','').startswith(lid[:16]):
        print(d.get('deposit_pubkey',''))
        break
" "$lid" 2>/dev/null || echo "")

        if [ -z "$deposit_pubkey" ]; then
            log_warn "  No deposit_pubkey found for ${lid:0:16}..., skipping credit"
            continue
        fi

        log_info "  Crediting $AGENT_DEPOSIT_MSATS msats on $operator..."
        credit_output=$(run_node_cmd "$operator" deposit credit \
            "$lid" "$deposit_pubkey" "$AGENT_DEPOSIT_MSATS" "agent-setup-$(date +%s)" 2>&1 || true)

        if echo "$credit_output" | grep -q "credited\|New balance"; then
            new_bal=$(echo "$credit_output" | grep -oE '[0-9]+ msats' | tail -1)
            log_success "  $operator: credited ($new_bal)"
            credits_ok=$((credits_ok + 1))
        else
            log_warn "  $operator: credit may have failed"
            echo "    $credit_output" | head -3
        fi
    done

    if [ "$credits_ok" -ge "${#LEDGER_IDS[@]}" ]; then
        log_success "All $credits_ok deposits credited"
    else
        log_warn "Only $credits_ok/${#LEDGER_IDS[@]} deposits credited"
    fi

    # Update agent wallet balances
    log_info "Syncing agent wallet balances..."
    RUST_LOG=error "$DEPOSITS_WALLET" sync \
        --seed "$AGENT_SEED" --network regtest \
        --relay "$RELAY_ALICE" --relay "$RELAY_BOB" --relay "$RELAY_CHARLIE" --relay "$RELAY_DIANA" \
        --data-dir "$AGENT_DATA_DIR" 2>&1 || true
fi

# ── Start the agent ──────────────────────────────────────────────────────────

log_info "Starting HTLC agent..."
RUST_LOG=info "$HTLC_AGENT" \
    --relay "$RELAY_ALICE" \
    --ledgers-relay "$RELAY_LEDGERS" \
    --network regtest \
    --node "agent:$AGENT_DATA_DIR" \
    --margin-fixed 100 --margin-bps 10 \
    --timeout-margin 144 \
    --bitcoin-cli "docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass" \
    > "$AGENT_DATA_DIR/agent.log" 2>&1 &

agent_pid=$!
echo "$agent_pid" > "$AGENT_DATA_DIR/agent.pid"

# Quick health check — did it survive 2 seconds?
sleep 2
if kill -0 "$agent_pid" 2>/dev/null; then
    log_success "HTLC agent running (pid $agent_pid)"
else
    log_error "HTLC agent exited immediately — check $AGENT_DATA_DIR/agent.log"
    tail -5 "$AGENT_DATA_DIR/agent.log" 2>/dev/null || true
    exit 1
fi

echo ""
log_info "HTLC Agent:"
echo "  PID:      $agent_pid"
echo "  Log:      $AGENT_DATA_DIR/agent.log"
echo "  Data:     $AGENT_DATA_DIR"
echo "  Deposits: $(python3 -c "
import json
data = json.load(open('$AGENT_DATA_DIR/deposits.json'))
funded = [d for d in data if d.get('status') in ('completed', 'funded')]
print(f'{len(funded)} across {len(set(d[\"ledger_id\"] for d in funded))} ledgers')
" 2>/dev/null || echo "unknown")"
echo ""
log_success "Done!"
