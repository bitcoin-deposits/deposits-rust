#!/bin/bash
# On-chain funds report for the deposits cluster.
#
# Shows for each node:
#   - Reserves UTXOs (taproot + legacy), amounts, quorum info
#   - Ledger obligations vs reserves
#   - Lightning channels and balances (if available)
#
# Usage:
#   ./funds-report.sh                    # All nodes
#   ./funds-report.sh alice bob          # Specific nodes
#   ./funds-report.sh --json             # JSON output
#   ./funds-report.sh --summary          # One-line per node

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="$SCRIPT_DIR/node-cli.sh"

# Auto-detect node list from $SEED_DIR (each subdirectory containing a `seed`
# file is a node). DEPOSITS_NODES env var overrides; the hardcoded fallback
# is the historical 4-op cluster names if neither is available.
SEED_DIR="${DEPOSITS_SEED_DIR:-/mnt/bitcoind/deposits}"
detect_nodes() {
    [ -d "$SEED_DIR" ] || return 0
    for d in "$SEED_DIR"/*/; do
        [ -f "$d/seed" ] && basename "$d"
    done | sort | tr '\n' ' ' | sed 's/ $//'
}
ALL_NODES="${DEPOSITS_NODES:-$(detect_nodes)}"
ALL_NODES="${ALL_NODES:-alice bob charlie diana}"
JSON_MODE=false
SUMMARY_MODE=false
NODES=()

for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --summary) SUMMARY_MODE=true ;;
        --help|-h)
            echo "Usage: $0 [--json|--summary] [node1 node2 ...]"
            exit 0 ;;
        *) NODES+=("$arg") ;;
    esac
done

[ ${#NODES[@]} -eq 0 ] && NODES=($ALL_NODES)

# Colors
R='\033[0m' B='\033[1m' G='\033[32m' Y='\033[33m' C='\033[36m' M='\033[35m' D='\033[2m'

# ── Helpers ──────────────────────────────────────────────────────────────────

fmt_sats() {
    local sats=$1
    if [ "$sats" -ge 100000000 ] 2>/dev/null; then
        python3 -c "print(f'{$sats/100_000_000:.8f} BTC')"
    elif [ "$sats" -ge 1000 ] 2>/dev/null; then
        python3 -c "s=$sats; print(f'{s:,} sat')"
    else
        echo "${sats} sat"
    fi
}

fmt_msats() {
    local msats=$1
    local sats=$((msats / 1000))
    fmt_sats "$sats"
}

# ── LDK Lightning helper ────────────────────────────────────────────────────

ldk_cli() {
    local network=$(docker exec lightning printenv NETWORK 2>/dev/null || echo "regtest")
    local api_key=$(docker exec lightning sh -c "cat /ldk/${network}/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null)
    docker exec lightning ldk-server-cli -b "localhost:3000" -a "$api_key" -t /ldk/tls.crt "$@" 2>/dev/null
}

report_lightning() {
    echo -e "\n${B}══════════════════════════════════════════${R}"
    echo -e "${B}  Lightning Node${R}  ${D}(container: lightning)${R}"
    echo -e "${B}══════════════════════════════════════════${R}"

    # Node info
    local ln_info=$(ldk_cli get-node-info 2>/dev/null || echo "")
    if [ -z "$ln_info" ]; then
        echo -e "  ${Y}Lightning node not reachable${R}"
        return
    fi

    local ln_pubkey=$(echo "$ln_info" | python3 -c "import json,sys; print(json.load(sys.stdin).get('node_id','?'))" 2>/dev/null || echo "?")
    echo -e "  Node ID: ${D}${ln_pubkey:0:20}...${R}"

    # Balances
    local balances=$(ldk_cli get-balances 2>/dev/null || echo "{}")
    local onchain=$(echo "$balances" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_onchain_balance_sats', d.get('spendable_onchain_balance_sats', 0)))" 2>/dev/null || echo 0)
    local spendable=$(echo "$balances" | python3 -c "import json,sys; print(json.load(sys.stdin).get('spendable_onchain_balance_sats',0))" 2>/dev/null || echo 0)
    local ln_total=$(echo "$balances" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_lightning_balance_sats',0))" 2>/dev/null || echo 0)
    local ln_outbound=$(echo "$balances" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('outbound_capacity_msat',0)//1000)" 2>/dev/null || echo 0)
    local ln_inbound=$(echo "$balances" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('inbound_capacity_msat',0)//1000)" 2>/dev/null || echo 0)

    echo -e "\n  ${B}Balances:${R}"
    echo -e "    On-chain total:    ${G}$(fmt_sats $onchain)${R}"
    echo -e "    On-chain spendable:${G}$(fmt_sats $spendable)${R}"
    echo -e "    Lightning total:   ${C}$(fmt_sats $ln_total)${R}"

    # Channels
    local channels=$(ldk_cli list-channels 2>/dev/null || echo "")
    local chan_list=$(echo "$channels" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    chans = data if isinstance(data, list) else data.get('channels', data.get('list', []))
    for c in chans:
        cid = c.get('channel_id', c.get('id', '?'))[:16]
        peer = c.get('counterparty_node_id', c.get('peer', '?'))[:16]
        cap = c.get('channel_value_sats', c.get('channel_value_satoshis', 0))
        bal = c.get('outbound_capacity_msat', c.get('balance_msat', 0)) // 1000
        ready = c.get('is_channel_ready', c.get('is_usable', False))
        status = 'ready' if ready else 'pending'
        print(f'{cid}  peer={peer}...  capacity={cap} sat  balance={bal} sat  [{status}]')
except:
    pass
" 2>/dev/null || echo "")

    if [ -n "$chan_list" ]; then
        echo -e "\n  ${B}Channels:${R}"
        echo "$chan_list" | while IFS= read -r line; do
            [ -n "$line" ] && echo -e "    ${line}"
        done
    else
        echo -e "\n  ${D}  No channels${R}"
    fi

    # Payments summary
    local payments=$(ldk_cli list-payments 2>/dev/null || echo "")
    local pay_summary=$(echo "$payments" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    pays = data.get('payments', data.get('list', []))
    ok = sum(1 for p in pays if p.get('status') in (1, 'SUCCEEDED'))
    pending = sum(1 for p in pays if p.get('status') in (0, 'PENDING'))
    failed = sum(1 for p in pays if p.get('status') in (2, 'FAILED'))
    total_ok = sum(p.get('amount_msat', 0) for p in pays if p.get('status') in (1, 'SUCCEEDED')) // 1000
    print(f'{len(pays)} total: {ok} succeeded ({total_ok} sat), {pending} pending, {failed} failed')
except:
    print('(unavailable)')
" 2>/dev/null || echo "(unavailable)")
    echo -e "\n  ${B}Payments:${R} ${pay_summary}"
}

# ── Per-node report ──────────────────────────────────────────────────────────

report_node() {
    local node="$1"

    # Get node info
    local info=$("$CLI" "$node" info 2>/dev/null || echo "")
    local node_id=$(echo "$info" | grep "Node ID:" | awk '{print $3}')
    local wallet_bal=$(echo "$info" | grep "Wallet balance:" | awk '{print $3}')

    if [ -z "$node_id" ]; then
        echo -e "${Y}$node: not reachable${R}"
        return
    fi

    local node_short="${node_id:0:16}..."

    # ── Summary mode ──
    if $SUMMARY_MODE; then
        # Get ledger summary
        local ledger_info=$("$CLI" "$node" ledger list 2>/dev/null || echo "")
        local num_ledgers=$(echo "$ledger_info" | grep -c "Operator)" || echo 0)
        local total_msats=$(echo "$ledger_info" | grep "msats balance" | awk '{print $NF}' | sed 's/msats//' | awk '{s+=$1}END{print s+0}')
        local total_reserves=$(echo "$ledger_info" | grep "Reserves:" | awk '{print $2}' | awk '{s+=$1}END{print s+0}')
        local total_sats=$((total_msats / 1000))
        printf "${B}%-10s${R} ${D}%s${R}  ${G}%d ledger(s)${R}  obligations: ${C}%s${R}  reserves: ${C}%s${R}  wallet: ${D}%s sat${R}\n" \
            "$node" "$node_short" "$num_ledgers" "$(fmt_sats $total_sats)" "$(fmt_sats $total_reserves)" "$wallet_bal"
        return
    fi

    # ── Full report ──
    echo -e "\n${B}══════════════════════════════════════════${R}"
    echo -e "${B}  $node${R}  ${D}$node_short${R}"
    echo -e "${B}══════════════════════════════════════════${R}"
    echo -e "  Wallet balance: ${C}$(fmt_sats ${wallet_bal:-0})${R}"

    # ── Reserves ──
    echo -e "\n  ${B}Reserves:${R}"
    local reserves=$("$CLI" "$node" reserves list 2>/dev/null || echo "")
    if echo "$reserves" | grep -q "Outpoint:"; then
        echo "$reserves" | while IFS= read -r line; do
            case "$line" in
                *Outpoint:*) echo -e "    ${M}${line}${R}" ;;
                *Amount:*) echo -e "    ${G}${line}${R}" ;;
                *Quorum*|*Members*) echo -e "    ${C}${line}${R}" ;;
                *Expiry*|*Timeout*) echo -e "    ${Y}${line}${R}" ;;
                *) echo "    $line" ;;
            esac
        done
    else
        echo -e "    ${D}(none)${R}"
    fi

    # ── Ledgers ──
    echo -e "\n  ${B}Ledgers:${R}"
    local ledgers=$("$CLI" "$node" ledger list 2>/dev/null || echo "")
    if echo "$ledgers" | grep -q "Ledger ID:"; then
        echo "$ledgers" | while IFS= read -r line; do
            case "$line" in
                *Operator\)*) echo -e "    ${G}${line}${R}" ;;
                *Partner\)*) echo -e "    ${C}${line}${R}" ;;
                *msats\ balance*) echo -e "    ${line}" ;;
                *Reserves:*) echo -e "    ${line}" ;;
                *) [ -n "$line" ] && echo "    $line" ;;
            esac
        done
    else
        echo -e "    ${D}(no ledgers)${R}"
    fi

    # ── Lightning ──
    echo -e "\n  ${B}Lightning:${R}"
    local ln_balance=$("$CLI" "$node" lightning balance 2>/dev/null || echo "")
    if echo "$ln_balance" | grep -q "balance\|sats"; then
        echo "$ln_balance" | while IFS= read -r line; do
            [ -n "$line" ] && echo -e "    ${line}"
        done
    else
        echo -e "    ${D}(not configured or unavailable)${R}"
    fi

    local ln_channels=$("$CLI" "$node" lightning channels 2>/dev/null || echo "")
    if echo "$ln_channels" | grep -q "channel\|Channel\|peer"; then
        echo -e "    ${B}Channels:${R}"
        echo "$ln_channels" | while IFS= read -r line; do
            [ -n "$line" ] && echo -e "      ${line}"
        done
    fi
}

# ── JSON mode ────────────────────────────────────────────────────────────────

report_json() {
    echo "["
    local first=true
    for node in "${NODES[@]}"; do
        $first || echo ","
        first=false

        local info=$("$CLI" "$node" info 2>/dev/null || echo "")
        local node_id=$(echo "$info" | grep "Node ID:" | awk '{print $3}')
        local wallet_bal=$(echo "$info" | grep "Wallet balance:" | awk '{print $3}')

        local ledger_info=$("$CLI" "$node" ledger list 2>/dev/null || echo "")
        local num_op=$(echo "$ledger_info" | grep -c "Operator)" || echo 0)
        local num_partner=$(echo "$ledger_info" | grep -c "Partner)" || echo 0)
        local total_msats=$(echo "$ledger_info" | grep "msats balance" | awk '{print $NF}' | sed 's/msats//' | awk '{s+=$1}END{print s+0}')
        local total_reserves=$(echo "$ledger_info" | grep "Reserves:" | awk '{print $2}' | awk '{s+=$1}END{print s+0}')

        cat <<EOF
  {
    "node": "$node",
    "node_id": "$node_id",
    "wallet_balance_sats": ${wallet_bal:-0},
    "operated_ledgers": $num_op,
    "partner_ledgers": $num_partner,
    "total_obligations_msats": $total_msats,
    "total_reserves_sats": $total_reserves
  }
EOF
    done
    echo "]"
}

# ── Main ─────────────────────────────────────────────────────────────────────

if $JSON_MODE; then
    report_json
    exit 0
fi

if $SUMMARY_MODE; then
    echo -e "${B}Node       ID                  Ledgers    Obligations          Reserves             Wallet${R}"
    echo    "────────── ──────────────────  ─────────  ───────────────────  ───────────────────  ────────────────"
fi

for node in "${NODES[@]}"; do
    report_node "$node"
done

# Lightning node report (unless summary or json mode)
if ! $SUMMARY_MODE && ! $JSON_MODE; then
    report_lightning
fi

if ! $SUMMARY_MODE; then
    echo ""
fi
