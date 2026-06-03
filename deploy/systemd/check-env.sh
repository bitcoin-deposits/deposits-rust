#!/bin/bash
# Pre-flight sanity check on /etc/deposits/deposits-node.env.
#
# `make start` runs this first. The daemon won't refuse to start on
# placeholder values — it just crashes later when it tries to read a
# nonexistent macaroon or connect to nothing — so catching the
# common gotchas up front beats the journalctl detective work.
#
# Two severity levels:
#   FATAL — start would fail; exit 1
#   WARN  — start may succeed but look suspicious; print + continue
#
# Override the env path with ENV_FILE=/some/other/file ./check-env.sh.

set -u

ENV_FILE="${ENV_FILE:-/etc/deposits/deposits-node.env}"

RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; GREEN=$'\033[0;32m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

fatals=()
warns=()
oks=()
fatal() { fatals+=("$1"); }
warn()  { warns+=("$1");  }
ok()    { oks+=("$1");    }

# Step 1: file exists + readable
if [ ! -f "$ENV_FILE" ]; then
    echo "${RED}FATAL${RESET} $ENV_FILE does not exist. Run: make bootstrap" >&2
    exit 1
fi

# Source under `set -u` is awkward (the file may reference unset vars).
# Just regex out KEY=VALUE lines.
get() { awk -F= -v k="$1" '$1==k { sub(/^[^=]*=/, ""); print }' "$ENV_FILE" | tail -n1; }

NETWORK=$(get NETWORK)
OPERATOR_NAME=$(get OPERATOR_NAME)
RELAY_LEDGERS=$(get RELAY_LEDGERS)
SIGNER_PUBKEY=$(get SIGNER_PUBKEY)
LIGHTNING_BACKEND=$(get LIGHTNING_BACKEND)
CHAIN_BACKEND=$(get CHAIN_BACKEND)

# --- required for the wrapper to run at all ---

case "$NETWORK" in
    bitcoin|testnet|signet|regtest) ok "NETWORK=$NETWORK" ;;
    "") fatal "NETWORK is empty (one of: bitcoin, testnet, signet, regtest)" ;;
    *) fatal "NETWORK=$NETWORK is not a recognised network" ;;
esac

if [ -z "$OPERATOR_NAME" ]; then
    fatal "OPERATOR_NAME is empty"
elif [ "$OPERATOR_NAME" = "operator" ]; then
    warn "OPERATOR_NAME=operator (template default — appears in advertisements; pick something recognisable)"
else
    ok "OPERATOR_NAME=$OPERATOR_NAME"
fi

if [ -z "$RELAY_LEDGERS" ]; then
    fatal "RELAY_LEDGERS is empty (needs wss:// or ws:// URL)"
elif [[ ! "$RELAY_LEDGERS" =~ ^wss?:// ]]; then
    fatal "RELAY_LEDGERS=$RELAY_LEDGERS does not look like a wss:// or ws:// URL"
else
    ok "RELAY_LEDGERS=$RELAY_LEDGERS"
fi

if [ -z "$SIGNER_PUBKEY" ]; then
    fatal "SIGNER_PUBKEY is empty (re-run: make bootstrap)"
elif [[ ! "$SIGNER_PUBKEY" =~ ^0[23][0-9a-fA-F]{64}$ ]]; then
    fatal "SIGNER_PUBKEY=$SIGNER_PUBKEY is not a 33-byte compressed secp256k1 pubkey (66 hex starting with 02 or 03)"
else
    ok "SIGNER_PUBKEY set"
fi

# --- Lightning backend ---

case "$LIGHTNING_BACKEND" in
    lnd)
        mac_hex=$(get LND_MACAROON_HEX)
        mac_file=$(get LND_MACAROON_FILE)
        rest_url=$(get LND_REST_URL)
        [ -n "$rest_url" ] || fatal "LIGHTNING_BACKEND=lnd but LND_REST_URL is empty"
        if [ -n "$mac_hex" ]; then
            ok "LND macaroon supplied inline (HEX)"
        elif [ -n "$mac_file" ]; then
            if [ ! -r "$mac_file" ]; then
                fatal "LND_MACAROON_FILE=$mac_file unreadable by current user (try: sudo -u deposits cat $mac_file). If the file exists, add the 'deposits' user to the lnd group: sudo usermod -a -G lnd deposits && make restart"
            else
                ok "LND macaroon file readable: $mac_file"
            fi
        else
            fatal "LIGHTNING_BACKEND=lnd but neither LND_MACAROON_HEX nor LND_MACAROON_FILE is set"
        fi
        tls=$(get LND_TLS_CERT_FILE)
        if [ -n "$tls" ] && [ ! -r "$tls" ]; then
            warn "LND_TLS_CERT_FILE=$tls unreadable (will fail TLS handshake)"
        fi
        ;;
    cln)
        sock=$(get CLN_SOCKET_PATH)
        [ -n "$sock" ] || fatal "LIGHTNING_BACKEND=cln but CLN_SOCKET_PATH is empty"
        if [ -n "$sock" ] && [ ! -S "$sock" ]; then
            fatal "CLN_SOCKET_PATH=$sock is not a Unix socket (or unreadable). Add 'deposits' to the lightning group: sudo usermod -a -G lightning deposits && make restart"
        elif [ -S "$sock" ]; then
            ok "CLN socket exists: $sock"
        fi
        ;;
    ldk)
        host=$(get LDK_HOST); port=$(get LDK_PORT)
        if [ -z "$host" ] || [ -z "$port" ]; then
            fatal "LIGHTNING_BACKEND=ldk but LDK_HOST/LDK_PORT are not both set"
        else
            ok "LDK_HOST=$host LDK_PORT=$port"
        fi
        ;;
    "") fatal "LIGHTNING_BACKEND is empty (one of: lnd, cln, ldk)" ;;
    *) fatal "LIGHTNING_BACKEND=$LIGHTNING_BACKEND is not a known backend" ;;
esac

# --- Chain backend ---

case "$CHAIN_BACKEND" in
    bitcoind)
        rpc_url=$(get BITCOIND_RPC_URL)
        cookie=$(get BITCOIND_COOKIE_FILE)
        user=$(get BITCOIND_RPC_USER)
        pass=$(get BITCOIND_RPC_PASS)
        [ -n "$rpc_url" ] || fatal "CHAIN_BACKEND=bitcoind but BITCOIND_RPC_URL is empty"
        if [ -n "$cookie" ]; then
            if [ ! -r "$cookie" ]; then
                fatal "BITCOIND_COOKIE_FILE=$cookie unreadable (sudo -u deposits cat $cookie). If the file exists, add 'deposits' to the bitcoin group: sudo usermod -a -G bitcoin deposits && make restart"
            else
                ok "bitcoind cookie readable: $cookie"
            fi
        elif [ -n "$user" ] && [ -n "$pass" ]; then
            ok "bitcoind RPC user+pass set"
        else
            fatal "CHAIN_BACKEND=bitcoind needs either BITCOIND_COOKIE_FILE (preferred) or BITCOIND_RPC_USER + BITCOIND_RPC_PASS"
        fi
        ;;
    esplora)
        url=$(get ESPLORA_URL)
        if [ -z "$url" ]; then
            fatal "CHAIN_BACKEND=esplora but ESPLORA_URL is empty"
        elif [[ "$url" =~ blockstream\.info ]] && [ "$NETWORK" = "bitcoin" ]; then
            warn "ESPLORA_URL=$url trusts blockstream.info for mainnet chain queries — consider running your own electrs"
        else
            ok "ESPLORA_URL=$url"
        fi
        ;;
    electrum)
        host=$(get ELECTRUM_HOST); port=$(get ELECTRUM_PORT)
        if [ -z "$host" ] || [ -z "$port" ]; then
            fatal "CHAIN_BACKEND=electrum but ELECTRUM_HOST/ELECTRUM_PORT are not both set"
        else
            ok "ELECTRUM_HOST=$host:$port"
        fi
        ;;
    "") fatal "CHAIN_BACKEND is empty (one of: bitcoind, esplora, electrum)" ;;
    *) fatal "CHAIN_BACKEND=$CHAIN_BACKEND is not a known backend" ;;
esac

# --- Report -----------------------------------------------------------

echo "${BOLD}env check: $ENV_FILE${RESET}"
for line in "${oks[@]}"; do
    echo "  ${GREEN}ok${RESET}    $line"
done
for line in "${warns[@]}"; do
    echo "  ${YELLOW}warn${RESET}  $line"
done
for line in "${fatals[@]}"; do
    echo "  ${RED}fatal${RESET} $line" >&2
done

if [ ${#fatals[@]} -gt 0 ]; then
    echo >&2
    echo "${RED}${BOLD}refusing to start: ${#fatals[@]} fatal issue(s) above${RESET}" >&2
    echo "edit $ENV_FILE and try again" >&2
    exit 1
fi
echo
echo "${GREEN}${BOLD}env check passed${RESET}${YELLOW}${BOLD}${WARN_LABEL:-}${RESET} — safe to start"
exit 0
