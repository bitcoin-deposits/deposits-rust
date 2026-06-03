#!/usr/bin/env bash
#
# deposits-node operator setup wizard. Per PACKAGING_PLAN.md Tier 2.
#
# Interactive prompts walk you through:
#   1. operator seed (generate or import)
#   2. Lightning backend choice + per-backend config
#   3. Chain backend choice + per-backend config
#   4. nostr relay URLs
#   5. signer init: generate the signer's transport keypair, allowlist
#      the daemon, write SIGNER_PUBKEY back to .env
#
# Idempotent — safe to re-run. Already-set values in .env are kept as
# the default for each prompt.
#
# Acceptance (per PACKAGING_PLAN.md Tier 2): a clean Ubuntu VPS with
# bitcoind + LND already running can install and bring up an operator
# in 5 minutes following README.md and running this script.

set -euo pipefail

cd "$(dirname "$0")"

# --- styling --------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    RED=$'\033[31m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
else
    BOLD=; DIM=; GREEN=; YELLOW=; RED=; BLUE=; RESET=
fi

heading() { printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
ok()      { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()    { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$1"; }
err()     { printf '%s✘%s %s\n' "$RED" "$RESET" "$1" >&2; }

# --- env-file helpers -----------------------------------------------------

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ ! -f "$EXAMPLE_FILE" ]; then
        err "$EXAMPLE_FILE missing. Are you in deploy/operator/?"
        exit 1
    fi
    cp "$EXAMPLE_FILE" "$ENV_FILE"
    ok "Created $ENV_FILE from $EXAMPLE_FILE"
fi

# Read a key from .env (returns empty string if absent or commented out).
env_get() {
    local key=$1
    awk -F= -v k="$key" '
        $0 ~ "^"k"=" {
            sub("^"k"=", "");
            # Strip surrounding quotes if present.
            gsub(/^"|"$/, "");
            print;
            exit;
        }' "$ENV_FILE"
}

# Set or replace a key in .env. Idempotent.
env_set() {
    local key=$1
    local value=$2
    # Escape any & or | in value for sed RHS.
    local esc
    esc=$(printf '%s' "$value" | sed -e 's/[\/&]/\\&/g')
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${esc}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

# Prompt with a default (current value in .env, or fallback).
prompt() {
    local key=$1
    local question=$2
    local fallback=${3:-}
    local current
    current=$(env_get "$key")
    local default="${current:-$fallback}"
    local label="$question"
    if [ -n "$default" ]; then
        label="$question [${default}]"
    fi
    printf '  %s: ' "$label" >&2
    local input
    IFS= read -r input
    if [ -z "$input" ]; then
        input="$default"
    fi
    printf '%s' "$input"
}

prompt_choice() {
    local question=$1
    shift
    local options=("$@")
    printf '  %s\n' "$question" >&2
    local i=1
    for opt in "${options[@]}"; do
        printf '    [%d] %s\n' "$i" "$opt" >&2
        i=$((i+1))
    done
    while :; do
        printf '  > ' >&2
        local n
        IFS= read -r n
        if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "${#options[@]}" ]; then
            printf '%s' "${options[$((n-1))]}"
            return
        fi
        err "Please enter a number 1-${#options[@]}"
    done
}

# --- preflight ------------------------------------------------------------

heading "deposits-node operator setup"
echo "${DIM}This wizard fills in .env and bootstraps the signer keys.${RESET}"
echo "${DIM}Safe to re-run; existing values in .env become the defaults.${RESET}"

# Find the deposits-signer binary. Prefer one in PATH; fall back to a
# repo-local release build.
SIGNER_BIN=""
if command -v deposits-signer >/dev/null 2>&1; then
    SIGNER_BIN=$(command -v deposits-signer)
elif [ -x "../../target/release/deposits-signer" ]; then
    SIGNER_BIN="$(cd ../.. && pwd)/target/release/deposits-signer"
fi
if [ -z "$SIGNER_BIN" ]; then
    err "deposits-signer not found. Build it first:"
    err "  (from repo root) cargo build --release --bin deposits-signer"
    exit 1
fi

NODE_BIN=""
if command -v deposits-node >/dev/null 2>&1; then
    NODE_BIN=$(command -v deposits-node)
elif [ -x "../../target/release/deposits-node" ]; then
    NODE_BIN="$(cd ../.. && pwd)/target/release/deposits-node"
fi
if [ -z "$NODE_BIN" ]; then
    err "deposits-node not found. Build it first:"
    err "  (from repo root) cargo build --release --bin deposits-node"
    exit 1
fi

# Data directories for the signer + node. The compose volumes are
# named volumes, but the wizard runs the binaries from the host, so it
# needs host paths. Put them next to the compose file.
SIGNER_DATA_DIR="./signer-data"
NODE_DATA_DIR="./node-data"
mkdir -p "$SIGNER_DATA_DIR" "$NODE_DATA_DIR"

# --- 1. Network -----------------------------------------------------------

heading "Step 1/5: Network"
network=$(prompt NETWORK "Bitcoin network (bitcoin|testnet|signet|regtest)" "bitcoin")
env_set NETWORK "$network"

operator_name=$(prompt OPERATOR_NAME "Operator name (shown in advertisements)" "operator")
env_set OPERATOR_NAME "$operator_name"

# --- 2. Lightning backend -------------------------------------------------

heading "Step 2/5: Lightning backend"
ln_choice=$(prompt_choice "Which Lightning daemon?" "ldk" "lnd" "cln")
env_set LIGHTNING_BACKEND "$ln_choice"

case "$ln_choice" in
    ldk)
        echo "  ${DIM}LDK config — these are the host:port of ldk-server.${RESET}"
        env_set LDK_HOST     "$(prompt LDK_HOST "LDK host" "localhost")"
        env_set LDK_PORT     "$(prompt LDK_PORT "LDK port" "3000")"
        env_set LDK_API_KEY  "$(prompt LDK_API_KEY "LDK API key (hex)" "")"
        env_set LDK_TLS_CERT "$(prompt LDK_TLS_CERT "LDK TLS cert path (in container)" "")"
        ;;
    lnd)
        echo "  ${DIM}LND config — REST endpoint + macaroon auth.${RESET}"
        env_set LND_REST_URL       "$(prompt LND_REST_URL "LND REST URL" "https://127.0.0.1:8080")"
        auth_choice=$(prompt_choice "Macaroon auth method?" "inline hex (LND_MACAROON_HEX)" "file path (LND_MACAROON_FILE)")
        case "$auth_choice" in
            "inline hex"*)
                env_set LND_MACAROON_HEX "$(prompt LND_MACAROON_HEX "Admin macaroon (hex)" "")"
                env_set LND_MACAROON_FILE ""
                ;;
            "file path"*)
                env_set LND_MACAROON_FILE "$(prompt LND_MACAROON_FILE "Macaroon file path (in container)" "/run/secrets/lnd-admin.macaroon")"
                env_set LND_MACAROON_HEX ""
                warn "Mount the macaroon file into the container via docker-compose.override.yml (see README)."
                ;;
        esac
        env_set LND_TLS_CERT_FILE  "$(prompt LND_TLS_CERT_FILE "LND TLS cert path (in container)" "/run/secrets/lnd-tls.cert")"
        warn "Mount the TLS cert into the container via docker-compose.override.yml (see README)."
        ;;
    cln)
        echo "  ${DIM}CLN config — Unix socket path (must be bind-mounted into the container).${RESET}"
        env_set CLN_SOCKET_PATH "$(prompt CLN_SOCKET_PATH "Socket path (in container)" "/run/cln/lightning-rpc")"
        warn "Mount the CLN lightning-rpc socket into the container via docker-compose.override.yml (see README)."
        ;;
esac

# --- 3. Chain backend -----------------------------------------------------

heading "Step 3/5: Chain backend"
chain_choice=$(prompt_choice "Which chain data source?" "esplora" "bitcoind" "electrum")
env_set CHAIN_BACKEND "$chain_choice"

case "$chain_choice" in
    esplora)
        env_set ESPLORA_URL "$(prompt ESPLORA_URL "Esplora HTTP URL" "https://blockstream.info/api")"
        ;;
    bitcoind)
        env_set BITCOIND_RPC_URL "$(prompt BITCOIND_RPC_URL "bitcoind RPC URL" "http://127.0.0.1:8332")"
        auth_choice=$(prompt_choice "bitcoind auth method?" "user+pass" "cookie file")
        case "$auth_choice" in
            "user+pass")
                env_set BITCOIND_RPC_USER "$(prompt BITCOIND_RPC_USER "RPC user" "")"
                env_set BITCOIND_RPC_PASS "$(prompt BITCOIND_RPC_PASS "RPC pass" "")"
                env_set BITCOIND_COOKIE_FILE ""
                ;;
            "cookie file")
                env_set BITCOIND_COOKIE_FILE "$(prompt BITCOIND_COOKIE_FILE "Cookie file path (in container)" "/run/secrets/bitcoin-cookie")"
                env_set BITCOIND_RPC_USER ""
                env_set BITCOIND_RPC_PASS ""
                warn "Mount the cookie file into the container via docker-compose.override.yml (see README)."
                ;;
        esac
        ;;
    electrum)
        env_set ELECTRUM_HOST "$(prompt ELECTRUM_HOST "Electrum host" "127.0.0.1")"
        env_set ELECTRUM_PORT "$(prompt ELECTRUM_PORT "Electrum port" "50001")"
        ;;
esac

# --- 4. Relays ------------------------------------------------------------

heading "Step 4/5: Nostr relays"
env_set RELAY_LEDGERS   "$(prompt RELAY_LEDGERS   "Durable ledger relay (wss://)" "wss://relay.bitcoindeposits.net")"
env_set RELAY_MESSAGING "$(prompt RELAY_MESSAGING "Messaging relay (optional)" "")"

# --- 5. Seed + signer init -----------------------------------------------

heading "Step 5/5: Operator seed + signer bootstrap"

# Stage the seed in a host-tmp file. NOT inside $SIGNER_DATA_DIR —
# `deposits-signer init --seed-file` writes the seed to its own
# canonical path ($SIGNER_DATA_DIR/seed), so a collision means the
# post-init `rm` removes the seed the signer just placed (the
# signer's `run` then errors with "seed not installed").
seed_file_path="$(mktemp -p "${TMPDIR:-/tmp}" deposits-seed-XXXXXX)"
chmod 0600 "$seed_file_path"
if [ -f "$SIGNER_DATA_DIR/transport_secret" ]; then
    ok "Signer already initialized at $SIGNER_DATA_DIR (skipping)"
    rm -f "$seed_file_path"
else
    seed_choice=$(prompt_choice "Operator seed source?" "generate a new one (will print once)" "import from a file")
    case "$seed_choice" in
        "generate"*)
            # 32 bytes hex via /dev/urandom — same entropy source the
            # rest of the daemon uses for nonces.
            head -c 32 /dev/urandom | xxd -p -c 64 > "$seed_file_path"
            chmod 0600 "$seed_file_path"
            ok "Generated 32-byte seed at $seed_file_path"
            warn "BACK THIS UP NOW. There is no recovery if you lose it."
            echo "  ${BOLD}Seed (hex):${RESET} $(cat "$seed_file_path")"
            ;;
        "import"*)
            src=$(prompt _SEED_IMPORT_SRC "Path to existing 32-byte hex seed file" "")
            if [ ! -f "$src" ]; then
                err "Not a file: $src"
                exit 1
            fi
            cp "$src" "$seed_file_path"
            chmod 0600 "$seed_file_path"
            ok "Imported seed to $seed_file_path"
            ;;
    esac

    # Initialise the signer.
    echo "  Running deposits-signer init..."
    "$SIGNER_BIN" init --data-dir "$SIGNER_DATA_DIR" --seed-file "$seed_file_path" >/dev/null
    # Remove the host-side seed file once the signer has copied it into
    # its own data-dir; reduces the blast radius if someone wanders into
    # the deploy/operator directory.
    rm -f "$seed_file_path"
    ok "Signer initialized; seed material lives only in $SIGNER_DATA_DIR/seed"
fi

signer_pubkey=$("$SIGNER_BIN" pubkey --data-dir "$SIGNER_DATA_DIR" | tr -d '\n')
ok "Signer transport pubkey: ${BOLD}$signer_pubkey${RESET}"
env_set SIGNER_PUBKEY "$signer_pubkey"

# Get the daemon's transport pubkey and trust-add it. Idempotent.
node_pubkey=$("$NODE_BIN" transport-pubkey --data-dir "$NODE_DATA_DIR" | tr -d '\n')
ok "Daemon transport pubkey: ${BOLD}$node_pubkey${RESET}"
"$SIGNER_BIN" trust add --data-dir "$SIGNER_DATA_DIR" "$node_pubkey" >/dev/null 2>&1 || true
ok "Daemon allowlisted on signer"

# --- done -----------------------------------------------------------------

heading "Setup complete"
cat <<EOF

Configuration written to: $(pwd)/.env
Signer data dir:          $(pwd)/$SIGNER_DATA_DIR
Daemon data dir:          $(pwd)/$NODE_DATA_DIR

Before bringing up the cluster, make sure these are mounted into the
deposits-node container if applicable (edit docker-compose.override.yml):
  - LND macaroon / TLS cert  (LIGHTNING_BACKEND=lnd)
  - CLN lightning-rpc socket (LIGHTNING_BACKEND=cln)
  - bitcoind cookie file     (CHAIN_BACKEND=bitcoind + cookie auth)

Start the operator:
  ${BOLD}docker compose up -d${RESET}

Tail logs:
  ${BOLD}docker compose logs -f deposits-node${RESET}

Stop:
  ${BOLD}docker compose down${RESET}

See ./README.md for the full reference.
EOF
