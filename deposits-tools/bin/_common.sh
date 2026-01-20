# Common functions for deposits-tools scripts
# Source this file: . ./bin/_common.sh

# Run cargo with warnings suppressed (warnings go to stderr)
cargo_quiet() {
    cargo "$@" 2>/dev/null
}

# Get the network from config file or argument
# Usage: get_network [optional_arg]
#   If optional_arg is provided and non-empty, use it
#   Otherwise read from .network config file
get_network() {
    local arg="${1:-}"

    if [ -n "$arg" ]; then
        echo "$arg"
        return 0
    fi

    if [ -f ".network" ]; then
        cat ".network"
        return 0
    fi

    echo "ERROR: No network specified and no .network config file found." >&2
    echo "Either pass network as argument or run: ./bin/use-network.sh <regtest|mutinynet>" >&2
    return 1
}

# Validate network value
validate_network() {
    local network="$1"
    case "$network" in
        regtest|mutinynet)
            return 0
            ;;
        *)
            echo "ERROR: Unknown network '$network'. Valid networks: regtest, mutinynet" >&2
            return 1
            ;;
    esac
}

# Get relay URL for network
get_relay_url() {
    local network="$1"
    case "$network" in
        regtest)   echo "ws://localhost:7777" ;;
        mutinynet) echo "ws://localhost:7777" ;;
        *)
            echo "ERROR: Unknown network '$network'" >&2
            return 1
            ;;
    esac
}

# Get docker-compose file for network
get_compose_file() {
    local network="$1"
    case "$network" in
        regtest)   echo "docker-compose-deposits.yml" ;;
        mutinynet) echo "docker-compose-mutinynet.yml" ;;
        *)
            echo "ERROR: Unknown network '$network'" >&2
            return 1
            ;;
    esac
}

# API key for LDK server authentication
LDK_API_KEY="test_api_key"

# Generate HMAC-SHA256 auth header for LDK server
# Usage: ldk_auth_header [body]
#   body: optional request body (empty string for GET/empty POST)
# Returns: "HMAC <timestamp>:<hmac_hex>"
ldk_auth_header() {
    local body="${1:-}"
    local timestamp=$(date +%s)

    # Compute HMAC: HMAC-SHA256(key, timestamp_be_bytes || body)
    # timestamp is 8 bytes big-endian
    local timestamp_hex=$(printf '%016x' "$timestamp")
    local body_hex=$(printf '%s' "$body" | xxd -p | tr -d '\n')
    local data_hex="${timestamp_hex}${body_hex}"

    local hmac=$(echo -n "$data_hex" | xxd -r -p | openssl dgst -sha256 -hmac "$LDK_API_KEY" -binary | xxd -p | tr -d '\n')

    echo "HMAC ${timestamp}:${hmac}"
}

# Make authenticated HTTPS request to LDK server
# Usage: ldk_curl <port> <method> <endpoint> [body]
# Returns: response body
ldk_curl() {
    local port="$1"
    local method="$2"
    local endpoint="$3"
    local body="${4:-}"

    local auth_header=$(ldk_auth_header "$body")

    if [ -n "$body" ]; then
        curl -s -k -X "$method" \
            -H "X-Auth: $auth_header" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "https://localhost:${port}${endpoint}"
    else
        curl -s -k -X "$method" \
            -H "X-Auth: $auth_header" \
            "https://localhost:${port}${endpoint}"
    fi
}

# Copy TLS certificates from LDK containers to local certs/ directory
# Usage: copy_tls_certs [container_names...]
#   If no containers specified, copies from alice, bob, charlie
copy_tls_certs() {
    local containers=("${@:-alice bob charlie}")
    local certs_dir="certs"

    mkdir -p "$certs_dir"

    for node in "${containers[@]}"; do
        local container="ldk-${node}"
        if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            if docker cp "${container}:/ldk/tls.crt" "${certs_dir}/${node}.crt" 2>/dev/null; then
                echo "  📜 Copied TLS cert for ${node}"
            else
                echo "  ⚠️  Could not copy TLS cert for ${node}" >&2
            fi
        fi
    done
}
