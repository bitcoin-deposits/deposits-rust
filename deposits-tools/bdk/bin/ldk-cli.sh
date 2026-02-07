#!/bin/bash
#
# Wrapper for ldk-server-cli for BDK Lightning nodes
#
# Usage: ./bin/ldk-cli.sh <node> <command> [args...]
#   e.g.: ./bin/ldk-cli.sh alice get-node-info
#         ./bin/ldk-cli.sh bob list-channels

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BDK_DIR="$(dirname "$SCRIPT_DIR")"

NODE="$1"
shift

if [ -z "$NODE" ]; then
    echo "Usage: $0 <node> <command> [args...]"
    echo "  e.g.: $0 alice get-node-info"
    echo "        $0 bob list-channels"
    exit 1
fi

# Map node name to port (BDK Lightning network ports)
case "$NODE" in
    alice)   PORT=3111 ;;
    bob)     PORT=3112 ;;
    *)
        echo "Unknown node: $NODE"
        echo "Valid nodes: alice, bob"
        exit 1
        ;;
esac

CERT="$BDK_DIR/certs/${NODE}.crt"
if [ ! -f "$CERT" ]; then
    echo "TLS cert not found: $CERT"
    echo "Run reinit-lightning.sh to set up the environment"
    exit 1
fi

# Find ldk-server-cli
CLI="${LDK_SERVER_CLI:-$HOME/workspace/ldk-server/target/debug/ldk-server-cli}"
if [ ! -x "$CLI" ]; then
    CLI="$HOME/workspace/ldk-server/target/release/ldk-server-cli"
fi
if [ ! -x "$CLI" ]; then
    echo "ldk-server-cli not found. Build it with: cd ~/workspace/ldk-server && cargo build --bin ldk-server-cli"
    exit 1
fi

exec "$CLI" -b "localhost:$PORT" -a test_api_key -t "$CERT" "$@"
