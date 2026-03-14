#!/bin/bash
#
# Wrapper for ldk-server-cli for Lightning sidecar nodes
#
# Usage: ./bin/ldk-cli.sh <node> <command> [args...]
#   e.g.: ./bin/ldk-cli.sh alice get-node-info
#         ./bin/ldk-cli.sh bob list-channels

NODE="$1"
shift

if [ -z "$NODE" ]; then
    echo "Usage: $0 <node> <command> [args...]"
    echo "  e.g.: $0 alice get-node-info"
    echo "        $0 bob list-channels"
    exit 1
fi

case "$NODE" in
    alice|bob|charlie|diana) ;;
    *)
        echo "Unknown node: $NODE"
        echo "Valid nodes: alice, bob, charlie, diana"
        exit 1
        ;;
esac

# Run ldk-server-cli inside the container (talks to localhost:3000 with local TLS cert)
exec docker exec "${NODE}-ln" ldk-server-cli -b "localhost:3000" -a test_api_key -t /ldk/tls.crt "$@"
