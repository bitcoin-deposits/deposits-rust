#!/bin/bash
#
# Wrapper for ldk-server-cli — talks to the shared lightning container
#
# Usage: ./bin/ldk-cli.sh [node] <command> [args...]
#   e.g.: ./bin/ldk-cli.sh get-node-info
#         ./bin/ldk-cli.sh list-channels
#
# The node argument (alice/bob/etc) is accepted for backward compatibility
# but ignored — all operators share a single lightning node.

# Skip node arg if it looks like an operator name
case "${1:-}" in
    alice|bob|charlie|diana) shift ;;
esac

if [ -z "$1" ]; then
    echo "Usage: $0 [node] <command> [args...]"
    echo "  e.g.: $0 get-node-info"
    echo "        $0 list-channels"
    exit 1
fi

NETWORK=$(docker exec lightning printenv NETWORK 2>/dev/null || echo "regtest")
API_KEY=$(docker exec lightning sh -c "cat /ldk/${NETWORK}/api_key | od -A n -t x1 | tr -d ' \n'" 2>/dev/null)

exec docker exec lightning ldk-server-cli -b "localhost:3000" -a "$API_KEY" -t /ldk/tls.crt "$@"
