#!/bin/bash
# Smoke test for the deposits-signer plumbing inside the Docker image.
#
# Validates that `deposits-tools/docker/entrypoint.sh`'s
# DEPOSITS_USE_SIGNER=1 path actually lights up inside the
# deposits-node container: spawns the signer, allowlists the daemon's
# transport pubkey, completes the handshake. The daemon's deeper
# behaviour (relay subscriptions, BDK wallet, etc.) is intentionally
# out of scope here — those need real bitcoin + relays + LDK.
#
# What this catches: regressions in the Dockerfile (missing
# deposits-signer binary, missing crate sources for the workspace
# build), regressions in the entrypoint's signer wiring (race
# conditions, env-var bugs, file-permission issues), regressions in
# the daemon's --signer-pubkey/--signer-socket plumbing inside an
# Alpine + musl runtime.
#
# What this DOES NOT catch: full protocol behaviour against
# signer-backed daemons. That's a separate cluster test with
# bitcoin-regtest + relays — see DEPOSITS_USE_SIGNER=1 ./bin/setup.sh
# for that path.
#
# Usage:
#   ./bin/test-signer-docker.sh
#
# Roughly 2-5 minutes for the cold Docker build; a few seconds for
# the actual smoke test once the image exists.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-deposits-node:test-signer}"
CONTAINER_NAME="deposits-test-signer-$$"
DATA_VOLUME="${CONTAINER_NAME}-data"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker volume rm "$DATA_VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/4] build deposits-node image"
docker build -f "$REPO_ROOT/deposits-node/Dockerfile" -t "$IMAGE_TAG" "$REPO_ROOT" >/dev/null

echo "[2/4] generate a deterministic seed"
SEED_FILE=$(mktemp)
trap "rm -f $SEED_FILE; cleanup" EXIT
echo "44444444444444444444444444444444444444444444444444444444444444cc" > "$SEED_FILE"
chmod 0600 "$SEED_FILE"

echo "[3/4] run container with DEPOSITS_USE_SIGNER=1"
# We expect the daemon to fail later when it can't reach bitcoin /
# relays, but the signer-handshake phase happens *before* that, so
# the entrypoint's signer-related output lands in the container logs.
# A 10s wait is plenty for the signer to come up + handshake to log.
docker run --name "$CONTAINER_NAME" -d \
    -e DEPOSITS_USE_SIGNER=1 \
    -e NETWORK=regtest \
    -e ELECTRUM_URL="http://192.0.2.1:9999" \
    -e LEDGER_RELAY="ws://192.0.2.1:9999" \
    -e NODE_NAME=test-signer \
    -e NODE_SEED_FILE=/secrets/seed \
    -v "$SEED_FILE:/secrets/seed:ro" \
    -v "$DATA_VOLUME:/data" \
    "$IMAGE_TAG" >/dev/null
sleep 10

echo "[4/4] inspect signer + daemon logs"
LOGS=$(docker logs "$CONTAINER_NAME" 2>&1 || true)
SIGNER_LOG=$(docker exec "$CONTAINER_NAME" cat /data/node/signer.log 2>/dev/null || echo "")

# Required: the entrypoint's signer-spawn line.
if ! echo "$LOGS" | grep -q "Signer:.*co-located"; then
    echo "FAIL: container logs missing the 'Signer: co-located ...' line:" >&2
    echo "$LOGS" >&2
    exit 1
fi

# Required: signer process logged a successful handshake (daemon's
# transport pubkey was allowlisted and verified).
if ! echo "$SIGNER_LOG" | grep -q "handshake ok with node"; then
    echo "FAIL: signer log missing 'handshake ok with node ...':" >&2
    echo "  signer.log:" >&2
    echo "$SIGNER_LOG" >&2
    echo "  container logs (tail):" >&2
    echo "$LOGS" | tail -30 >&2
    exit 1
fi

echo ""
echo "ok — Docker entrypoint signer wiring works."
echo "    container:   $CONTAINER_NAME"
echo "    image:       $IMAGE_TAG"
echo ""
echo "    co-located signer line from container logs:"
echo "$LOGS" | grep "Signer:.*co-located" | sed 's/^/      /'
echo ""
echo "    handshake from signer.log:"
echo "$SIGNER_LOG" | grep "handshake ok" | sed 's/^/      /'
echo ""
echo "next steps for full Docker cluster coverage:"
echo "  DEPOSITS_USE_SIGNER=1 docker compose -f deposits-tools/docker-compose.yml \\"
echo "                                       -f deposits-tools/docker/docker-compose.nodes.yml up -d"
