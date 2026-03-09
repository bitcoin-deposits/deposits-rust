#!/bin/bash
# Capture CPU profile from running deposits-bdk containers
#
# Uses pprof-rs (timer-based sampling at 99 Hz, works on Docker Desktop).
# SIGUSR1 triggers an immediate profile dump; auto-dumps also happen every 60s.
#
# Usage:
#   ./bin/flamegraph.sh                    # all 4 nodes
#   ./bin/flamegraph.sh bdk-alice          # just Alice
#
# Output: flamegraphs/<container>-profile.{collapsed,pb}
#   - .collapsed: Load in speedscope (https://www.speedscope.app) — drag & drop
#     Or pipe through flamegraph.pl: cat profile.collapsed | flamegraph.pl > out.svg
#   - .pb: Load with `go tool pprof` or pprof web UI

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$BDK_DIR/flamegraphs"

CONTAINER="${1:-all}"

mkdir -p "$OUT_DIR"

capture_profile() {
    local container="$1"

    echo "[$container] Sending SIGUSR1 to flush profile..."
    docker kill -s SIGUSR1 "$container" >/dev/null 2>&1

    # Wait for dump to complete
    sleep 2

    # Check if container is still alive
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "[$container] ERROR: Container died after SIGUSR1"
        return 1
    fi

    # Copy collapsed stacks
    local outfile="${OUT_DIR}/${container}-profile.collapsed"
    if docker cp "${container}:/data/profile-latest.collapsed" "$outfile" 2>/dev/null; then
        local samples=$(wc -l < "$outfile" 2>/dev/null || echo 0)
        echo "[$container] Saved: $outfile ($samples stacks)"
    else
        echo "[$container] No profile data yet (profiler may still be collecting)"
    fi

    # Copy protobuf profile
    local pbfile="${OUT_DIR}/${container}-profile.pb"
    if docker cp "${container}:/data/profile-latest.pb" "$pbfile" 2>/dev/null; then
        local size=$(wc -c < "$pbfile" 2>/dev/null || echo 0)
        echo "[$container] Saved: $pbfile (${size} bytes)"
    fi
}

if [ "$CONTAINER" = "all" ]; then
    for node in bdk-alice bdk-bob bdk-charlie bdk-diana; do
        if docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
            capture_profile "$node"
        else
            echo "[$node] Not running, skipping"
        fi
    done
else
    capture_profile "$CONTAINER"
fi

echo ""
echo "Profiles saved to: $OUT_DIR/"
echo "  View: Load .collapsed files in speedscope.app (drag & drop)"
echo "  CLI:  cat file.collapsed | flamegraph.pl > out.svg"
echo "  Go:   go tool pprof -http=:8080 file.pb"
