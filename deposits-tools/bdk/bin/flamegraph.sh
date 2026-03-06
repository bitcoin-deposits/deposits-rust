#!/bin/bash
# Capture a CPU flamegraph from a running deposits-bdk container
#
# Usage:
#   ./bin/flamegraph.sh [container] [seconds]
#   ./bin/flamegraph.sh                    # all 4 nodes, 30s each
#   ./bin/flamegraph.sh bdk-alice          # just Alice, 30s
#   ./bin/flamegraph.sh bdk-alice 60       # just Alice, 60s
#
# Output: flamegraph-*.svg and profile-*.pb files in ./flamegraphs/
#
# The .svg files can be opened in any browser (interactive — click to zoom).
# The .pb files can be loaded into:
#   - speedscope (https://www.speedscope.app) — drag & drop
#   - go tool pprof: go tool pprof -http=:8080 profile-*.pb

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$BDK_DIR/flamegraphs"

CONTAINER="${1:-all}"
SECONDS="${2:-30}"

mkdir -p "$OUT_DIR"

capture_flamegraph() {
    local container="$1"
    local secs="$2"

    echo "[$container] Sending SIGUSR1 — profiling for ${secs}s..."

    # Set profile duration via env if different from default
    if [ "$secs" != "30" ]; then
        docker exec "$container" sh -c "export DEPOSITS_PROFILE_SECONDS=$secs" 2>/dev/null || true
    fi

    # Trigger profiling
    docker kill -s SIGUSR1 "$container"

    # Wait for profiling to complete (plus a few seconds for file write)
    echo "[$container] Waiting ${secs}s for profile capture..."
    sleep $((secs + 3))

    # Copy output files
    local files_found=0
    for ext in svg pb; do
        for f in $(docker exec "$container" sh -c "ls /data/flamegraph-*.${ext} /data/profile-*.${ext} 2>/dev/null" 2>/dev/null); do
            local basename=$(basename "$f")
            local outfile="${OUT_DIR}/${container}-${basename}"
            docker cp "${container}:${f}" "$outfile" 2>/dev/null && {
                echo "[$container] Saved: $outfile"
                # Clean up inside container
                docker exec "$container" rm -f "$f" 2>/dev/null || true
                files_found=$((files_found + 1))
            }
        done
    done

    if [ "$files_found" -eq 0 ]; then
        echo "[$container] WARNING: No profile files found. Check container logs."
    fi
}

if [ "$CONTAINER" = "all" ]; then
    for node in bdk-alice bdk-bob bdk-charlie bdk-diana; do
        if docker ps --format '{{.Names}}' | grep -q "^${node}$"; then
            capture_flamegraph "$node" "$SECONDS"
        else
            echo "[$node] Not running, skipping"
        fi
    done
else
    capture_flamegraph "$CONTAINER" "$SECONDS"
fi

echo ""
echo "Flamegraphs saved to: $OUT_DIR/"
echo "  - .svg: Open in browser (interactive, click to zoom)"
echo "  - .pb:  Load in speedscope.app or 'go tool pprof -http=:8080 file.pb'"
