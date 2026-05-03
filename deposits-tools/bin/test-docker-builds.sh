#!/bin/bash
# Acceptance test: every Dockerfile in the repo's main service set
# builds cleanly. Catches the class of bug where a workspace member
# is added but the Dockerfiles never get the corresponding `COPY`
# or stub directive — cargo refuses to load the manifest and the
# build fails mid-Step.
#
# Skipped:
#   - deposits-tools/Dockerfile.ldk-node    requires the ldk-server
#                                           submodule outside the
#                                           workspace
#   - deposits-web/wallet/Dockerfile        static-site nginx, no
#                                           Rust build
#
# Usage:
#   ./deposits-tools/bin/test-docker-builds.sh           # build all
#   ./deposits-tools/bin/test-docker-builds.sh node      # one image
#   KEEP_IMAGES=1 ./deposits-tools/bin/test-docker-builds.sh
#                                           # don't `docker rmi` after
#   DRY_RUN=1 ./deposits-tools/bin/test-docker-builds.sh
#                                           # list what would be built
#                                           # without invoking docker
#
# Exit 0 if all builds succeed, non-zero otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# (image-name dockerfile-path) pairs. Image names are local-only
# tags, prefixed with `deposits-test/` to keep them distinguishable
# from production tags.
IMAGES=(
    "deposits-test/node:deposits-node/Dockerfile"
    "deposits-test/attestation:deposits-attestation/Dockerfile"
    "deposits-test/lnurl:deposits-lnurl/Dockerfile"
)

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found on PATH" >&2
    exit 2
fi

# Optional first arg filters by substring against the image-tag
# part. e.g. `… node` runs only the deposits-node build.
filter="${1:-}"

passed=()
failed=()

for entry in "${IMAGES[@]}"; do
    tag="${entry%%:*}"
    dockerfile="${entry#*:}"
    short_name="${tag#deposits-test/}"

    if [ -n "$filter" ] && [[ "$short_name" != *"$filter"* ]]; then
        continue
    fi

    echo
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "=== [dry-run] would build $tag from $dockerfile ==="
        if [ -f "$REPO_ROOT/$dockerfile" ]; then
            passed+=("$short_name")
        else
            echo "  ! Dockerfile not found: $REPO_ROOT/$dockerfile" >&2
            failed+=("$short_name")
        fi
        continue
    fi
    echo "=== Building $tag from $dockerfile ==="
    if (cd "$REPO_ROOT" && docker build -t "$tag" -f "$dockerfile" . ); then
        passed+=("$short_name")
    else
        failed+=("$short_name")
    fi
done

if [ "${KEEP_IMAGES:-0}" != "1" ]; then
    echo
    echo "=== Cleaning up images (set KEEP_IMAGES=1 to keep) ==="
    for entry in "${IMAGES[@]}"; do
        tag="${entry%%:*}"
        docker rmi "$tag" >/dev/null 2>&1 || true
    done
fi

echo
echo "=== Summary ==="
echo "  passed: ${#passed[@]}  ${passed[*]:-(none)}"
echo "  failed: ${#failed[@]}  ${failed[*]:-(none)}"

if [ "${#failed[@]}" -gt 0 ]; then
    exit 1
fi
