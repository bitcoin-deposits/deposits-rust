#!/bin/bash
# Build the Bitcoin Deposits CLI binaries.
#
# Usage:
#   ./bin/build-cmds.sh               Build the daily-use binaries
#                                     (deposits-node, deposits-wallet)
#   ./bin/build-cmds.sh --all         Also build inspection / test utilities
#   ./bin/build-cmds.sh --debug       Use a debug build (faster compile,
#                                     slower runtime; useful for iteration)
#
# After building, symlinks are dropped into deposits-tools/bin/ pointing
# at target/release/ (or target/debug/), so you can invoke them as
# ./bin/deposits-node, ./bin/deposits-wallet, etc. from the repo root.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

cd "$REPO_ROOT"

MODE="--release"
CORE_BINS=(deposits-node deposits-wallet)
EXTRA_BINS=(
    nostr-ping
    nostr-bench
    transfer-simulator
    htlc-agent
    decode-updates
    treasury-address
    treasury-send
    standalone-reserves-demo
    discover
    replay-ledger
    deposits-lnurl
)
BINS=("${CORE_BINS[@]}")

for arg in "$@"; do
    case "$arg" in
        --debug) MODE="" ;;
        --all) BINS=("${CORE_BINS[@]}" "${EXTRA_BINS[@]}") ;;
        -h|--help)
            awk '/^# /{ sub(/^# ?/, ""); print; next } /^set/{ exit }' "$0"
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg (use --all, --debug, or --help)" >&2
            exit 1
            ;;
    esac
done

BIN_ARGS=()
for b in "${BINS[@]}"; do
    BIN_ARGS+=(--bin "$b")
done

OUT_DIR="target/release"
[ -z "$MODE" ] && OUT_DIR="target/debug"

echo "Building ${#BINS[@]} binaries into $OUT_DIR/:"
for b in "${BINS[@]}"; do echo "  - $b"; done
echo ""

# shellcheck disable=SC2086
cargo build $MODE "${BIN_ARGS[@]}"

# Drop symlinks into deposits-tools/bin/ so `./bin/<name>` resolves to
# the freshly-built binary. The symlinks are relative, so the script
# remains portable across moves of the repo.
echo ""
echo "Built:"
for b in "${BINS[@]}"; do
    bin_path="$OUT_DIR/$b"
    if [ ! -x "$bin_path" ]; then
        echo "  (missing) $bin_path"
        continue
    fi
    size=$(stat -c %s "$bin_path" 2>/dev/null || stat -f %z "$bin_path" 2>/dev/null || echo "?")
    # Compute a path that's relative to SCRIPT_DIR so the symlink works
    # regardless of where the repo is checked out (../../target/... from
    # deposits-tools/bin/).
    rel_target="../../$bin_path"
    ln -sf "$rel_target" "$SCRIPT_DIR/$b"
    echo "  $SCRIPT_DIR/$b -> $rel_target   ($size bytes)"
done
echo ""
echo "Use them from the repo root:"
echo "  ./bin/deposits-wallet discover --relay ws://localhost:7779"
echo "  ./bin/deposits-node info"
