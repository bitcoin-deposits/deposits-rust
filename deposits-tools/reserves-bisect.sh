#!/usr/bin/env bash
# reserves-bisect.sh — walk historical commits of tapscript_reserves.rs and
# find the one whose `TapscriptReservesBuilder::build` produces the address
# currently declared in your operator's QuorumBegin.
#
# Use when sweep-all reports `reserves address rebuild mismatch: declared X
# but rebuilt Y` — that means the operator's wallet was running an older
# build when it computed X, and our current code's rebuild doesn't match.
#
# Usage:
#   ./reserves-bisect.sh \
#       --root /mnt/bitcoind/deposits/ \
#       --destination bc1qDESTINATION \
#       --esplora http://localhost:3100 \
#       --network bitcoin
#
# The script checks out each candidate commit's copy of
# deposits-core/src/tapscript_reserves.rs, rebuilds sweep-all, runs it in
# --dry-run mode, and reports whether the rebuild matched. It restores the
# current file at the end (success or failure).
#
# Exit code 0 if a matching commit is found, 1 if exhausted.

set -euo pipefail

# Most-recent-first — start from suspects that changed address shape.
COMMITS=(
  HEAD                # current code (baseline)
  c1cde608^           # before "tie-breaker as taproot internal key"
  7d70d45e^           # before --split flag
  f73b0368^           # before P0b cleanup (drop quorum_expiry args)
  8ae1c3ab^           # before Ruleset registry; tier timelocks → absolute
  c075cc0f^           # before CLTV anchored to quorum_expiry
  476174cf^           # before tier order quorum-first/operator-last
  b3d38acc^           # before NUMS fix
  6ece370f^           # before threshold script fix
  07ac99be^           # before lottery builder was added
)

FILE="deposits-core/src/tapscript_reserves.rs"

restore() {
  git checkout HEAD -- "$FILE" 2>/dev/null || true
}
trap restore EXIT

# Pass all script args straight through to sweep-all.
SWEEP_ARGS=("$@")

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

for commit in "${COMMITS[@]}"; do
  resolved="$(git rev-parse --short "$commit" 2>/dev/null || echo "$commit")"
  echo
  echo "═══ commit $commit ($resolved) ═══"

  if [ "$commit" = "HEAD" ]; then
    git checkout HEAD -- "$FILE"
  else
    if ! git checkout "$commit" -- "$FILE" 2>/dev/null; then
      echo "  skip: cannot check out $FILE at $commit"
      continue
    fi
  fi

  if ! cargo build --release --bin sweep-all 2>build.log >/dev/null; then
    echo "  skip: build failed at $commit (see build.log)"
    continue
  fi

  output="$(./target/release/sweep-all "${SWEEP_ARGS[@]}" --dry-run 2>&1 || true)"
  mismatch_count="$(printf '%s\n' "$output" | grep -c 'reserves address rebuild mismatch' || true)"
  reserves_attempted="$(printf '%s\n' "$output" | sed -n 's/^  Reserves attempted: *\([0-9]*\).*/\1/p' | head -1)"

  echo "  Reserves attempted: ${reserves_attempted:-?}"
  echo "  Mismatches: $mismatch_count"

  if [ "$mismatch_count" = "0" ] && [ "${reserves_attempted:-0}" != "0" ]; then
    echo
    echo "✔ Match at $commit ($resolved) — every reserves address rebuilt cleanly."
    echo "  To proceed without --dry-run:"
    echo "      git checkout $commit -- $FILE"
    echo "      cargo build --release --bin sweep-all"
    echo "      ./target/release/sweep-all ${SWEEP_ARGS[*]}"
    exit 0
  fi
done

echo
echo "✘ No commit in the candidate list matched."
echo "  Run \`git log --oneline -- $FILE\` and try earlier commits manually,"
echo "  or add them to the COMMITS array at the top of this script."
exit 1
