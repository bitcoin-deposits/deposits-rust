#!/bin/bash
# Run the ignored deposits-test suite with cluster isolation.
#
# Background: most #[ignore]'d integration tests assume a freshly-set-
# up cluster — specifically, a chain that hasn't yet crossed any
# ledger's `quorum_expiry + 720` boundary. `auto_dispute_on_expiry`
# (and friends) deliberately mine past that boundary to exercise
# partner-side auto-dispute, which then marks every quorum in the
# cluster as eligible for auto-fire. Any fraud_proof_* or
# cooperative_refund_* test that runs after on the same cluster
# either hits stale-state preconditions or never sees its update
# applied by a peer that's already moved past the ledger.
#
# Solution: run each disruptive test against `./bin/setup.sh --fresh 3`
# so each one gets clean chain state. Cheap tests group together with
# one fresh boot up front.
#
# Usage:
#   ./bin/run-ignored.sh           # run everything (~25 minutes)
#   ./bin/run-ignored.sh fraud     # run just the fraud_proof_* tests
#
# Exit 0 iff every group's tests passed.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$TOOLS_DIR")"
FILTER="${1:-}"

# Groups of tests that need fresh-cluster state, mapped to (filter,
# test binary list).
#
# Each "group" gets ONE fresh-cluster boot via `setup.sh --fresh 3`,
# then cargo test runs the named binaries against it. Tests within a
# group are allowed to mutate state; tests across groups are isolated.
declare -a GROUPS=(
    "cheap:state-independent tests:allowlist_pubkey allowlist_subkey docker_adversarial domain_allowlist_challenge domain_allowlist_nip05 domain_allowlist_proclaim lnurl_zap invoice_cosign pay_invoice_self_pay webof_trust_ringsig cross_ledger_route fuzz_protocol dispute_fork_shape equivocation_broadcast"
    "lifecycle:operator-driven self-rescue:lifecycle_self_rescue candidate_queue_swap"
    "auto-dispute:partner-driven auto-dispute past grace:auto_dispute_on_expiry"
    "fraud-broadcast:fraud-proof injection + confiscation:fraud_proof_dispute_dereliction fraud_proof_quorum_expired fraud_proof_stale_cosig fraud_proof_uncredited_lightning fraud_proof_uncredited_onchain dispute_initiation"
    "refund:cooperative refund + replacement collateral:cooperative_refund_e2e cooperative_refund_gate delivery_embed replacement_collateral_e2e"
)

run_group() {
    local key="$1" desc="$2" binaries="$3"
    echo
    echo "========================================================================"
    echo "GROUP: $key — $desc"
    echo "========================================================================"
    DEPOSITS_USE_HUB=1 "$SCRIPT_DIR/setup.sh" --fresh 3 > /tmp/run-ignored-setup-"$key".log 2>&1
    if [ $? -ne 0 ]; then
        echo "FAIL: setup.sh --fresh failed for group $key"
        return 1
    fi
    local cargo_args=()
    for b in $binaries; do
        cargo_args+=("--test" "$b")
    done
    (cd "$REPO_ROOT" && cargo test -p deposits-test --no-fail-fast "${cargo_args[@]}" -- --ignored 2>&1) \
        | tee /tmp/run-ignored-"$key".log \
        | grep -E "^test result|^test .* (FAILED|ok)"
    local pipe_status=("${PIPESTATUS[@]}")
    return "${pipe_status[0]}"
}

overall_rc=0
for entry in "${GROUPS[@]}"; do
    IFS=":" read -r key desc binaries <<< "$entry"
    if [ -n "$FILTER" ] && ! grep -q "$FILTER" <<< "$key"; then
        continue
    fi
    if ! run_group "$key" "$desc" "$binaries"; then
        overall_rc=1
    fi
done

echo
echo "========================================================================"
echo "SUMMARY"
echo "========================================================================"
for entry in "${GROUPS[@]}"; do
    IFS=":" read -r key desc binaries <<< "$entry"
    if [ -n "$FILTER" ] && ! grep -q "$FILTER" <<< "$key"; then
        continue
    fi
    if [ -f /tmp/run-ignored-"$key".log ]; then
        passed=$(grep -E "^test result" /tmp/run-ignored-"$key".log | awk '{for(i=1;i<=NF;i++)if($i=="passed;")p+=$(i-1)}END{print p+0}')
        failed=$(grep -E "^test result" /tmp/run-ignored-"$key".log | awk '{for(i=1;i<=NF;i++)if($i=="failed;")f+=$(i-1)}END{print f+0}')
        printf "  %-15s %3d passed, %3d failed\n" "$key" "$passed" "$failed"
    fi
done

exit "$overall_rc"
