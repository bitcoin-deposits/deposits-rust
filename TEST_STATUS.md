# Integration Test Status

Snapshot of cluster-test (`#[ignore]`) status on a fresh
`./bin/setup.sh --fresh 3` cluster. Update whenever a test moves
between Pass / Fail / Skip.

**Last full run:** 2026-06-07 — fresh Q=3 cluster at block 227.
**Tally:** 26 pass / 11 fail / 37 total (some "pass" rows are
precondition-skips that exit cleanly).

## Pass (26)

| Test | Time | Notes |
|---|---|---|
| `allowlist_pubkey::pubkey_allowlist_gates_deposit_open` | 19s | |
| `allowlist_subkey::allowlist_subkey_resolves_to_allowlisted_account` | 14s | |
| `auto_dispute_on_expiry::*` | 56s | esplora marker-poll fix |
| `candidate_queue_swap::*` | 84s | |
| `cross_ledger_route::cross_ledger_route_via_htlc_agent` | 0.2s | skip — htlc-agent down |
| `dispute_fork_shape::*` | 19s | |
| `dispute_initiation::*` | 4s | |
| `domain_allowlist_challenge::domain_allowlist_challenge_unlocks_deposit_open` | 0.2s | skip — lnaddr-attest down |
| `domain_allowlist_nip05::domain_allowlist_nip05_unlocks_deposit_open` | 0.3s | skip |
| `domain_allowlist_proclaim::proclaim_unlocks_deposit_open` | 0.2s | skip |
| `equivocation_broadcast::*` | 10s | |
| `fraud_proof_dispute_dereliction::*` | 46s | |
| `fuzz_protocol::docker_balance_sheet_tracking` | (in 7.87s batch) | |
| `fuzz_protocol::docker_verify_ledger_relay_consistency` | | |
| `fuzz_protocol::docker_verify_reserve_backing_invariant` | | |
| `fuzz_protocol::docker_verify_utxo_reserves_match` | | |
| `fuzz_protocol::explore_10node_q3_4adv_placements` | (in 288s batch) | |
| `fuzz_protocol::explore_dispute_activity` | | |
| `fuzz_protocol::explore_op_histogram` | | |
| `fuzz_protocol::fuzz_protocol_heavy` | | |
| `lifecycle_self_rescue::quorum_repair_succeeds_at_tier0_post_expiry` | (in 173s batch) | short-expiry victim rewrite |
| `lifecycle_self_rescue::auto_quorum_refresh_self_rescues_past_expiry` | | |
| `lnurl_zap::lnurl_pay_flow_metadata_and_invoice` | (in 0.3s batch) | |
| `lnurl_zap::lnurl_short_subdomain_rejected` | | |
| `replacement_collateral_e2e::*` | 21s | |
| `webof_trust_ringsig::ringsig_via_wallet_binary` | 0.3s | skip — attestation setup absent |

## Fail (11)

| Test | Time | Diagnosis |
|---|---|---|
| `cooperative_refund_e2e::*` | 90s | unknown — needs investigation |
| `cooperative_refund_gate::*` | 5.6s | unknown — quick assertion fail, likely paired with above |
| `delivery_embed::wallet_escalate_lands_delivery_embed_on_member_ledger` | 30s | regression — silent-drop fix didn't cover the actual failure mode |
| `fraud_proof_equivocation::*` | 54s | regression — new test added this session, passed on prior degraded cluster |
| `fraud_proof_non_conforming_cosignature::*` | 53s | regression — same pattern as above |
| `fraud_proof_quorum_expired::*` | 36s | unknown — pre-existing |
| `fraud_proof_stale_cosig::*` | 21s | unknown — pre-existing |
| `fraud_proof_uncredited_lightning::*` | 73s | unknown — pre-existing |
| `fraud_proof_uncredited_onchain::*` | 73s | unknown — pre-existing |
| `invoice_cosign::make_invoice_returns_valid_cosignature` | 0.4s | likely lightning-precondition surfacing as panic, not clean skip |
| `pay_invoice_self_pay::pay_invoice_self_pay_returns_real_preimage` | 0.4s | same pattern |

## Root causes

### 1. fraud_proof_* (5 failures) — test-order pollution

Cargo runs test binaries alphabetically. `auto_dispute_on_expiry` and
`candidate_queue_swap` mine hundreds of blocks past expiry to exercise
the auto-confiscation grace window. By the time the `fraud_proof_*`
tests run a few minutes later, the chain tip has blown past every
setup-provisioned ledger's `quorum_expiry` (~1216).

Concretely: `op1` has auto-fired `DisputeEnter` fork-branches on every
op0 ledger before `fraud_proof_stale_cosig` even starts. The test
then forges a stale-cosignature update via `danger forge-stale-cosig`,
broadcasts it, and tries to read it back from op1's view of the
accused ledger — but op1's canonical chain for that ledger is frozen
at the dispute-fork sequence and never ingests new updates from the
"disputed" operator. The forged update is invisible from op1, the
test panics with "forged stale-cosig update should be in op0's
history."

`fraud_proof_dispute_dereliction` (the one fraud_proof that passes)
gets lucky: it picks op1's L3 (op1's *own* view of which has no fork
branches) and races with the cluster's already-in-flight
auto-confiscation, so the marker shows up regardless of whether its
own fraud claim or someone else's drove the confiscation.

**Fix:** each `fraud_proof_*` test must own its victim ledger —
open a fresh ledger on op0 with a long-enough `--quorum-expiry-blocks`
that no parallel mining can push it past expiry within the test's
runtime, add Q=3 healthy cosigners, activate, extend past QB,
then forge against it. Same pattern as the
`lifecycle_self_rescue` rewrite, but with a *long* expiry override
(victim must stay healthy through the whole test).

This is a significant refactor — ~5 tests, each with their own
fraud-specific evidence requirements.

### 2. invoice_cosign / pay_invoice_self_pay — missing skip guard

Both fail in 0.4s when the LDK container is down. They lack the
`if !lightning_available() { skip }` guard the other lightning
tests use.

### 3. cooperative_refund pair — needs diagnosis

`_e2e` (90s) and `_gate` (5.6s). Both reach a real assertion; not
yet investigated.

### 4. delivery_embed — needs diagnosis

In-session fix added silent-drop on non-operators. Test still fails;
the actual failure mode is something else. Read panic message,
redirect fix.

## Re-run

```bash
# Fresh cluster (wipes bitcoind + electrs):
./bin/setup.sh --fresh 3

# All ignored tests serially:
cargo test --no-fail-fast -p deposits-test --tests \
    -- --ignored --test-threads=1

# One test:
cargo test -p deposits-test --test fraud_proof_stale_cosig \
    -- --ignored --nocapture
```
