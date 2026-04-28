# Chapter 22: Testing and Fuzzing

> **Audience**: developers
> **Prereqs**: chapter 19, parts II and III
> **DEPs**: none directly

The reference implementation has thousands of lines of test code, and the breakdown of what each kind of test buys you matters. The protocol is a state machine with adversarial inputs and economic invariants — "does it compile" tells you nothing useful about whether the network is safe. This chapter walks through the layers: in-process simulations that exercise the state machine in seconds, cluster tests that boot a regtest network and exercise the daemon end-to-end, and the protocol fuzzer that drives multi-operator scenarios with random adversarial inputs and checks the invariants the whitepaper claims.

The bias of the test suite is towards finding *protocol* bugs — accounting drift, missed unlocks, conformance gaps — rather than implementation bugs in any one Rust function. That bias is deliberate. Single-function bugs are caught by code review and, when they slip through, by integration tests bouncing off them. Protocol bugs are the ones that quietly invalidate the security model, and the only way to catch those is to run the protocol against itself with random inputs and watch the invariants.

## The three tiers

The suite splits into three tiers that differ in setup cost, runtime, and what they exercise.

### Tier 1: in-process simulations

These tests live in `deposits-test/tests/` and run with a plain `cargo test --workspace`. They build a multi-operator scenario in process — no daemon, no Nostr relay, no Bitcoin Core, no Docker — by composing `Ledger` values from `deposits-core` directly. The harness in `deposits-test/src/lib.rs` exposes a `TestNetwork::new(names, reserves_amount)` that spawns N operators each with their own `Ledger`, plus helpers for opening deposits, crediting balances, locking transfers, and replaying one operator's history into another's watcher copy.

This is where the workhorse tests live:

- `tests/fuzz_protocol.rs` — the protocol fuzzer (described in detail below). The deepest exercise of the state machine in the suite.
- `tests/defend_49pct.rs` — the 49% coalition simulation. Builds five different quorum topologies (ring, dispersed, anchor-seeded, multi-anchor, all-anchor) on a 100-node graph and asks: with 49 of those 100 nodes adversarial, can the wallet pick a metric that excludes adversary-majority quorums while still finding enough honest operators to deposit with?
- `tests/final_game.rs` — a longer-running game: attacker fills 49 positions, defender fills 51, both choose quorum members, the attacker sees the defender's topology before choosing (worst case), the wallet applies a metric and funds whatever passes, and the attacker tries to profit. This is the empirical version of the whitepaper's economic-deterrence claim.
- `tests/conformance_detection.rs`, `tests/operation_coverage.rs`, `tests/transfer_protocol.rs`, `tests/deposit_lifecycle.rs`, `tests/quorum_formation.rs` — per-feature unit/integration tests that exercise specific operation flows on the in-process model.

Tier-1 tests typically run in milliseconds to a few seconds. They're the right place to check protocol invariants. If you're modifying `deposits-core` and the in-process tests still pass, the change is unlikely to have broken the core state machine.

### Tier 2 and Tier 3: cluster tests

Tests that need a running cluster are marked `#[ignore]` so they don't run in a default `cargo test` pass. They're opted in with `cargo test -- --ignored`. The cluster itself is brought up by `deposits-tools/bin/setup.sh N` (where N is the quorum size — `setup.sh 3`, `setup.sh 5`, or `setup.sh 7`).

The line between Tier 2 and Tier 3 is whether the test runs only against the local daemon binaries (Tier 2) or also touches Docker-managed containers like Bitcoin Core, electrs, strfry relays, or LDK Lightning (Tier 3). Because `setup.sh` already requires Docker for `bitcoind`, in practice almost every `#[ignore]` test in this suite is Tier 3 — the distinction matters more conceptually than in the test runner.

Tier-3 tests live in:

- `tests/dispute_initiation.rs` — Tier-3 fraud-proof + dispute pipeline test (the canonical end-to-end recovery exercise; runs in ~90s on Q=3).
- `tests/fraud_proof_stale_cosig.rs`, `tests/fraud_proof_uncredited_lightning.rs`, `tests/fraud_proof_uncredited_onchain.rs`, `tests/fraud_proof_inactive_quorum.rs` — one Tier-3 test per fraud-proof verifier type, each on a different ledger so they run back-to-back.
- `tests/cross_ledger_route.rs` — exercises the htlc-agent courier Tier-3.
- `tests/equivocation_broadcast.rs` — the equivocation defense: an attacker mints two valid-cosigned updates at the same `(seq, prev_hash)`, broadcasts them four seconds apart, and the test asserts that the second one is rejected on chain-continuity grounds because honest members already advanced.
- `tests/delivery_embed.rs` — wallet → quorum-member escalation transport.
- `tests/actor_shadow_consistency.rs` — regression test for the per-ledger actor's parallel JSONL.
- `tests/docker_adversarial.rs` — declarative adversarial-network harness with attacker/honest/offline-after roles.

Tier-3 tests can take minutes to run because they wait on real Bitcoin confirmations, Nostr relay round trips, and dispute timers gated on block heights.

## The cluster setup

The script at `deposits-tools/bin/setup.sh` is the canonical "give me an N-operator cluster" tool. Its argument is the quorum size Q; it produces a network of `3*Q + 1` operators. So `setup.sh 3` gives you 10 operators, `setup.sh 5` gives you 16, and `setup.sh 7` gives you 22. The unusual count (3Q+1) is there to make sure every ledger's quorum can be drawn from disjoint operators with room to spare.

What the script does, in phases:

1. **Reset.** Kills any prior daemons and relays, deletes `deposits-tools/data/`, and starts fresh.

2. **Start relays.** Boots two `strfry` instances on `ws://localhost:17779` (the durable "ledgers" relay, where `Kind:9100` updates and `Kind:9101` fraud broadcasts live) and `ws://localhost:17780` (the ephemeral "messaging" relay for request/response traffic). The default ports are exported by `deposits-tools/bin/_common.sh`; tests read them via `relay_ledgers()` and `relay_messaging()` in `deposits-test/src/regtest.rs`.

3. **Fund operators.** Loads or creates a `faucet` Bitcoin Core wallet, mines 101 blocks for coinbase maturity, then sends `(reserves + collateral) * ledgers_per_op` BTC to each operator's regtest address. Default split: 0.4 BTC reserves + 0.6 BTC collateral per ledger, three ledgers per operator.

4. **Start daemons.** Each operator gets `deposits-tools/data/op<idx>` as its data dir and a unique seed derived as `op<idx>` zero-padded to 64 hex chars (so `op0` becomes `6f70300000…`). Daemons are launched with `--esplora http://localhost:3102` (electrs), the two relay URLs, and a per-operator metrics port at `9100 + idx`.

5. **Reserves + ledgers.** For each `(operator, ledger_index)` pair, runs `deposits-node reserves create <utxo_sats>` followed by `deposits-node ledger open`. Stores resulting IDs under `deposits-tools/data/state/reserves_i_l` and `ledger_i_l` so tests can look them up via `read_setup_state("ledger_2_1")`.

6. **Form quorums.** For each ledger, picks Q members spread across the remaining operators using a stride-based offset (so different ledgers on the same operator end up with disjoint quorums where the math allows). Runs `deposits-node quorum add` for each member.

7. **Activate quorums.** Backgrounds a `deposits-node quorum begin` per ledger (each broadcasts a rotation tx and then blocks waiting for its `default_quorum_begin_confs` depth), then loops mining blocks while reaping completed pids. The mine-and-drain dance is necessary because all the rotation txs hit mempool together and need confirmations before staged members will cosign the `QuorumBegin` update.

By design, `setup.sh` is a fresh-start tool. Running it on an already-populated `data/` directory deletes the prior state. This is intentional — re-running on a partially-set-up cluster is a fast path to "the daemon thinks the ledger is at sequence 47, but the relay only retained the first 12 updates" and other shapes of head-tail drift. There is a `setup-resume.sh` companion for the case where a single phase failed, but the standard advice is "wipe and re-run."

## Tier-3 idempotency

This deserves its own callout: **most Tier-3 tests are not idempotent.** Fraud-proof tests dispute a ledger, which moves it out of `Normal` state. Once that's done, the ledger is no longer a valid target for another fraud-proof test (or any test that asserts on `Normal`). Running `cargo test -p deposits-test -- --ignored` straight through can succeed once and fail on the second invocation against the same cluster.

The mitigation in the suite is to spread fraud-proof tests across different ledgers — `fraud_proof_stale_cosig.rs` uses op0's L1, `fraud_proof_uncredited_onchain.rs` uses op0's L2, and so on. That lets all four verifier-type tests pass in a single back-to-back run on a fresh `setup.sh 3` cluster. But re-running any individual test on the same cluster after that requires `setup.sh 3` again first.

`actor_shadow_consistency.rs` has the additional wrinkle that it needs prior accumulated traffic on the actor's inbox — a brand-new cluster's actor logs are empty, so the assertion "every overlapping `(ledger, seq)` between actor.log and handler.jsonl matches" is trivially satisfied. The test drives its own StaleCosig forge to generate the inbound traffic, but that means it consumes a ledger like the other fraud-proof tests do.

The practical rule when adding a Tier-3 test: write it to run on a freshly-set-up cluster, document that requirement at the top of the file, and pick a ledger no other Tier-3 test claims.

## Cluster helpers

The primitives Tier-3 tests build on live in `deposits-test/src/regtest.rs`. The most load-bearing ones:

- `cluster_available()` — true iff `bitcoind` responds to `getblockcount` AND the release binaries `target/release/deposits-node` and `target/release/deposits-wallet` are present. Tests gate on this and emit `eprintln!("skipping: cluster not running")` when false, so a `cargo test --workspace -- --ignored` against an empty machine returns "all skipped" instead of crashing.
- `op_data_dir(idx)` — returns the path to operator `idx`'s data dir under `deposits-tools/data/`.
- `op_seed(idx)` — reproduces the script's deterministic seed scheme.
- `read_setup_state(key)` — reads a value the script stored under `deposits-tools/data/state/<key>` (e.g. `ledger_2_1`).
- `discover_op0_ledger()` — runs `deposits-wallet discover --json` and returns op0's first ledger ID. Used by every test that just needs *some* ledger to attack.
- `read_ledger_history(data_dir, ledger_id)` — parses `<data_dir>/wallet/ledgers/<ledger_id>.jsonl` and returns the list of `SignedLedgerUpdate`s. The header rows (`Role`, `State`) are skipped; only `Update` rows come back.
- `read_actor_log(data_dir, ledger_id)` — same shape, but reads `<ledger_id>.actor.log` (the per-ledger actor's parallel shadow).
- `embed_proof_hash(node_bin, op_idx, peer_op_idx, ledger_id, proof_hash)` — runs `deposits-node recovery embed-hash` from `op_idx` and then re-reads the ledger from `peer_op_idx`'s view. The peer detour exists because the daemon currently skips inbound updates for its own ledgers, so a fresh embedding only shows up after a peer has ingested it from the relay.
- `publish_fraud_broadcast(node_bin, op_idx, broadcast)` — serializes a `FraudBroadcast` to JSON, drops it to a temp file, and runs `deposits-node recovery publish-fraud-broadcast` to publish it as a `Kind:9101` event.
- `poll_confiscation_marker(ledger_id, timeout)` — every operator that completes a confiscation TX writes a `confiscated_<ledger_id_prefix>.marker` file to its data dir. This polls every operator's data dir every two seconds and returns the index of whichever one wins. Confiscation success is the canonical end-of-pipeline signal; if the marker shows up, detection → fork → DisputeArmed → lottery → on-chain confiscation all happened.
- `find_peer_with_ledger(ledger_id, exclude_op_idx)` — `setup.sh`'s quorum assignment is deterministic but not fixed to a particular operator-index ordering. Tests that need a quorum member's view of an accused ledger don't know in advance which operator that is, so they call this to find any peer that has the ledger imported.
- `earliest_anchored_block_hash(op_idx)` — scans every imported ledger in `op_idx`'s data dir for the lowest-block-height update with a non-zero `block_hash` and returns it. Useful as an "earlier confirmed block" anchor in fraud-proof tests where the accused ledger's own updates may all share a single block.
- `build_node_with_danger()` — rebuilds the release `deposits-node` binary with the `dangerous-testing` Cargo feature enabled, which exposes the `danger publish-invalid`, `danger forge-stale-cosig`, and `danger fork-update` subcommands. These are the test-only attack injectors; without the feature flag the subcommands don't compile in.

The pattern these primitives encode is "talk to the cluster the way an external actor would, then read disk state to verify what happened." There's no test-side hook into the daemon's internals; everything goes through the same CLI entry points an operator would use.

## The protocol fuzzer

`tests/fuzz_protocol.rs` is the deepest state-machine exercise in the suite. Three thousand lines, no I/O, runs in seconds, finds bugs the rest of the suite doesn't.

The shape: instantiate N operators, each with their own `Ledger` and replicas of the ledgers they're a quorum member of. Mark some operators as adversarial. Drive a loop where, on each step, a random operator proposes a random operation (weighted by class — opens, credits, locks, fulfills, fails, transfers, fees, disputes, etc.). The proposal goes through the real cosigning path: each member runs `apply_and_check` against its replica using the same `CoreWitnessVerifier` that the daemon uses, accepts or rejects, and the proposal lands on the proposer's ledger only if a majority of cosigners accept. After each step, run the invariant checker.

Adversary operators don't go through the cosigning path on their own ledger — they're allowed to write whatever they want to their own state, the way a real malicious operator would. The point of the fuzzer is to ask: when the adversary's quorum has adversary majority, what shapes of damage can they actually produce on their own ledger? And when the adversary is in another ledger's quorum, can they trick honest cosigners into co-signing something non-conforming?

The invariant checker (`ProtocolSim::check_all_invariants`) walks every operator's ledger and every replica and reports violations:

- **Reserves invariant (honest-only).** `total_deposit_balance() <= reserves_amount` must hold for every honest operator's ledger. Adversary operators are exempt from this — over-promising against reserves *is* their attack surface, and the test measures whether they can ever profit from it.
- **Locked-balance invariant (universal).** `locked_balance <= balance` for every deposit on every ledger. If we've locked more than the deposit owes, the accounting is broken regardless of who did it.
- **Pending-claims invariant (universal).** The sum of pending transfers + pending withdrawals + open invoice locks against any deposit must not exceed that deposit's `locked_balance`. Catches dangling pending entries and accounting drift where claims outlive their locks.
- **History integrity (honest-only).** Sequence numbers are contiguous from 0 (no gaps, no duplicates). Each update's `previous_hash` matches the prior update's `content_hash`. The chain hash-chains correctly.
- **Operator-key transitions (honest-only).** `operator_key` may only change from a `LedgerOpen` (initial) or a `DisputeAcquire` (custody transfer). Walk history, track the last key set by either of those, and verify the final `operator_key` matches.
- **Replica conformance (honest-only).** A replica an honest operator holds of any ledger must itself be conforming — we only co-sign conforming updates, so any replica reaching a non-conforming state is a co-signing bug.
- **Equivocation invariant (cross-replica).** If a replica's sequence equals the owning operator's current sequence, the `chain_tip_hash` MUST agree. Disagreement at the same seq means the operator equivocated and got two different histories signed at the same chain seq.

After invariant checking, the fuzzer evaluates **profit**: for each ledger that ended up over-reserved, count the excess against the adversary if they had cosign majority on it, against "stolen from users" if they pushed through despite an honest majority (which shouldn't happen, and the test asserts it doesn't), or as a slashing event if neither.

Two top-level tests anchor the run:

- `fuzz_protocol_5node_q3_2adv_no_profit` — five operators, two adversarial, Q=3. With this configuration the adversary provably cannot achieve cosign majority on any ledger's quorum, so net profit must be exactly 0 across 100 runs of 200 ops each. If profit is non-zero, the protocol let the adversary score on a ledger they shouldn't have been able to compromise — that's a bug.
- `fuzz_protocol_5node_q3_3adv_profit_is_reachable` — same but with three adversaries. Now operator 0's quorum is `[1, 2, 3]` and members 1 and 2 are adversarial (majority). The adversary *should* be able to push through over-reserved updates on op 0's ledger; the test asserts profit > 0 in at least one seed across 100 runs. This is a sanity check on the fuzzer itself: if profit is zero here, the fuzzer isn't exercising the attack surface and the previous test's "net = 0" assertion is meaningless.

There's also a heavier `fuzz_protocol_heavy` (`#[ignore]`, 1000 runs × 1000 ops = 1M steps in release mode) and several exploratory tests that emit histograms instead of asserting — `explore_op_histogram`, `explore_dispute_activity`, `explore_10node_q3_4adv_placements`. These are observability tests; their job is to tell you *what the fuzzer is actually doing*, so a "no profit" assertion isn't accidentally vacuous.

A canary test at the top, `equivocation_invariant_fires_on_divergent_replica`, manually corrupts a replica's `chain_tip_hash` and asserts the invariant checker catches it. Without this, a regression that silently weakens the cross-replica check would leave `fuzz_protocol_5node_q3_2adv_no_profit` passing even after the protocol broke.

### What the fuzzer has actually found

This isn't theoretical. The fuzzer has caught real protocol bugs in its short life:

- **Transfer balance-accounting bug** (commit `888b0e3`). A `TransferLock` accounting path was decrementing `balance` rather than incrementing `locked_balance`, which made it look like the source deposit's funds had vanished. The fuzzer's pending-claims invariant flagged the divergence.
- **`OnchainFail` missing unlock** (`e6fe801`). A failed on-chain withdrawal wasn't restoring the locked balance to `balance`, leaving the deposit permanently short. Caught by the locked-balance invariant.
- **`OnchainLock` fee not locked** (`d8bac56`). The lock-side accounting reserved the principal but not the fee, so the operator could double-spend the fee portion via a follow-up op. Caught by the pending-claims invariant.

These are exactly the shape of bug human review tends to miss — the operation looks right when read in isolation, but the accounting drift only shows up after a sequence of ops that nobody would think to write by hand.

## Coverage gaps

Honest accounting of what isn't yet fuzzed:

- **Cross-ledger random fuzz.** The fuzzer is single-ledger-centric; it doesn't generate random courier-routed transfers across ledgers and check the cross-ledger HTLC accounting under adversarial pressure. There's a Tier-3 happy-path test (`cross_ledger_route.rs`) but no fuzz coverage.
- **Simultaneous-broadcast races.** The equivocation Tier-3 test stages a four-second gap between U_A and U_B specifically because an interleaved arrival could split-brain quorum members in ways the test doesn't currently characterize. Modeling that requires finer Nostr-timing control than the harness exposes.
- **Courier-route fuzzing.** Same shape as the cross-ledger gap above, but specifically exercising courier-vs-counterparty adversarial behavior.
- **First-class equivocation fraud proof.** Equivocation is currently caught by the cross-replica chain-tip invariant in the fuzzer and by the broadcast Tier-3 test; there's no dedicated `FraudProofType::Equivocation` in `deposits-protocol/fraud.rs` yet.

These are tracked as follow-up work.

## The actor shadow regression

`tests/actor_shadow_consistency.rs` is a Tier-3 test that exists for one specific reason: the daemon currently runs a per-ledger actor in parallel with the legacy `handler.ledgers` apply path (see chapter 20 for the actor migration state). Both write to disk — `<ledger_id>.jsonl` for the handler, `<ledger_id>.actor.log` for the actor — and the migration plan is for the actor to eventually become authoritative. Until then, "the actor's view matches the handler's" is a regression we want to lock in.

The test drives a StaleCosig forge → embed → publish → quorum-arm → confiscation pipeline (the same workload as `fraud_proof_stale_cosig.rs`) to generate inbound traffic, then walks every operator that has a handler.jsonl for the accused ledger and asserts that for every overlapping `(ledger, seq)` in both files, the `content_hash` is identical. Drift between the two paths would mean the actor and the handler are interpreting the same wire bytes differently — rare, given they share an `Arc<RwLock<Ledger>>` over the apply path, but the regression remains a useful smoke check while both paths exist.

The asymmetry the test deliberately doesn't assert: the actor's log only contains updates the actor saw via inbound during this process's lifetime, while the handler's JSONL includes the pre-existing setup history loaded at boot. So total counts diverge legitimately; only the overlap is checked.

## The simulation tests

`defend_49pct.rs` and `final_game.rs` are a different shape from the rest of the suite. They don't pass-or-fail in the ordinary sense — they're empirical evaluations of the protocol's economic claims under simulated adversaries. They're worth understanding as a category.

The model: 100 operator positions on a graph, six anchor positions (trusted, cannot be compromised), 49 of the remaining 94 controlled by an attacker. The attacker sees the defender's topology before choosing their own. The wallet sees the full graph and applies a metric — vertex-connectivity from its trusted anchors to a candidate operator's quorum, anchor-majority requirements, mincut bounds, etc. — and funds whatever passes the metric. The attacker tries to profit from those funded operators given their quorum-majority positions.

The tests sweep different topology builders (ring, dispersed, anchor-seeded, multi-anchor, all-anchor) and different wallet metrics, computing the attacker's net profit in each combination. The output is a table; the protocol claim is that with reasonable metrics the attacker can't break even, and the table either substantiates that or doesn't. This is the empirical cousin of the whitepaper's economic-deterrence argument, run as a Rust test so a regression in the underlying protocol parameters surfaces as a concrete number going the wrong way.

## Running tests locally

The actual commands. Tier 1 first — these are cheap and you should run them on every change:

```
cargo test --workspace
```

This runs everything not marked `#[ignore]`: in-process simulations, the protocol fuzzer's two anchor tests, all per-feature unit tests across all crates, the canary tests in `fuzz_protocol.rs`. Should complete in under a minute on a workstation.

For Tier 2/3, first bring up a cluster:

```
./deposits-tools/bin/setup.sh 3
```

That takes a few minutes and leaves you with a Q=3 cluster running on `localhost`. Then opt in to the ignored tests:

```
cargo test --workspace -- --ignored
```

Or, more usefully, pick a single test to drive:

```
cargo test -p deposits-test --test dispute_initiation -- --ignored --nocapture
```

The `--nocapture` matters — Tier-3 tests log step-by-step progress to stderr, and seeing it scroll by is the difference between "the test hung" and "the test is waiting for a 102-block confirmation, give it another minute."

Heavy fuzzer runs are an explicit opt-in:

```
cargo test --release -p deposits-test fuzz_protocol_heavy -- --ignored --nocapture
```

Release mode is necessary; debug-mode 1M-step fuzz runs take an order of magnitude longer.

## CI considerations

The split is the obvious one: Tier 1 in CI on every push, Tier 2/3 in nightly or pre-release runs.

Tier 1 fits comfortably under a minute and parallelizes per-crate. The protocol fuzzer's two anchor tests (`fuzz_protocol_5node_q3_2adv_no_profit` and `_3adv_profit_is_reachable`) run in this tier and are the most valuable thing CI can catch — a regression in protocol invariants shows up as a concrete invariant-violation message rather than a hand-waved "tests pass."

Tier 3 doesn't fit comfortably in standard CI because of the Docker dependency: every run needs to start `bitcoind`, electrs, two strfry instances, and 10+ daemon processes. Tooling that supports docker-in-docker can run it, but the wall-clock budget per test (~90s for the dispute pipeline, longer for some fraud-proof variants) and the non-idempotency mean a full Tier-3 sweep takes 15-30 minutes against a fresh cluster. The pragmatic split is "Tier 3 on pre-release or on a nightly schedule, Tier 1 every push."

For the fuzzer specifically, `fuzz_protocol_heavy` (1M steps in release mode) is a candidate for a weekly run rather than nightly — it takes a few minutes even in release mode and the fixed-seed configuration means a green run today is a green run tomorrow unless protocol code changed.

## What stays in your head

- Three tiers: in-process simulations (Tier 1, fast, every push), Tier 2/3 cluster tests (`#[ignore]`, opt in with `-- --ignored`, requires `setup.sh N`).
- The protocol fuzzer in `tests/fuzz_protocol.rs` is the deepest exercise of the state machine. Two anchor tests assert profit invariants under provably-safe and provably-vulnerable configurations; canary tests assert the invariant checker itself works.
- The fuzzer has caught real protocol bugs (transfer accounting, onchain unlocks, fee locking). The bugs caught are exactly the shape that human review misses.
- Tier-3 tests aren't idempotent — fraud-proof tests dispute a ledger. Each runs on a fresh cluster, or chooses a different ledger to dispute.
- `deposits-test/src/regtest.rs` exposes the cluster primitives; tests build on `cluster_available`, `discover_op0_ledger`, `read_ledger_history`, `embed_proof_hash`, `publish_fraud_broadcast`, `poll_confiscation_marker`.
- The simulation tests (`defend_49pct.rs`, `final_game.rs`) are empirical economic evaluations, not pass/fail tests in the usual sense.

## Where this leads

[Chapter 23](23-operations.md) covers what changes when this implementation moves from regtest clusters to mainnet operators: deployment shapes, key management, monitoring, the upgrade path between protocol versions. The test infrastructure described here is what you exercise before promoting a build; the operations chapter is what you do once it's deployed.
