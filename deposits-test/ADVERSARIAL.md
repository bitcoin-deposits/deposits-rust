# Adversarial Testing

## How it works

Three layers, each building on the last:

**Layer 1 — Protocol invariants** (`tests/tests/invariants.rs`, `adversarial.rs`, `adversarial_spec.rs`)
In-process tests against `LedgerState::apply()`. No Docker, no network. Tests that the state machine rejects invalid transitions. Every test targets a named invariant and produces structured output.

**Layer 2 — Boundary search** (`tests/tests/boundary_search.rs`)
Binary search over protocol parameters to find the exact threshold where an attack flips from deterred to profitable. Pure computation — models the economics, doesn't run nodes.

**Layer 3 — Docker live tests** (`tests/tests/docker_adversarial.rs`, `docker_expiry_boundary.rs`)
Tests against a running 4-operator regtest network. Verify invariants hold in the real system, measure actual cascade timing, track balance sheets across operators.

## Writing a test

### Step 1: Pick an invariant

Every test targets one invariant from the registry:

| ID | Invariant | What it means |
|----|-----------|---------------|
| E1 | ReserveBacking | reserves >= deposits at all times |
| E2 | CollateralBacking | collateral >= obligations backed |
| E3 | SlashingDeterrence | slashing extraction >= maximum theft |
| E4 | NegativeExpectedValue | expected value of attack < 0 |
| C1 | WitnessValidity | witness must satisfy descriptor |
| C2 | PaymentUniqueness | unique payment_hash per credit |
| C3 | SignatureBinding | signatures bound to (ledger, op, context) |
| C4 | NUMSPoint | Taproot internal key is unspendable |
| C5 | TaprootTreeIntegrity | Taproot tree matches announced quorum |
| S1 | DisputeStateGate | dispute state blocks normal ops |
| S2 | HashChainIntegrity | hash chain is append-only |
| S3 | BalanceNonNegative | balance cannot go negative |
| S4 | CollateralInUTXO | collateral preserved in UTXO by co-signers |
| L1 | DisputeLiveness | disputes resolve in bounded time |
| L2 | LotteryLiveness | lottery completes even with withholding |
| L3 | WalletEmbedding | wallet can force evidence onto ledger |
| L4 | RelayCensorshipResistance | relay censorship can't suppress disputes |

### Step 2: Write the test

Every test produces an `AttackResult` via the `AttackLog`:

```rust
use deposits_test::adversarial::*;

#[test]
fn attack_my_new_vector() {
    let mut log = AttackLog::new();

    // -- set up the scenario --
    // Use TestNetwork for in-process, or Docker harness for live

    // -- attempt the attack --
    // Construct the malicious operation and apply it

    // -- measure the result --
    let blocked = /* did the protocol prevent it? */;

    log.record(AttackResult {
        name: "Description of the attack".into(),
        invariant: Invariant::ReserveBacking,  // which property was tested
        adversary: AdversaryCapability::single_operator(4),  // what attacker controls
        cost_sats: 500_000,      // what attacker spends/risks
        extraction_sats: 1_000_000,  // what attacker gains if successful
        blocked,
        defense: DefenseLayer::Protocol,  // where the defense lives
        scaling: Scaling::Linear,  // how cost scales with network size
        notes: "Explanation of why it was blocked or exploitable".into(),
    });

    // Assert if the invariant MUST hold (protocol-level defense)
    // Don't assert if it's a wallet-policy gap (document instead)
    assert!(blocked, "This invariant must hold at protocol level");
}
```

### Step 3: Choose the right layer

**Use Layer 1 (in-process) when:**
- Testing state machine transitions (apply succeeds/fails)
- Testing conformance detection (watcher catches violation)
- Testing cryptographic properties (witness verification)
- Testing balance arithmetic (overflow, underflow)

```rust
// Layer 1: direct state manipulation
let mut net = TestNetwork::new(&["alice", "bob", "charlie", "diana"], 1_000_000);
let user = net.create_depositor("victim", 10);
let deposit_id = net.op_mut("alice").open_deposit(&user);
net.op_mut("alice").credit_deposit(deposit_id, 2_000_000, [0xAA; 32]); // over-reserve

let mut watcher = net.create_watcher("alice");
let violations = net.op("alice").sync_to_checked(&mut watcher);
assert!(!violations.is_empty()); // watcher caught it
```

**Use Layer 2 (boundary search) when:**
- Finding the parameter threshold where an attack becomes profitable
- Modeling economic incentives (cost vs extraction)
- Comparing analytical solutions to empirical results

```rust
// Layer 2: binary search over parameters
let search = InvariantBoundarySearch::new("collateral_ratio", 0.0, 1.0, 0.01);
let threshold = search.find_boundary(|ratio| {
    let collateral = (reserves as f64 * ratio) as u64 * quorum_size;
    reserves as f64 - collateral as f64  // positive = profitable
});
// threshold ≈ 0.33 (1/N members)
```

**Use Layer 3 (Docker) when:**
- Testing real Nostr relay propagation timing
- Testing actual Bitcoin transaction confirmation
- Measuring dispute cascade latency
- Verifying UTXO state matches ledger claims

```rust
// Layer 3: live infrastructure (mark with #[ignore])
#[test]
#[ignore = "requires Docker infrastructure"]
fn docker_my_live_test() {
    if !infra_available() { return; }
    // Use node_cmd() to interact with running operators
    // Use mine_blocks() to control block timing
    // Use get_block_height() to measure time
}
```

### Step 4: Record findings

Tests that find exploitable conditions should NOT assert failure — they should document the finding:

```rust
// EXPLOITABLE finding — document, don't assert
log.record(AttackResult {
    blocked: false,  // this IS exploitable
    defense: DefenseLayer::WalletPolicy,  // defense is outside protocol
    notes: "Wallets must check X before depositing".into(),
});
// No assert! — the test passes, the finding is logged
```

Tests that verify protocol-level defenses SHOULD assert:

```rust
// Protocol defense — assert it holds
assert!(result.is_err(), "Protocol must reject this");
```

## Running tests

```bash
# Layer 1+2: in-process (no Docker needed)
cargo test -p deposits-test

# Layer 3: Docker (requires running environment)
cd deposits-tools && ./bin/setup.sh 3
cargo test -p deposits-test -- --ignored --nocapture
```

## File layout

```
tests/
├── src/
│   ├── lib.rs              # TestNetwork harness
│   ├── adversarial.rs      # AttackResult, AttackLog, Invariant enum
│   └── docker.rs           # NetworkSpec, TestEnvironment, InvariantBoundarySearch
├── tests/
│   ├── deposit_lifecycle.rs       # 6 tests — open/credit/lock/fulfill/close
│   ├── quorum_formation.rs        # 4 tests — add/begin/attest/full setup
│   ├── dispute_resolution.rs      # 6 tests — enter/arm/acquire/yield/gates
│   ├── transfer_protocol.rs       # 3 tests — lock/complete/fail
│   ├── conformance_detection.rs   # 4 tests — reserve/witness violations
│   ├── operation_coverage.rs      # 10 tests — previously untested operations
│   ├── adversarial.rs             # 10 tests — attack vectors (forgery, replay, etc.)
│   ├── adversarial_spec.rs        # 8 tests — spec probes (NUMS, taproot, overflow)
│   ├── invariants.rs              # 13 tests — one per security invariant
│   ├── boundary_search.rs         # 6 tests — parameter threshold search
│   ├── docker_adversarial.rs      # 4 tests — live invariant verification
│   └── docker_expiry_boundary.rs  # 2 tests — near-expiry timing measurement
└── docker/
    ├── README.md
    └── harness.sh           # Shell orchestration for Docker environments
```

## Findings so far

| Finding | Severity | Defense | Action |
|---------|----------|---------|--------|
| Near-expiry extraction window | High | Wallet-policy | Wallets must check remaining_lock > cascade_time |
| Collateral can be < deposits | Medium | Wallet-policy | Wallets must check total_collateral >= total_deposits |
| Quorum member misbehavior | Medium | Node-policy | Cross-ledger slashing via fraud proof |
| NUMS point | Needs audit | Implementation | Verify BIP-341 construction |
| Deposit ID 128-bit collision | Low | Protocol | 2^64 birthday — infeasible but not 256-bit |
| Lottery liveness (all withhold) | Low | Node-policy | Liveness proofs + quorum slashing for non-reveals |

## Adding a new attack tier

The tiers from the adversarial testing roadmap:

- **Tier 1**: Load-bearing informal arguments (sybil topology, expiry extraction, slash racing, lightning theft)
- **Tier 2**: Spec-level ambiguities (NUMS, taproot tree, cosigner scope, proof embedding)
- **Tier 3**: Protocol-level games (censorship via rotation, collateral double-counting, lottery griefing, entropy MEV)
- **Tier 4**: Integration attacks (relay censorship, wallet state exfiltration, recovery confusion, verifier compromise)
- **Tier 5**: Implementation attacks (signature malleability, timing oracles, integer overflow, cross-ledger replay, descriptor fuzzing)

For each attack: state the hypothesis, pick the invariant, choose the layer, write the test, record the result.
