# Adversarial Docker Testing

Configurable test environments for finding invariant boundaries
at which theft becomes profitable.

## Architecture

```
test spec (Rust struct)
    ↓
harness (brings up Docker environment matching spec)
    ↓
test code (takes manual control over nodes)
    ↓
balance sheet (tracks funds before/after each action)
```

## Usage

```rust
let env = TestEnvironment::from_spec(NetworkSpec {
    operators: vec![
        OperatorSpec { name: "alice", reserves_sats: 100_000_000, role: Role::Honest },
        OperatorSpec { name: "bob", reserves_sats: 100_000_000, role: Role::Honest },
        OperatorSpec { name: "charlie", reserves_sats: 100_000_000, role: Role::Attacker },
        OperatorSpec { name: "diana", reserves_sats: 100_000_000, role: Role::Honest },
    ],
    quorum: QuorumSpec::FullMesh,  // everyone backs everyone
    collateral_per_member_sats: 50_000_000,
    enforcement_delay_blocks: 200,
    deposits: vec![
        DepositSpec { operator: "alice", amount_sats: 10_000_000, depositor: "user1" },
    ],
});

env.start().await;

// Take manual control
let charlie = env.control("charlie");
charlie.inject_invalid_credit(deposit_id, 999_000_000).await; // over-reserve

// Check who detected it
let detections = env.poll_conformance_violations().await;
assert!(!detections.is_empty());

// Measure: what's charlie's balance sheet?
let sheet = env.balance_sheet("charlie").await;
// sheet.reserves, sheet.collateral_locked, sheet.collateral_at_risk, sheet.profit
```

## Components

- `NetworkSpec` — declarative environment configuration
- `TestEnvironment` — Docker orchestration (start, stop, fund)
- `NodeControl` — per-node command injection
- `BalanceSheet` — tracks funds across all operators
- `InvariantBoundarySearch` — binary search for profitable attack thresholds

## Files

```
docker/
├── README.md           — this file
├── harness.sh          — shell-level Docker orchestration
├── spec.rs             — NetworkSpec, OperatorSpec, etc.
└── control.rs          — NodeControl for injecting operations
```
