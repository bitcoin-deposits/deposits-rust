# Collateral Strategy

> Status: Design notes, not yet implemented. Captured during dispute automation work.

## Problem

When you join a quorum on another operator's ledger, you need to maintain collateral backing. Currently this is manual:

```
collateral_lock <secret> <msats> <blocks> <node_id>
```

For N quorum memberships, you need to:
1. Track each membership
2. Monitor collateral levels vs their ledger size
3. Lock sufficient collateral
4. Refresh before expiry

This doesn't scale. A human won't make better decisions than automation here.

## What Collateral Backs

Your collateral on Operator B's ledger proves you have skin in the game as a quorum member. If you vote dishonestly (sign contradicting states), your own partners can confiscate from you.

The collateral isn't backing B's deposits - it's backing your honest participation in B's quorum.

## Target Levels

From SPEC.md:
- Partners need ledgers >= half size of the ledger they're backing
- Before `collateral_enforcement_block`, this is relaxed
- After enforcement, the 51% capital threshold applies

Simple starting point:
```
required_collateral = their_reserves / 2
```

More sophisticated later:
- Weight by their deposit activity
- Adjust for number of quorum members (more members = less individual requirement?)
- Factor in our total capital available

## Refresh Strategy

Attestations expire after N blocks. Need to re-lock before expiry:

```
refresh_buffer = 144  # ~1 day before expiry
for attestation in our_attestations:
    if attestation.expires_at - current_block < refresh_buffer:
        lock_collateral(attestation.amount, attestation.operator)
```

## Auto-Maintain Loop

```rust
async fn auto_maintain_collateral(&self) {
    // 1. Get all ledgers where we're a quorum member
    let memberships = self.get_quorum_memberships();

    for membership in memberships {
        let operator = membership.operator_id;
        let their_reserves = self.get_operator_reserves_amount(operator);
        let required = their_reserves / 2;

        // 2. Sum our current unexpired attestations for this operator
        let current = self.sum_attestations_for_operator(operator);

        // 3. Lock more if needed
        if current < required {
            let deficit = required - current;
            self.lock_collateral(deficit, operator).await;
        }
    }
}
```

## Questions to Resolve

1. **Where does the collateral come from?**
   - Our own reserves on our own ledger
   - Need to ensure we don't over-commit

2. **Capital allocation across memberships**
   - If we have 100 BTC and 10 memberships each needing 20 BTC, we're short
   - Priority? Proportional? First-come?

3. **Lightning integration**
   - Locks go through HTLC
   - Need NWC or direct LDK access
   - What if Lightning node is down?

4. **Bootstrapping**
   - When joining a new quorum, we have zero collateral
   - Should auto-lock immediately after QuorumJoin?

5. **Graceful degradation**
   - If we can't maintain levels, what happens?
   - Warn? Auto-leave quorum? Just let attestations expire?

## Not Automated (Yet)

These remain manual decisions:
- **Which quorums to join** - business/trust decision
- **Total capital allocation** - how much to commit to quorum backing vs other uses
- **Risk limits** - max exposure per operator

## Implementation Order

1. Track quorum memberships (we have `get_joined_ledger_ids()`)
2. Query attestation levels per operator
3. Add `auto_maintain_collateral()` to periodic loop
4. Config for target ratio, refresh buffer
5. Capital allocation strategy (later, more complex)

## Related

- `deposits-ldk/src/services/reserves_management.rs` - similar pattern for reserves
- `SPEC.md` - collateral requirements and enforcement
