# Collateral Strategy

> Status: Design notes, not yet implemented. Captured during dispute automation work.

## Problem

When you add someone to YOUR quorum, you need to put YOUR funds at risk on THEIR ledger. This is currently manual:

1. Ask Operator B to join your quorum
2. B joins (QuorumJoin on your ledger)
3. You add them (QuorumAddMember on your ledger)
4. **Now you need to:**
   - Open a deposit on B's ledger
   - Fund it
   - Convert it to collateral (lock)

This puts your funds at risk on their ledger. If you go rogue on your own ledger, they can confiscate from your deposit on their ledger.

For N quorum members, you need to maintain N deposits on N other ledgers. This doesn't scale manually.

## What Collateral Backs

Your collateral on Operator B's ledger proves YOU have skin in the game as a ledger operator. If you (the operator) behave dishonestly, your quorum members can confiscate from your deposits on their ledgers.

The collateral isn't backing B's deposits - it's backing YOUR honest behavior as an operator.

## Target Levels

From SPEC.md:
- Partners need ledgers >= half size of the ledger they're backing
- Before `collateral_enforcement_block`, this is relaxed
- After enforcement, the 51% capital threshold applies

Simple starting point:
```
required_collateral_per_member = our_reserves / (2 * num_quorum_members)
```

Or proportional to our ledger size - each quorum member should be able to confiscate enough from us to make dishonesty unprofitable.

## Automation Flow

When we add a quorum member:

```
on QuorumAddMember(member_pubkey):
    1. Find or create deposit on member's ledger
       - Query their ledger for our existing deposit
       - If none, open new deposit (deposit_offer + fund + complete)

    2. Calculate required collateral
       - Based on our ledger size and number of quorum members

    3. Lock collateral
       - collateral_lock to convert deposit balance to locked collateral
       - This creates attestation they can use against us
```

## Refresh Strategy

Attestations expire after N blocks. Need to re-lock before expiry:

```
refresh_buffer = 144  # ~1 day before expiry
for member in our_quorum_members:
    attestation = our_attestation_on_their_ledger(member)
    if attestation.expires_at - current_block < refresh_buffer:
        lock_collateral(attestation.amount, member)
```

## Auto-Maintain Loop

```rust
async fn auto_maintain_collateral(&self) {
    // 1. Get all members of OUR quorum
    let our_quorum_members = self.get_our_quorum_members();

    for member in our_quorum_members {
        // 2. Check our deposit on THEIR ledger
        let our_deposit = self.get_our_deposit_on_ledger(member.ledger_id);

        if our_deposit.is_none() {
            // Open deposit on their ledger
            self.open_deposit_on_ledger(member.ledger_id).await;
            continue; // Will fund and lock on next cycle
        }

        // 3. Calculate required collateral (our skin in the game)
        let our_reserves = self.get_our_reserves_amount();
        let required = our_reserves / (2 * our_quorum_members.len());

        // 4. Check current locked amount
        let current_locked = our_deposit.locked_collateral;

        // 5. Lock more if needed
        if current_locked < required {
            let deficit = required - current_locked;
            // May need to fund deposit first if balance insufficient
            self.lock_collateral_on_their_ledger(member, deficit).await;
        }
    }
}
```

## Questions to Resolve

1. **Deposit funding source**
   - On-chain from our wallet?
   - Lightning payment to their ledger?
   - Need funds available to open deposits on N ledgers

2. **Circular dependency**
   - We need deposits on their ledgers
   - They need deposits on our ledger
   - Bootstrap: someone goes first, trusts briefly

3. **Capital allocation across members**
   - If we have 100 BTC reserves and 10 quorum members
   - Each needs 5 BTC collateral from us (100 / 2 / 10)
   - Total: 50 BTC spread across 10 other ledgers

4. **Lightning integration**
   - Locks go through HTLC on their ledger
   - Need NWC or direct LDK access to their node
   - What if their Lightning node is down?

5. **Scaling our ledger**
   - When our reserves grow, need to increase collateral on all member ledgers
   - Proportional increase or threshold-based?

6. **Graceful degradation**
   - If we can't maintain levels (low funds, member offline), what happens?
   - Warn? Stop accepting deposits?

## Not Automated (Yet)

These remain manual decisions:
- **Who to invite to quorum** - trust decision
- **Total reserves size** - business decision about how big to grow
- **Risk limits** - max exposure, min quorum size

## Implementation Order

1. Track our quorum members (QuorumAddMember events on our ledgers)
2. For each member, track our deposit on their ledger
3. On QuorumAddMember: auto-open deposit on their ledger
4. Add `auto_maintain_collateral()` to periodic loop
5. Config for target ratio, refresh buffer
6. Handle deposit funding (on-chain or Lightning)

## Related

- `deposits-ldk/src/services/reserves_management.rs` - similar pattern for reserves
- `SPEC.md` - collateral requirements and enforcement
