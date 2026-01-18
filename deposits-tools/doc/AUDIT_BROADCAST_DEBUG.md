# Audit Broadcast Debugging

## Expected Flow

### Scenario: Alice adds reserves to her channel with Frank

1. **Alice** (operator) calls `add_reserves_to_channel(frank_id, 10000)`
2. Alice creates `ReservesToReserves` message
3. Alice stores it in `sent_messages_for_broadcast` with key (alice_id, frank_id, message)
4. Alice sends message to Frank
5. **Frank** (partner) receives message, processes it, sends ACK back
6. **Alice** receives ACK from Frank
7. Alice's `handle_received_ack()` is called with `sender=Frank`
8. Alice retrieves message from `sent_messages_for_broadcast[message_hash]`
9. Alice calls `broadcast_message_to_other_partners(message_hash, Frank)`
10. `broadcast_message_to_other_partners`:
    - Retrieves (operator_id=Alice, partner_id=Frank, message)
    - Creates signed update with Alice's signature
    - Broadcasts `SignedAuditUpdate` to Bob, Charlie, Diana, Eve
11. **Diana** and **Eve** receive `SignedAuditUpdate`
12. They verify signature and store it

## Current Problem

Auditors (Diana, Eve) are only seeing **DepositAdded** operations, not:
- LedgerOpened (HandshakeInit)
- ReservesIncreased (ReservesAdd)
- BalanceAdded (ReceivingCreditPayment)
- BalanceLocked (SendingLockPayment)
- BalanceWithdrawn (SendingFulfillPayment)

## Hypothesis 1: Messages Not Being Stored

Check if all message types are being stored in `sent_messages_for_broadcast`.

**Functions that store messages**:
1. ✅ `add_deposit_async` - line 1023 - **WORKS** (auditors see DepositAdded)
2. ✅ `add_reserves_to_channel` - line 2673 - **Should work but doesn't?**
3. ✅ `reduce_reserves_from_channel` - line 2723
4. ✅ `initiate_handshake_async` - line 1536 - **Just added**
5. ✅ Others at lines 2225, 2883, 3017, 3155

## Hypothesis 2: ACK Handler Not Broadcasting

Check if `handle_received_ack` is actually calling `broadcast_message_to_other_partners`.

**Check**:
- Line 3486: Calls `broadcast_message_to_other_partners(ack_msg.message_hash, sender)`
- This should happen for ALL successful ACKs

## Hypothesis 3: Broadcast Function Failing Silently

`broadcast_message_to_other_partners` might be failing to create signed updates:
- Line 3709: Returns OK if message not found ("may have been already broadcast")
- Line 3790: Logs "No ledger found for signing" if ledger doesn't exist
- Line 3824: Logs "Could not create signed update" if signing fails

## Hypothesis 4: Role Confusion

Maybe there's confusion about who is operator vs partner when Alice initiates vs when Frank responds?

**Alice's perspective**:
- Operator: Alice
- Partner: Frank
- Ledger key: (Alice, Frank)

**Frank's perspective**:
- Operator: Alice (still!)
- Partner: Frank (still!)
- Ledger key: (Alice, Frank) for operator role, OR
- Ledger key: (Frank, Alice) for partner role?

Wait - this could be the issue! When Frank receives a message from Alice, does he look in:
- `channel_ledgers[(Alice, Frank)]` - if he's the partner
- `channel_ledgers[(Frank, Alice)]` - if he thinks he's operator

## Hypothesis 5: Payment Messages Have Different Flow

`ReceivingCreditPayment`, `SendingLockPayment`, `SendingFulfillPayment` might use a different code path that doesn't store messages for broadcast.

Let me check where these are sent from.

## Action Items

1. ✅ Check `add_reserves_to_channel` - DOES store message
2. Check where `ReceivingCreditPayment` is sent from
3. Check where `SendingLockPayment` is sent from
4. Check where `SendingFulfillPayment` is sent from
5. Add logging to see if `broadcast_message_to_other_partners` is being called
6. Add logging to see if signed updates are being created
7. Check if the ledger exists when trying to sign

## Next Steps

Need to add debug logging or check real logs to see:
- Is `broadcast_message_to_other_partners` being called for ReservesAdd?
- Is it finding the message in `sent_messages_for_broadcast`?
- Is it finding the ledger to create signatures?
- Is it actually sending the `SignedAuditUpdate` messages?
- Are Diana/Eve receiving the messages but not storing them?
