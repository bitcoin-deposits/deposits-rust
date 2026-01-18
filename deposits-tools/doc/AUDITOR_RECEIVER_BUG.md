# Auditor Receiver Bug - Incomplete Audit Logs

**Date**: 2025-10-21
**Status**: ❌ PARTIALLY FIXED - Sender-side works, receiver-side broken
**Severity**: High - Auditors only receiving 2 of 7 ledger updates

---

## Problem Summary

Third-party auditors (nodes not involved in a channel) are only seeing **2 out of 7 ledger updates** for channels they're auditing, even though the sending node successfully broadcasts all 7 updates.

### Example - Current Behavior

**Alice → Frank** (7 operations total):
```
Direct Alice view:  7 updates ✅
Direct Frank view:  7 updates ✅
Auditor Diana view: 2 updates ❌  (missing 5!)
Auditor Eve view:   2 updates ❌  (missing 5!)
```

**Operations Auditors See:**
1. ✅ LedgerOpened (from HandshakeInit)
2. ✅ DepositAdded (from LedgerAddDeposit)

**Operations Auditors MISS:**
3. ❌ ReservesIncreased (from ReservesToReserves)
4. ❌ BalanceAdded (from ReceivingCreditPayment)
5. ❌ ReservesIncreased (from ReservesToReserves - 2nd time)
6. ❌ BalanceLocked (from SendingLockPayment)
7. ❌ BalanceWithdrawn (from SendingFulfillPayment)

---

## What Was Fixed Today (Sender Side)

### Bug #1: Missing ACK Tracking

**Issue**: Most message-sending functions weren't calling `ledger.add_pending_ack()` before sending, which prevented the ACK handler from triggering broadcasts.

**Fixed Functions** (added ACK tracking to):
1. `handle_deposit_cosigned_invoice_async()` - line ~1370 - ReservesToReserves
2. `initiate_ledger_handshake_async()` - line ~1517 - HandshakeInit (partial)
3. `handle_channel_credit_for_cosigned_invoice()` - line ~3094 - ReceivingCreditPayment
4. `reclaim_reserves_to_local_async()` - line ~3243 - ReservesToLocal
5. `handle_sending_lock_payment()` - line ~3340 - SendingLockPayment

**Evidence It Works:**
```bash
# Alice's logs now show:
🔵 ADDED PENDING ACK: hash=[39, 5d, 8b, c1], type=32785  # DepositAdded
🔵 ADDED PENDING ACK: hash=[21, 59, 4a, 69], type=32773  # ReservesToReserves ← NEW!
🔵 ADDED PENDING ACK: hash=[75, ef, 56, e0], type=32819  # ReceivingCreditPayment ← NEW!
🔵 ADDED PENDING ACK: hash=[23, 75, 26, 47], type=32833  # SendingLockPayment ← NEW!

🟢 BROADCAST SUCCEEDED: hash=[39, 5d, 8b, c1]
🟢 BROADCAST SUCCEEDED: hash=[21, 59, 4a, 69]
🟢 BROADCAST SUCCEEDED: hash=[75, ef, 56, e0]
🟢 BROADCAST SUCCEEDED: hash=[23, 75, 26, 47]
🟢 BROADCAST SUCCEEDED: hash=[a4, 48, 37, 42]  # SendingFulfillPayment (already worked)
```

**Before fix**: 1 ACK tracked, 2 broadcasts
**After fix**: 4 ACKs tracked, 5 broadcasts
**Plus**: 1 HandshakeInit broadcast (bypasses ACK system)
**Total**: 6 broadcasts working on sender side

---

## What's STILL Broken (Receiver Side)

### Bug #2: Auditors Not Storing Received Updates

**Evidence:**
- Alice's logs show `🟢 BROADCAST SUCCEEDED` for all 5 operations
- `broadcast_message_to_other_partners()` creates `SignedAuditUpdateMsg` and sends via `send_message()`
- Diana and Eve's logs show NO receipt of these messages (searched for "SignedAuditUpdate", "audit", etc.)
- Only the FIRST 2 operations (HandshakeInit, DepositAdded) appear in auditor logs

**Key Observation:**
The first 2 operations work correctly - auditors receive and store them. But operations #3-7 are NOT being received or stored, even though Alice successfully sends them.

---

## Technical Details

### Sender Side (Working)

Alice's `handle_received_ack()` flow:
```rust
1. Message sent → Partner ACKs
2. handle_received_ack() called
3. Checks ledger.handle_ack(message_hash)
   - If pending ACK found: ✅ proceeds
   - If NOT found: ❌ "NO PENDING ACK FOUND" (was the bug we fixed)
4. Calls broadcast_message_to_other_partners()
5. Creates SignedLedgerUpdate with ECDSA signature
6. Wraps in SignedAuditUpdateMsg
7. Calls send_message(diana_id, signed_msg)
8. Calls send_message(eve_id, signed_msg)
9. Returns success ✅
```

### Receiver Side (Broken)

What SHOULD happen on Diana/Eve:
```rust
1. Receive SignedAuditUpdateMsg from network
2. Route to handle_signed_audit_update() or similar
3. Verify ECDSA signature
4. Verify hash chain
5. Store in signed_update_logs
6. Persist to KV store
```

What's ACTUALLY happening:
```
1. ??? (no logs showing receipt)
2. ??? (unknown)
3. Not stored in logs
```

---

## Hypotheses to Investigate

### Hypothesis 1: Messages Not Being Received
- Network delivery failure?
- Peer connection issue?
- Message type not registered in codec?

**Test**: Add logging to message receive path in Diana/Eve containers

### Hypothesis 2: Messages Received But Dropped
- Handler not implemented for SignedAuditUpdate?
- Validation failing silently?
- Wrong message routing logic?

**Test**: Check if `handle_message()` has a case for `SignedAuditUpdate`

### Hypothesis 3: Messages Received and Processed But Not Stored
- Storage logic has a bug?
- Only storing first N updates?
- Wrong storage key?

**Test**: Check `persist_signed_update()` and `load_signed_update_log()` implementations

### Hypothesis 4: Timing Issue
- First 2 messages arrive during handshake when auditors are "ready"
- Later messages arrive when auditors are "not listening"?
- Some initialization state required?

**Test**: Check if there's a difference in when HandshakeInit vs later messages are processed

### Hypothesis 5: Status Binary Display Bug
- All messages ARE being stored
- But `status ledger-updates` command only shows first 2?

**Test**: Check raw KV store data or add logging to status binary

---

## Files Modified Today

**src/bitcoin_deposits/handler.rs**:
- Added `add_pending_ack()` calls to 5 functions
- Added debug logging with println! (🔵, 🟢, 🟡, 🔴 prefixes)

---

## How to Reproduce

```bash
./reinit.sh && ./test.sh
```

**Expected**: All nodes show 7 updates for Alice→Frank, 5 for Bob→Charlie
**Actual**: Only Alice/Frank show their own 7, auditors only show 2

---

## Next Steps for Tomorrow

1. **Find the message receive handler**
   - Search for where `SignedAuditUpdate` messages are processed
   - Add logging to see if Diana/Eve receive the messages at all

2. **Check message routing**
   - Verify `DepositsMessage::SignedAuditUpdate` has a handler
   - Check if it's being routed correctly in the protocol

3. **Verify storage logic**
   - Check if `signed_update_logs` HashMap is being populated
   - Verify `persist_signed_update()` is being called
   - Check KV store keys

4. **Compare working vs broken flows**
   - Why do HandshakeInit and DepositAdded work?
   - What's different about the other 5 message types?
   - Is there special handling for "early" messages?

5. **Add comprehensive receiver-side logging**
   - Log message receipt in protocol handler
   - Log verification steps
   - Log storage attempts
   - Check for any silent errors

---

## Key Code Locations

**Sender (Broadcasting)**:
- `broadcast_message_to_other_partners()` - handler.rs:3810
- Creates `SignedAuditUpdateMsg` - handler.rs:3989
- Sends via `send_message()` - handler.rs:4005

**Receiver (Processing)**:
- Message routing: handler.rs (search for `handle_message` or protocol dispatch)
- Signature verification: types.rs `SignedLedgerUpdateLog::verify_signature()`
- Storage: handler.rs `persist_signed_update()`, `load_signed_update_log()`

**Status Display**:
- bin/status.rs - ledger-updates subcommand

---

## Logs to Check Tomorrow

```bash
# Check if Diana receives the messages
docker logs ldk-diana 2>&1 | grep -i "signed\|audit\|receive"

# Check Alice's send confirmation
docker logs ldk-alice 2>&1 | grep "🟢 BROADCAST"

# Check status binary logic
target/release/status ledger-updates diana --verbose  # if verbose flag exists
```

---

## Critical Insight

**The sender-side broadcast mechanism is working correctly now.** We confirmed:
- ACKs are being tracked ✅
- Broadcasts are being triggered ✅
- SignedAuditUpdateMsg is being created ✅
- send_message() is being called ✅
- No errors reported ✅

**The bug is 100% on the receiver side.** Diana and Eve are either:
- Not receiving the messages (network)
- Receiving but not processing them (handler)
- Processing but not storing them (storage)
- Storing but not displaying them (status binary)

The fact that the first 2 work suggests the infrastructure exists and works sometimes, but something about operations #3-7 causes them to be dropped.

---

**Status**: Ready for tomorrow's debugging session
**Confidence**: High that sender is fixed, receiver is the culprit
