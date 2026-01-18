# Auditor Receiver Bug - Resolution Status

**Date**: 2025-10-21
**Session**: Follow-up debugging
**Status**: ✅ ROOT CAUSE FIXED, ❌ DELIVERY ISSUE REMAINS

---

## Root Cause Fixed

### The Problem
The `node_secret_key` was never set in `DepositsHandler`, preventing cryptographic signing of audit updates.

###Fix Applied
**File**: `src/builder.rs:1627-1629`

```rust
// Set the node secret key for signing audit updates
let node_secret_key = keys_manager.get_node_secret_key();
handler.set_node_secret_key(node_secret_key);
```

### Evidence of Fix
- ✅ Alice creates signed updates: `🟢 BROADCAST: Created signed update seq=X`
- ✅ Messages wrapped correctly: `🟢 BROADCAST: Wrapping in SignedAuditUpdate (0x8057)`
- ✅ `send_message()` succeeds: `🟢 BROADCAST: send_message succeeded`

---

## Remaining Issue: Message Delivery

### Current State
**Messages are created and queued but NOT delivered to auditors.**

### Evidence
1. Alice's logs show 24 `send_message` calls succeed (6 updates × 4 recipients)
2. Alice's logs show ZERO "📤 Queued" messages (from `log_info` at handler.rs:727)
3. Diana/Eve logs show ZERO received messages (no `PROCESS_MESSAGE` entries)

### Hypothesis
The `send_message()` function returns `Ok(())` but the actual queueing code (lines 698-733) may not be executing properly, OR messages are queued but LDK's `get_and_clear_pending_msg()` is not being called frequently enough to deliver them.

---

## Investigation Path

### What We Know
1. ✅ Signed updates created successfully with node secret key
2. ✅ `SignedAuditUpdate` messages constructed (type 0x8057)
3. ✅ `send_message()` returns success
4. ❌ No evidence of messages being queued (missing "📤 Queued" logs)
5. ❌ No evidence of messages delivered to recipients

### Code Flow
```
broadcast_message_to_other_partners()
  └─> create_signed_update() → ✅ Works
  └─> Wrap in SignedAuditUpdate → ✅ Works
  └─> send_message() → ✅ Returns success
      └─> Queue in outbound_messages → ❓ Silent failure?
      └─> trigger_immediate_send() → ❓ Not working?

LDK calls get_and_clear_pending_msg() → ❓ Not being called?
  └─> Returns queued messages → ❓ Queue is empty?
  └─> LDK delivers to peers → ❌ Never happens
```

### Likely Causes (in order of probability)

1. **Message not actually queued**: The queue operation at lines 709-716 completes but doesn't persist
   - Maybe lock is dropped immediately?
   - Maybe entry is cleared elsewhere?

2. **LDK not polling for messages**: `get_and_clear_pending_msg()` not being called by LDK
   - Custom message delivery requires peer connection
   - May need explicit message type advertisement

3. **Peer connectivity issue**: Messages only sent to direct channel partners
   - Diana HAS a channel with Alice (confirmed)
   - But custom messages may require additional setup

---

## User's Insight: Advertisement/Registration

**User suggested**: "perhaps we're not advertising / registering acceptance?"

This is likely correct! LDK's custom message system may require:
1. Advertising supported message types in node features
2. Registering message type handlers
3. Explicit peer negotiation for custom protocols

### Current Implementation
- `provided_node_features()` returns `NodeFeatures::empty()` (handler.rs:4961)
- `provided_init_features()` returns `InitFeatures::empty()` (handler.rs:4979)
- Comments say "we rely on Lightning's built-in custom message routing"
- **This may be insufficient for peer-to-peer custom message delivery**

---

## Next Steps

1. **Add feature advertisement** for Bitcoin Deposits protocol
   - Set appropriate feature bits in `provided_node_features()`
   - Set appropriate feature bits in `provided_init_features()`

2. **Verify message queueing** is actually happening
   - Add println debugging inside queue operation
   - Check if queue is being cleared unexpectedly

3. **Verify LDK is polling** for custom messages
   - Add logging to `get_and_clear_pending_msg()`
   - Check how often it's called
   - Verify it returns queued messages

4. **Check peer connectivity** requirements
   - Confirm Diana is a connected peer of Alice
   - Verify custom messages work between channel partners
   - Test if non-partner peers can receive custom messages

---

## Code Changes Made (Debug Logging)

### Unstaged Changes (Debug Only)
- Added `println!` debugging to `send_message()` (lines 698-725)
- Added `println!` debugging to `broadcast_message_to_other_partners()` (line 4022+)
- Added `println!` debugging to `process_message()` (line 1592+)
- Added `println!` debugging to `handle_third_party_audit_message()` (line 1673+)
- Added `println!` debugging to `verify_and_store_signed_update()` (line 4226+)

### Staged Changes (Production Code)
- Removed deprecated `pending_acks` HashMap (replaced with `pending_oneshot_acks`)
- Added `signed_update_logs` HashMap for audit trail
- Added `node_secret_key` field
- Added `set_node_secret_key()` method
- Various cleanup of old debugging code

---

## Summary

**Fixed**: Secret key initialization ✅
**Remaining**: Message delivery mechanism ❌
**Root Cause**: Likely missing feature advertisement/registration for custom message types
**Confidence**: High - sender creates and queues messages correctly, but delivery fails

The user's insight about advertisement/registration is almost certainly correct and should be the next focus.
